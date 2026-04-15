use std::{str::FromStr, time::Duration};

use iroh::{
    Endpoint, SecretKey,
    address_lookup::dns::DnsAddressLookup,
    endpoint::{default_relay_mode, presets},
};
use iroh_base::RelayUrl;
use iroh_relay::{
    RelayConfig, RelayMap,
    dns::{DnsProtocol, DnsResolver},
};
use n0_error::{Result, StdResultExt};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::{Config, DiscoveryMode};

/// Build a new iroh endpoint, applying all relevant details from configuration.
pub async fn build_endpoint(secret_key: SecretKey, common: &Config) -> Result<Endpoint> {
    let relay_mode = relay_mode_from_env_or_build().await?;
    let mut builder = match common.discovery_mode {
        DiscoveryMode::Dns => Endpoint::empty_builder()
            .relay_mode(relay_mode)
            .secret_key(secret_key),
        DiscoveryMode::Default | DiscoveryMode::Hybrid => Endpoint::builder(presets::N0)
            .relay_mode(relay_mode)
            .secret_key(secret_key),
    };
    if let Some(addr) = common.ipv4_addr {
        builder = builder.bind_addr(addr)?;
    }
    if let Some(addr) = common.ipv6_addr {
        builder = builder.bind_addr(addr)?;
    }
    match common.discovery_mode {
        DiscoveryMode::Default => {}
        DiscoveryMode::Dns | DiscoveryMode::Hybrid => {
            let origin = match &common.dns_origin {
                Some(origin) => origin.clone(),
                None => n0_error::bail_any!(
                    "dns_origin is required when discovery_mode is set to dns or hybrid"
                ),
            };
            if let Some(resolver_addr) = common.dns_resolver {
                let resolver = DnsResolver::builder()
                    .with_nameserver(resolver_addr, DnsProtocol::Udp)
                    .build();
                builder = builder.dns_resolver(resolver);
            }
            builder = builder.address_lookup(DnsAddressLookup::builder(origin));
        }
    }
    let endpoint = builder.bind().await?;
    info!(id = %endpoint.id(), "iroh endpoint bound");
    Ok(endpoint)
}

const IROH_GATEWAY_RELAY_URLS: &str = "IROH_GATEWAY_RELAY_URLS";
const BUILD_IROH_GATEWAY_RELAY_URLS: &str = "BUILD_IROH_GATEWAY_RELAY_URLS";
const STARTUP_RELAY_SELECTION_MAX: usize = 5;
const STARTUP_RELAY_PROBE_TIMEOUT: Duration = Duration::from_millis(800);

async fn relay_mode_from_env_or_build() -> Result<iroh::endpoint::RelayMode> {
    if let Ok(raw_urls) = std::env::var(IROH_GATEWAY_RELAY_URLS) {
        match parse_relay_urls(&raw_urls) {
            Ok(relays) => {
                let relays =
                    select_best_relays_for_startup(relays, STARTUP_RELAY_SELECTION_MAX).await;
                info!(
                    source = %IROH_GATEWAY_RELAY_URLS,
                    count = relays.len(),
                    "using custom iroh relay list from environment"
                );
                return Ok(iroh::endpoint::RelayMode::Custom(relays_to_map(relays)));
            }
            Err(err) => {
                warn!("invalid relay urls in {IROH_GATEWAY_RELAY_URLS}: {err:#}");
            }
        }
    }

    if let Some(raw_urls) = option_env!("BUILD_IROH_GATEWAY_RELAY_URLS") {
        match parse_relay_urls(raw_urls) {
            Ok(relays) => {
                let relays =
                    select_best_relays_for_startup(relays, STARTUP_RELAY_SELECTION_MAX).await;
                info!(
                    source = %BUILD_IROH_GATEWAY_RELAY_URLS,
                    count = relays.len(),
                    "using custom iroh relay list from build environment"
                );
                return Ok(iroh::endpoint::RelayMode::Custom(relays_to_map(relays)));
            }
            Err(err) => {
                warn!("invalid relay urls in {BUILD_IROH_GATEWAY_RELAY_URLS}: {err:#}");
            }
        }
    }

    Ok(default_relay_mode())
}

fn parse_relay_urls(raw: &str) -> Result<Vec<RelayUrl>> {
    let relays: Vec<RelayUrl> = raw
        .split(|c: char| c == ',' || c == ';' || c.is_ascii_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(normalize_relay_url)
        .map(|url| RelayUrl::from_str(&url))
        .collect::<std::result::Result<Vec<_>, _>>()
        .std_context(
            "Failed parsing relay URL list. Expected comma/space/newline separated URLs",
        )?;

    if relays.is_empty() {
        n0_error::bail_any!("Relay URL list was provided but empty after parsing");
    }

    let mut deduped = Vec::with_capacity(relays.len());
    for relay in relays {
        if !deduped.iter().any(|seen: &RelayUrl| seen == &relay) {
            deduped.push(relay);
        }
    }
    Ok(deduped)
}

fn normalize_relay_url(raw: &str) -> String {
    if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    }
}

async fn select_best_relays_for_startup(relays: Vec<RelayUrl>, max_relays: usize) -> Vec<RelayUrl> {
    let total_candidates = relays.len();
    if relays.len() <= max_relays {
        return relays;
    }

    let client = match reqwest::Client::builder()
        .timeout(STARTUP_RELAY_PROBE_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            warn!("relay probe setup failed, using first {max_relays} relays: {err:#}");
            return relays.into_iter().take(max_relays).collect();
        }
    };

    let mut joinset = JoinSet::new();
    for relay in relays.iter().cloned() {
        let client = client.clone();
        joinset.spawn(async move {
            let latency = probe_relay_latency(&client, &relay).await;
            (relay, latency)
        });
    }

    let mut successful = Vec::new();
    let mut failed = Vec::new();
    while let Some(joined) = joinset.join_next().await {
        match joined {
            Ok((relay, Ok(latency))) => successful.push((relay, latency)),
            Ok((relay, Err(reason))) => failed.push((relay, reason)),
            Err(err) => {
                debug!("relay probe task join error: {err:#}");
            }
        }
    }

    successful.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.as_str().cmp(b.0.as_str())));
    let mut selected: Vec<RelayUrl> = successful
        .iter()
        .take(max_relays)
        .map(|(relay, _)| relay.clone())
        .collect();

    if selected.len() < max_relays {
        failed.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        for (relay, _) in &failed {
            if selected.len() == max_relays {
                break;
            }
            if !selected.iter().any(|r| r == relay) {
                selected.push(relay.clone());
            }
        }
    }

    if selected.len() < max_relays {
        for relay in relays {
            if selected.len() == max_relays {
                break;
            }
            if !selected.iter().any(|r| r == &relay) {
                selected.push(relay);
            }
        }
    }

    if !failed.is_empty() {
        let failure_samples: Vec<String> = failed
            .iter()
            .take(5)
            .map(|(relay, reason)| format!("{relay} -> {reason}"))
            .collect();
        warn!(
            failed = failed.len(),
            samples = ?failure_samples,
            "relay ping probe failures observed"
        );
    }
    info!(
        total = total_candidates,
        successful = successful.len(),
        selected = selected.len(),
        selected_relays = ?selected,
        "selected startup relay shortlist"
    );
    selected
}

async fn probe_relay_latency(
    client: &reqwest::Client,
    relay: &RelayUrl,
) -> std::result::Result<Duration, String> {
    let host = relay
        .host_str()
        .ok_or_else(|| "missing host in relay url".to_string())?
        .trim_end_matches('.');
    let mut https_url = reqwest::Url::parse(&format!("https://{host}/ping"))
        .map_err(|err| format!("url parse: {err}"))?;
    https_url.set_query(None);
    debug!(
        relay = %relay,
        url = %https_url,
        timeout_ms = STARTUP_RELAY_PROBE_TIMEOUT.as_millis(),
        "starting relay ping probe"
    );
    let start = tokio::time::Instant::now();
    match client.get(https_url.clone()).send().await {
        Ok(resp) if resp.status().is_success() => {
            let elapsed = start.elapsed();
            debug!(
                relay = %relay,
                url = %https_url,
                status = %resp.status(),
                elapsed_ms = elapsed.as_millis(),
                "relay ping probe succeeded"
            );
            Ok(elapsed)
        }
        Ok(resp) => {
            debug!(
                relay = %relay,
                url = %https_url,
                status = %resp.status(),
                elapsed_ms = start.elapsed().as_millis(),
                "relay ping probe got non-success response"
            );
            Err(format!("status {}", resp.status()))
        }
        Err(err) => {
            debug!(
                relay = %relay,
                url = %https_url,
                elapsed_ms = start.elapsed().as_millis(),
                "relay ping probe request failed: {err:#}"
            );
            Err(format!("{err:#}"))
        }
    }
}

fn relays_to_map(relays: Vec<RelayUrl>) -> RelayMap {
    RelayMap::from_iter(relays.into_iter().map(RelayConfig::from))
}
