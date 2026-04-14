use clap::{Parser, ValueEnum};
use iroh::SecretKey;
use n0_error::{Result, StdResultExt};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use tracing::info;
use tracing_subscriber::prelude::*;

mod config;
mod endpoint;
mod gateway;

use config::{DiscoveryMode, GatewayConfig};

/// iroh HTTP/TCP proxy gateway
#[derive(Parser, Debug)]
#[clap(name = "iroh-gateway", version)]
struct Args {
    /// Bind address for the gateway proxy listener.
    #[clap(long, default_value = "0.0.0.0")]
    bind_addr: IpAddr,

    /// Port for the gateway proxy listener.
    #[clap(long, default_value = "8080")]
    port: u16,

    /// Bind address for the Prometheus metrics server.
    #[clap(long)]
    metrics_addr: Option<IpAddr>,

    /// Port for the Prometheus metrics server.
    #[clap(long)]
    metrics_port: Option<u16>,

    /// Also listen on a Unix domain socket at this path (e.g. for Envoy to forward via UDS).
    #[cfg(unix)]
    #[clap(long)]
    uds: Option<PathBuf>,

    /// Discovery mode for iroh endpoint connection details.
    #[clap(long, value_enum)]
    discovery: Option<DiscoveryModeArg>,

    /// DNS origin for _iroh.<endpoint-id>.<origin> lookups.
    #[clap(long)]
    dns_origin: Option<String>,

    /// DNS resolver address for discovery (e.g. 127.0.0.1:53535).
    #[clap(long)]
    dns_resolver: Option<SocketAddr>,

    /// Path to the gateway secret key file. Created on first run if not present.
    #[clap(long, default_value = "gateway_key", env = "IROH_GATEWAY_KEY_FILE")]
    key_file: PathBuf,

    /// Path to a gateway config YAML file.
    #[clap(long, env = "IROH_GATEWAY_CONFIG_FILE")]
    config_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DiscoveryModeArg {
    Default,
    Dns,
    Hybrid,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(sentry::integrations::tracing::layer())
        .init();

    if let Ok(path) = dotenv::dotenv() {
        info!("loaded environment variables from {}", path.display());
    }

    let _sentry_guard = sentry::init(sentry::ClientOptions {
        dsn: std::env::var("SENTRY_DSN")
            .ok()
            .and_then(|s| s.parse().ok()),
        release: sentry::release_name!(),
        send_default_pii: true,
        before_send: Some(std::sync::Arc::new(|event| match event.level {
            sentry::Level::Error | sentry::Level::Fatal => Some(event),
            _ if rand::random::<f64>() < 0.1 => Some(event),
            _ => None,
        })),
        traces_sample_rate: 0.1,
        ..Default::default()
    });

    let args = Args::parse();

    let secret_key = load_or_create_key(&args.key_file).await?;

    let mut config = match &args.config_file {
        Some(path) => GatewayConfig::from_file(path.clone()).await?,
        None => GatewayConfig::default(),
    };

    if let Some(discovery) = args.discovery {
        config.common.discovery_mode = match discovery {
            DiscoveryModeArg::Default => DiscoveryMode::Default,
            DiscoveryModeArg::Dns => DiscoveryMode::Dns,
            DiscoveryModeArg::Hybrid => DiscoveryMode::Hybrid,
        };
    }
    if let Some(origin) = args.dns_origin {
        config.common.dns_origin = Some(origin);
    }
    if let Some(resolver) = args.dns_resolver {
        config.common.dns_resolver = Some(resolver);
    }

    let bind_addr: SocketAddr = (args.bind_addr, args.port).into();
    let metrics_bind_addr = match (args.metrics_addr, args.metrics_port) {
        (None, None) => None,
        (Some(addr), Some(port)) => Some((addr, port).into()),
        (Some(addr), None) => Some((addr, 9090).into()),
        (None, Some(port)) => Some((args.bind_addr, port).into()),
    };

    #[cfg(unix)]
    let uds_listener = if let Some(uds_path) = &args.uds {
        if uds_path.exists() {
            std::fs::remove_file(uds_path)?;
        }
        let listener = tokio::net::UnixListener::bind(uds_path)?;
        info!("UDS gateway at {}", uds_path.display());
        Some(listener)
    } else {
        None
    };

    info!("serving on {bind_addr}");
    tokio::select! {
        res = gateway::bind_and_serve(
            secret_key,
            config,
            bind_addr,
            metrics_bind_addr,
            #[cfg(unix)]
            uds_listener,
        ) => res?,
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
        }
    }

    Ok(())
}

async fn load_or_create_key(key_file: &PathBuf) -> Result<SecretKey> {
    if !key_file.exists() {
        tracing::warn!(
            path = %key_file.display(),
            "gateway key file not found, generating new key"
        );
        if let Some(parent) = key_file.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        let key = SecretKey::generate(&mut rand::rng());
        tokio::fs::write(key_file, key.to_bytes()).await?;
        return Ok(key);
    }
    let bytes = tokio::fs::read(key_file).await?;
    let key = bytes.as_slice().try_into().anyerr()?;
    Ok(SecretKey::from_bytes(key))
}
