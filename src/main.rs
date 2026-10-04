use clap::{Parser, ValueEnum};
use iroh::SecretKey;
use n0_error::{Result, StdResultExt};
use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{Resource, propagation::TraceContextPropagator, trace::SdkTracerProvider};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use tracing::info;
use tracing_subscriber::{Layer, Registry, prelude::*};

mod config;
mod diagnostics;
mod endpoint;
mod gateway;

use config::{DiscoveryMode, GatewayConfig, TransportMode, UdpForward};
use tokio_util::sync::CancellationToken;

/// iroh HTTP/TCP and local UDP proxy gateway
#[derive(Parser, Debug)]
#[clap(name = "iroh-gateway", version)]
struct Args {
    /// Proxy listener address (default: 127.0.0.1 for MASQUE; 0.0.0.0 for legacy/auto).
    #[clap(long)]
    bind_addr: Option<IpAddr>,

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

    /// Upstream wire protocol: legacy, masque, or auto (per-destination routing).
    #[clap(long, value_enum)]
    transport: Option<TransportMode>,

    /// Static MASQUE peer address (ENDPOINT_ID=IP:PORT). Repeat for more addresses.
    #[clap(long, value_parser = parse_peer)]
    peer: Vec<(iroh::EndpointId, SocketAddr)>,

    /// Forward loopback UDP to one Connector (BIND_IP:PORT=CONNECTOR_ID:PORT). Repeatable; MASQUE only.
    #[clap(long)]
    udp_forward: Vec<UdpForward>,

    /// Maximum UDP client associations per listener (1–1024; default 128).
    #[clap(long)]
    udp_max_associations: Option<usize>,

    /// Expire inactive UDP associations after this many seconds (1–3600; default 60).
    #[clap(long)]
    udp_idle_timeout_secs: Option<u64>,

    /// Strict JSON file of approved CONNECT-IP grants (Linux only; requires CAP_NET_ADMIN).
    #[clap(long)]
    ip_config: Option<PathBuf>,

    /// Print this gateway's public endpoint ID and exit. Creates the key if needed.
    #[clap(long)]
    print_endpoint_id: bool,
}

fn parse_peer(value: &str) -> std::result::Result<(iroh::EndpointId, SocketAddr), String> {
    let (id, addr) = value
        .split_once('=')
        .ok_or("expected ENDPOINT_ID=IP:PORT")?;
    let id = id.parse().map_err(|_| "invalid endpoint ID")?;
    let addr: SocketAddr = addr
        .parse()
        .map_err(|_| "expected an IP address and port")?;
    if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() {
        return Err("peer address must be a unicast IP with a nonzero port".into());
    }
    Ok((id, addr))
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DiscoveryModeArg {
    Default,
    Dns,
    Hybrid,
    Static,
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_file = dotenv::dotenv().ok();
    // iroh requires ring. Other dependencies also enable aws-lc, so rustls
    // cannot select a provider automatically from the combined feature set.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (otel_layer, _otel_guard) = init_otel("iroh-gateway");
    let otel_enabled = otel_layer.is_some();
    tracing_subscriber::registry()
        .with(otel_layer)
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();
    if otel_enabled {
        tracing::info!(
            stage = "otel_exporter_init",
            "OpenTelemetry OTLP tracing enabled"
        );
    }

    if let Some(path) = env_file {
        info!("loaded environment variables from {}", path.display());
    }

    let args = Args::parse();

    let secret_key = load_or_create_key(&args.key_file).await?;
    if args.print_endpoint_id {
        println!("{}", secret_key.public());
        return Ok(());
    }

    let mut config = match &args.config_file {
        Some(path) => GatewayConfig::from_file(path.clone()).await?,
        None => GatewayConfig::default(),
    };

    if let Some(discovery) = args.discovery {
        config.common.discovery_mode = match discovery {
            DiscoveryModeArg::Default => DiscoveryMode::Default,
            DiscoveryModeArg::Dns => DiscoveryMode::Dns,
            DiscoveryModeArg::Hybrid => DiscoveryMode::Hybrid,
            DiscoveryModeArg::Static => DiscoveryMode::Static,
        };
    }
    if let Some(origin) = args.dns_origin {
        config.common.dns_origin = Some(origin);
    }
    if let Some(resolver) = args.dns_resolver {
        config.common.dns_resolver = Some(resolver);
    }
    if let Some(transport) = args.transport {
        config.transport = transport;
    }
    for (id, addr) in args.peer {
        config.peers.entry(id).or_default().push(addr);
    }
    config.udp_forwards.extend(args.udp_forward);
    if let Some(limit) = args.udp_max_associations {
        config.udp_max_associations = limit;
    }
    if let Some(timeout) = args.udp_idle_timeout_secs {
        config.udp_idle_timeout_secs = timeout;
    }
    if let Some(path) = args.ip_config {
        config.ip_config = Some(path);
    }
    config.validate()?;

    let bind_ip = args.bind_addr.unwrap_or_else(|| match config.transport {
        TransportMode::Legacy | TransportMode::Auto => IpAddr::from([0, 0, 0, 0]),
        TransportMode::Masque => IpAddr::from([127, 0, 0, 1]),
    });
    if !bind_ip.is_loopback() {
        tracing::warn!(%bind_ip, "gateway ingress trusts routing headers; restrict this listener to trusted ingress with network policy");
    }
    let bind_addr: SocketAddr = (bind_ip, args.port).into();
    let metrics_bind_addr = match (args.metrics_addr, args.metrics_port) {
        (None, None) => None,
        (Some(addr), Some(port)) => Some((addr, port).into()),
        (Some(addr), None) => Some((addr, 9090).into()),
        (None, Some(port)) => Some((bind_ip, port).into()),
    };

    #[cfg(unix)]
    let uds_listener = if let Some(uds_path) = &args.uds {
        // Do not unlink an existing listener or an unrelated file. The operator
        // must remove a stale socket after checking that its owner has stopped.
        let listener = tokio::net::UnixListener::bind(uds_path)?;
        info!("UDS gateway at {}", uds_path.display());
        Some(listener)
    } else {
        None
    };

    info!("serving on {bind_addr}");
    let shutdown = CancellationToken::new();
    let gateway = gateway::bind_and_serve(
        secret_key,
        config,
        bind_addr,
        metrics_bind_addr,
        #[cfg(unix)]
        uds_listener,
        shutdown.clone(),
    );
    tokio::pin!(gateway);
    tokio::select! {
        res = &mut gateway => res?,
        _ = shutdown_signal() => {
            info!("shutting down");
            shutdown.cancel();
            match tokio::time::timeout(std::time::Duration::from_secs(5), gateway).await {
                Ok(result) => result?,
                Err(_) => tracing::warn!("gateway shutdown timed out"),
            }
        }
    }

    Ok(())
}

struct OtelGuard(Option<SdkTracerProvider>);

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.0.take()
            && let Err(error) = provider.shutdown()
        {
            tracing::warn!(%error, stage="otel_shutdown", "OpenTelemetry exporter shutdown failed");
        }
    }
}

fn init_otel(
    service_name: &'static str,
) -> (Option<Box<dyn Layer<Registry> + Send + Sync>>, OtelGuard) {
    let endpoint = std::env::var("DATUM_CONNECT_OTEL_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| otlp_traces_endpoint(&value))
        .or_else(|| {
            std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|value| otlp_traces_endpoint(&value))
        });
    let Some(endpoint) = endpoint else {
        return (None, OtelGuard(None));
    };
    let exporter = match SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .with_timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(exporter) => exporter,
        Err(error) => {
            eprintln!("OpenTelemetry exporter disabled: {error}");
            return (None, OtelGuard(None));
        }
    };
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder()
                .with_service_name(service_name)
                .with_attributes([KeyValue::new("service.namespace", "datum")])
                .build(),
        )
        .build();
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    opentelemetry::global::set_tracer_provider(provider.clone());
    let layer = tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(service_name))
        .boxed();
    (Some(layer), OtelGuard(Some(provider)))
}

fn otlp_traces_endpoint(endpoint: &str) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    if endpoint.ends_with("/v1/traces") {
        endpoint.to_owned()
    } else {
        format!("{endpoint}/v1/traces")
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

async fn load_or_create_key(key_file: &PathBuf) -> Result<SecretKey> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if let Some(parent) = key_file.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    match options.open(key_file).await {
        Ok(mut file) => {
            let key = SecretKey::generate();
            file.write_all(&key.to_bytes()).await?;
            file.sync_all().await?;
            info!(path = %key_file.display(), "created gateway identity");
            return Ok(key);
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(key_file).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() {
        return Err(std::io::Error::other("gateway key must be a regular file").into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::other(
                "gateway key must be owned by the current user with mode 0600 (run chmod 600 on the key file)",
            ).into());
        }
    }
    let mut bytes = Vec::new();
    file.take(33).read_to_end(&mut bytes).await?;
    let key = bytes.as_slice().try_into().anyerr()?;
    Ok(SecretKey::from_bytes(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn key_is_persistent_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let first = load_or_create_key(&path).await.unwrap();
        assert_eq!(
            first.public(),
            load_or_create_key(&path).await.unwrap().public()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_and_shared_key() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        load_or_create_key(&path).await.unwrap();
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(load_or_create_key(&link).await.is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create_key(&path).await.is_err());
    }

    #[test]
    fn peer_requires_valid_direct_address() {
        let id = SecretKey::generate().public();
        assert!(parse_peer(&format!("{id}=127.0.0.1:9000")).is_ok());
        for invalid in ["0.0.0.0:9", "127.0.0.1:0", "224.0.0.1:9", "hostname:9"] {
            assert!(parse_peer(&format!("{id}={invalid}")).is_err());
        }
        assert!(parse_peer("bad=127.0.0.1:9000").is_err());
    }
}
