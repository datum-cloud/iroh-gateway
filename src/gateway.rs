use std::{io, net::SocketAddr, str::FromStr, sync::Arc};

use askama::Template;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    StatusCode,
    body::Bytes,
    http::{self, HeaderMap, HeaderValue},
};
use iroh::{Endpoint, EndpointId, SecretKey};
use iroh_proxy_utils::{
    Authority, HttpRequest, HttpRequestKind,
    downstream::{
        Deny, DownstreamProxy, ErrorResponder, HttpProxyOpts, ProxyMode, RequestHandler, SrcAddr,
    },
};
use n0_error::Result;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tracing::info;

mod ip;
mod masque;
mod metrics;
mod udp;

use self::metrics::{GatewayMetrics, MetricsHttpState, serve_metrics_http, shared_gateway_metrics};
use crate::endpoint::build_endpoint;

pub async fn bind_and_serve(
    secret_key: SecretKey,
    config: crate::config::GatewayConfig,
    tcp_bind_addr: SocketAddr,
    metrics_bind_addr: Option<SocketAddr>,
    #[cfg(unix)] uds_listener: Option<UnixListener>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<()> {
    config.validate()?;
    let ip_config = match &config.ip_config {
        Some(path) => {
            if !cfg!(target_os = "linux") {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "CONNECT-IP gateway requires Linux TUN support",
                )
                .into());
            }
            Some(ip::IpConfig::load(path).await?)
        }
        None => None,
    };
    if let Some(grants) = &ip_config {
        let underlay = config.common.ip_underlay_socket().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "CONNECT-IP requires exactly one explicit underlay address",
            )
        })?;
        if underlay.ip().is_unspecified() {
            if !underlay.ip().is_ipv6()
                || underlay.port() != 0
                || matches!(
                    config.common.discovery_mode,
                    crate::config::DiscoveryMode::Static
                )
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "an unspecified CONNECT-IP bind is allowed only as [::]:0 with relay discovery",
                )
                .into());
            }
            grants.validate_relay_only()?;
        } else {
            grants.validate_underlay(underlay.ip())?;
        }
    }
    let _cancel_on_drop = shutdown.clone().drop_guard();
    let listener = TcpListener::bind(tcp_bind_addr).await?;
    // Bind all ingress before serving any of it; a bad/occupied UDP listener
    // must fail startup rather than silently leave a partially working gateway.
    let mut udp_listeners = Vec::new();
    for forward in &config.udp_forwards {
        udp_listeners.push((
            forward.clone(),
            tokio::net::UdpSocket::bind(forward.bind_addr).await?,
        ));
    }
    let endpoint = build_endpoint(secret_key, &config.common, ip_config.is_some()).await?;
    let _diagnostics = crate::diagnostics::maybe_start(&endpoint).await;
    if !matches!(config.transport, crate::config::TransportMode::Legacy) {
        if ip_config.is_some() {
            endpoint.set_alpns(vec![connect_transport::ip::ALPN.to_vec()]);
        }
        let transport = connect_transport::Transport::client(endpoint.clone());
        let legacy = matches!(config.transport, crate::config::TransportMode::Auto)
            .then(|| DownstreamProxy::new(endpoint.clone(), Default::default()));
        // The legacy connection pool resolves by key. Operator-provided peer
        // addresses must be available to both transports, never HTTP callers.
        if !config.peers.is_empty() {
            let lookup = iroh::address_lookup::memory::MemoryLookup::from_endpoint_info(
                config.peers.iter().map(|(id, addresses)| {
                    addresses
                        .iter()
                        .fold(iroh::EndpointAddr::new(*id), |peer, addr| {
                            peer.with_ip_addr(*addr)
                        })
                }),
            );
            endpoint.address_lookup()?.add(lookup);
        }
        let metrics = shared_gateway_metrics();
        let udp_metrics = Arc::new(udp::UdpMetrics::default());
        let ip_metrics = Arc::new(ip::IpMetrics::default());
        let mut tasks = tokio::task::JoinSet::<io::Result<()>>::new();
        if let Some(addr) = metrics_bind_addr {
            let state = MetricsHttpState::masque(
                endpoint.clone(),
                metrics.clone(),
                transport.clone(),
                udp_metrics.clone(),
                ip_metrics.clone(),
            )
            .with_downstream(legacy.as_ref().map(|proxy| proxy.metrics().clone()));
            let cancel = shutdown.clone();
            tasks.spawn(async move {
                tokio::select! {
                    result = serve_metrics_http(addr, state) => result.map_err(io::Error::other),
                    _ = cancel.cancelled() => Ok(()),
                }
            });
        }
        info!(endpoint_id = %transport.endpoint_id(), mode=?config.transport, "gateway started");
        if let Some(config) = ip_config {
            tasks.spawn(ip::serve(
                endpoint.clone(),
                config,
                ip_metrics,
                shutdown.clone(),
            ));
        }
        #[cfg(unix)]
        if let Some(listener) = uds_listener {
            let uds_transport = transport.clone();
            let peers = config.peers.clone();
            let metrics = metrics.clone();
            let cancel = shutdown.clone();
            let legacy = legacy.clone();
            tasks.spawn(async move {
                tokio::select! {
                    result = masque::serve_uds(listener, uds_transport, peers, metrics, legacy) => result,
                    _ = cancel.cancelled() => Ok(()),
                }
            });
        }
        for (forward, socket) in udp_listeners {
            let peer = config
                .peers
                .get(&forward.connector)
                .into_iter()
                .flatten()
                .fold(iroh::EndpointAddr::new(forward.connector), |peer, addr| {
                    peer.with_ip_addr(*addr)
                });
            let options = udp::UdpOptions {
                max_associations: config.udp_max_associations,
                idle_timeout: std::time::Duration::from_secs(config.udp_idle_timeout_secs),
                queue_capacity: 32,
            };
            let transport = transport.clone();
            let metrics = udp_metrics.clone();
            let cancel = shutdown.clone();
            info!(bind_addr=%forward.bind_addr, peer=%forward.connector, port=forward.port, "UDP gateway listener started");
            tasks.spawn(udp::serve(
                socket,
                transport,
                peer,
                forward.port,
                options,
                metrics,
                cancel,
            ));
        }
        let http_transport = transport.clone();
        let cancel = shutdown.clone();
        tasks.spawn(async move {
            tokio::select! {
                result = masque::serve(listener, http_transport, config.peers, metrics, legacy) => result,
                _ = cancel.cancelled() => Ok(()),
            }
        });
        let result = tokio::select! {
            _ = shutdown.cancelled() => Ok(()),
            task = tasks.join_next() => match task {
                Some(Ok(Err(error))) => Err(error),
                Some(Err(error)) => Err(io::Error::other(error)),
                _ if shutdown.is_cancelled() => Ok(()),
                _ => Err(io::Error::other("gateway listener stopped unexpectedly")),
            }
        };
        shutdown.cancel();
        while tasks.join_next().await.is_some() {}
        transport.shutdown().await;
        return Ok(result?);
    }
    tokio::select! {
        result = serve_with_metrics(
        endpoint,
        listener,
        metrics_bind_addr,
        #[cfg(unix)]
        uds_listener,
        ) => result,
        _ = shutdown.cancelled() => Ok(()),
    }
}

pub async fn serve(endpoint: Endpoint, listener: TcpListener) -> Result<()> {
    serve_with_metrics(
        endpoint,
        listener,
        None,
        #[cfg(unix)]
        None,
    )
    .await
}

pub async fn serve_with_metrics(
    endpoint: Endpoint,
    listener: TcpListener,
    metrics_bind_addr: Option<SocketAddr>,
    #[cfg(unix)] uds_listener: Option<UnixListener>,
) -> Result<()> {
    let tcp_bind_addr = listener.local_addr()?;
    info!(
        ?tcp_bind_addr,
        endpoint_id = %endpoint.id().fmt_short(),
        "TCP proxy gateway started"
    );

    let metrics = shared_gateway_metrics();
    let proxy = DownstreamProxy::new(endpoint.clone(), Default::default());

    if let Some(metrics_bind_addr) = metrics_bind_addr {
        let state =
            MetricsHttpState::new(endpoint.clone(), metrics.clone(), proxy.metrics().clone());
        tokio::spawn(async move {
            if let Err(err) = serve_metrics_http(metrics_bind_addr, state).await {
                tracing::warn!(%err, "gateway metrics server failed");
            }
        });
    }

    #[cfg(unix)]
    if let Some(uds_listener) = uds_listener {
        let uds_proxy = proxy.clone();
        let uds_endpoint = endpoint.clone();
        let uds_metrics = metrics.clone();
        tokio::spawn(async move {
            if let Err(err) =
                serve_uds_with_proxy(uds_endpoint, uds_listener, uds_metrics, uds_proxy).await
            {
                tracing::warn!(%err, "UDS gateway task failed");
            }
        });
    }

    let resolver_endpoint = endpoint.clone();
    let error_endpoint = endpoint.clone();
    let mode = ProxyMode::Http(
        HttpProxyOpts::new(HeaderResolver::new(resolver_endpoint, metrics.clone()))
            .error_responder(ErrorResponseWriter::new(error_endpoint, metrics)),
    );
    proxy.forward_tcp_listener(listener, mode).await
}

#[cfg(unix)]
async fn serve_uds_with_proxy(
    endpoint: Endpoint,
    listener: UnixListener,
    metrics: Arc<GatewayMetrics>,
    proxy: DownstreamProxy,
) -> Result<()> {
    let uds_path = listener
        .local_addr()
        .ok()
        .and_then(|a| a.as_pathname().map(|p| p.to_path_buf()));
    info!(
        ?uds_path,
        endpoint_id = %endpoint.id().fmt_short(),
        "UDS proxy gateway started"
    );

    let resolver_endpoint = endpoint.clone();
    let mode = ProxyMode::Http(
        HttpProxyOpts::new(HeaderResolver::new(resolver_endpoint, metrics.clone()))
            .error_responder(ErrorResponseWriter::new(endpoint, metrics)),
    );
    proxy.forward_uds_listener(listener, mode).await
}

const HEADER_NODE_ID: &str = "x-iroh-endpoint-id";
const HEADER_TARGET_HOST: &str = "x-datum-target-host";
const HEADER_TARGET_PORT: &str = "x-datum-target-port";

const DATUM_HEADERS: [&str; 4] = [
    HEADER_NODE_ID,
    HEADER_TARGET_HOST,
    HEADER_TARGET_PORT,
    masque::TRANSPORT_HEADER,
];

struct HeaderResolver {
    endpoint: Endpoint,
    metrics: Arc<GatewayMetrics>,
}

impl RequestHandler for HeaderResolver {
    async fn handle_request(
        &self,
        src_addr: SrcAddr,
        req: &mut HttpRequest,
    ) -> Result<EndpointId, Deny> {
        if masque::selected_transport(&req.headers, crate::config::TransportMode::Legacy).is_err() {
            return Err(Deny::bad_request(
                "unsupported or invalid destination transport",
            ));
        }
        let is_tcp = matches!(src_addr, SrcAddr::Tcp(_));
        match src_addr {
            SrcAddr::Tcp(_) => self.metrics.inc_tcp_requests(),
            #[cfg(unix)]
            SrcAddr::Unix(_) => self.metrics.inc_uds_requests(),
        }
        match req.classify()? {
            HttpRequestKind::Tunnel => {
                self.metrics.inc_tunnel_requests();
                self.metrics
                    .inc_tunnel_reuse_attempt(has_existing_peer_conn(&self.endpoint));
                if is_tcp {
                    self.metrics.inc_tunnel_tcp_requests();
                } else {
                    #[cfg(unix)]
                    self.metrics.inc_tunnel_uds_requests();
                }
                let endpoint_id = self.endpoint_id_from_headers(&req.headers)?;
                req.remove_headers(DATUM_HEADERS);
                Ok(endpoint_id)
            }
            HttpRequestKind::Origin | HttpRequestKind::Http1Absolute => {
                self.metrics.inc_origin_requests();
                self.metrics
                    .inc_origin_reuse_attempt(has_existing_peer_conn(&self.endpoint));
                if is_tcp {
                    self.metrics.inc_origin_tcp_requests();
                } else {
                    #[cfg(unix)]
                    self.metrics.inc_origin_uds_requests();
                }
                let endpoint_id = self.endpoint_id_from_headers(&req.headers)?;
                let host = self.header_value(&req.headers, HEADER_TARGET_HOST)?;
                let port = self
                    .header_value(&req.headers, HEADER_TARGET_PORT)?
                    .parse::<u16>()
                    .map_err(|_| {
                        self.metrics.inc_denied_invalid_target_port();
                        Deny::bad_request("invalid x-datum-target-port header")
                    })?;
                req.set_absolute_http_authority(Authority::new(host.to_string(), port))?
                    .remove_headers(DATUM_HEADERS);
                Ok(endpoint_id)
            }
        }
    }
}

impl HeaderResolver {
    fn new(endpoint: Endpoint, metrics: Arc<GatewayMetrics>) -> Self {
        Self { endpoint, metrics }
    }

    fn endpoint_id_from_headers(
        &self,
        headers: &HeaderMap<HeaderValue>,
    ) -> Result<EndpointId, Deny> {
        let s = self.header_value(headers, HEADER_NODE_ID)?;
        EndpointId::from_str(s).map_err(|_| {
            self.metrics.inc_denied_invalid_endpoint();
            Deny::bad_request("invalid x-iroh-endpoint-id value")
        })
    }

    fn header_value<'a>(
        &self,
        headers: &'a HeaderMap<HeaderValue>,
        name: &str,
    ) -> Result<&'a str, Deny> {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                self.metrics.inc_denied_missing_header_name(name);
                Deny::bad_request(format!("Missing header {name}"))
            })
    }
}

#[derive(Template)]
#[template(path = "gateway_error.html")]
struct GatewayErrorTemplate<'a> {
    title: &'a str,
    body: &'a str,
}

struct ErrorResponseWriter {
    endpoint: Endpoint,
    metrics: Arc<GatewayMetrics>,
}

impl ErrorResponder for ErrorResponseWriter {
    async fn error_response(
        &self,
        status: StatusCode,
    ) -> hyper::Response<BoxBody<Bytes, io::Error>> {
        self.metrics.inc_status_code(status);
        if status.is_server_error() {
            self.metrics
                .inc_5xx_failure_by_peer_conn_state(has_existing_peer_conn(&self.endpoint));
        }
        let title = format!(
            "{} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or_default()
        );
        let body = match status {
            StatusCode::BAD_REQUEST => {
                "The request could not be understood by the gateway. Please try again."
            }
            StatusCode::UNAUTHORIZED => {
                "You are not logged in or your session has expired. Please sign in and try again."
            }
            StatusCode::FORBIDDEN => "Access to this resource is not allowed through the gateway.",
            StatusCode::NOT_FOUND => "The requested page could not be found through the gateway.",
            StatusCode::INTERNAL_SERVER_ERROR => {
                "The gateway encountered an internal error. Please try again later."
            }
            StatusCode::BAD_GATEWAY => {
                "The gateway could not get a valid response from the upstream service."
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                "The service is temporarily unavailable. Please try again shortly."
            }
            StatusCode::GATEWAY_TIMEOUT => "The upstream service took too long to respond.",
            _ => "The service experienced an unexpected error.",
        };
        let html = GatewayErrorTemplate {
            body,
            title: &title,
        }
        .render()
        .unwrap_or(title);
        hyper::Response::builder()
            .status(status)
            .header(http::header::CONTENT_LENGTH, html.len().to_string())
            .body(
                Full::new(Bytes::from(html))
                    .map_err(|err| match err {})
                    .boxed(),
            )
            .expect("infallible")
    }
}

impl ErrorResponseWriter {
    fn new(endpoint: Endpoint, metrics: Arc<GatewayMetrics>) -> Self {
        Self { endpoint, metrics }
    }
}

fn has_existing_peer_conn(endpoint: &Endpoint) -> bool {
    let endpoint_metrics = endpoint.metrics();
    let conns_current = endpoint_metrics
        .socket
        .num_conns_opened
        .get()
        .saturating_sub(endpoint_metrics.socket.num_conns_closed.get());
    conns_current > 0
}
