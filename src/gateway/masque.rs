//! HTTP ingress over the Connector's advertised MASQUE destination.
//!
//! Only the advertised TCP port selects an origin. Routing headers never select
//! a network address at the Connector. Deploy this listener behind a trusted
//! ingress that sets the internal routing headers, not directly on the Internet.
use std::{
    collections::HashMap,
    convert::Infallible,
    io,
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use connect_transport::{DestinationId, Transport};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::{Bytes, Incoming},
    header::{CONNECTION, HOST},
    http::{HeaderMap, HeaderValue, uri::Authority},
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use iroh::{EndpointAddr, EndpointId};
use iroh_proxy_utils::downstream::{DownstreamProxy, EndpointAuthority, TunnelClientStreams};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::Semaphore,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use super::metrics::GatewayMetrics;

const NODE: &str = "x-iroh-endpoint-id";
const HOST_HEADER: &str = "x-datum-target-host";
const PORT: &str = "x-datum-target-port";
pub(super) const TRANSPORT_HEADER: &str = "x-datum-connect-transport";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DestinationTransport {
    Legacy,
    Masque,
}

impl DestinationTransport {
    fn label(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Masque => "masque-v1",
        }
    }
}

/// The header is trusted operator routing metadata, NOT a public client option.
/// Explicit invalid values never become legacy, including duplicate values.
pub(super) fn selected_transport(
    headers: &HeaderMap,
    mode: crate::config::TransportMode,
) -> Result<DestinationTransport, &'static str> {
    use crate::config::TransportMode;
    let selected = if headers.contains_key(TRANSPORT_HEADER) {
        match single_header(headers, TRANSPORT_HEADER)
            .map_err(|_| "Invalid destination transport header.")?
        {
            "legacy" => DestinationTransport::Legacy,
            "masque-v1" => DestinationTransport::Masque,
            _ => return Err("Unsupported destination transport."),
        }
    } else if matches!(mode, TransportMode::Masque) {
        // Preserve the existing explicit MASQUE-only operator mode.
        DestinationTransport::Masque
    } else {
        DestinationTransport::Legacy
    };
    match (mode, selected) {
        (TransportMode::Legacy, DestinationTransport::Masque)
        | (TransportMode::Masque, DestinationTransport::Legacy) => {
            Err("Destination transport is disabled on this gateway.")
        }
        _ => Ok(selected),
    }
}
const SETUP_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONNECTION_AGE: Duration = Duration::from_secs(24 * 60 * 60);
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
type Body = UnsyncBoxBody<Bytes, io::Error>;

trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TunnelIo for T {}

// Keep the legacy connection-pool guard alive until the stream is dropped.
struct LegacyTunnel(
    TunnelClientStreams,
    Arc<iroh_proxy_utils::downstream::DownstreamMetrics>,
);
impl AsyncRead for LegacyTunnel {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.0.recv).poll_read(cx, buf);
        self.1
            .bytes_from_upstream
            .inc_by((buf.filled().len() - before) as u64);
        result
    }
}
impl AsyncWrite for LegacyTunnel {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let result = AsyncWrite::poll_write(std::pin::Pin::new(&mut self.0.send), cx, buf);
        if let std::task::Poll::Ready(Ok(count)) = result {
            self.1.bytes_to_upstream.inc_by(count as u64);
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.0.send), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.0.send), cx)
    }
}

#[derive(Clone)]
struct State {
    transport: Transport,
    legacy: Option<DownstreamProxy>,
    peers: Arc<HashMap<EndpointId, Vec<SocketAddr>>>,
    metrics: Arc<GatewayMetrics>,
    unix: bool,
    active: Arc<Semaphore>,
}

pub(super) async fn serve(
    listener: TcpListener,
    transport: Transport,
    peers: HashMap<EndpointId, Vec<SocketAddr>>,
    metrics: Arc<GatewayMetrics>,
    legacy: Option<DownstreamProxy>,
) -> io::Result<()> {
    let state = State {
        transport,
        legacy,
        peers: Arc::new(peers),
        metrics,
        unix: false,
        active: Arc::new(Semaphore::new(1024)),
    };
    let limit = Arc::new(Semaphore::new(1024));
    loop {
        let permit = limit
            .clone()
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            connection(stream, state).await;
        });
    }
}

#[cfg(unix)]
pub(super) async fn serve_uds(
    listener: tokio::net::UnixListener,
    transport: Transport,
    peers: HashMap<EndpointId, Vec<SocketAddr>>,
    metrics: Arc<GatewayMetrics>,
    legacy: Option<DownstreamProxy>,
) -> io::Result<()> {
    let state = State {
        transport,
        legacy,
        peers: Arc::new(peers),
        metrics,
        unix: true,
        active: Arc::new(Semaphore::new(1024)),
    };
    let limit = Arc::new(Semaphore::new(1024));
    loop {
        let permit = limit
            .clone()
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            connection(stream, state).await;
        });
    }
}

async fn connection<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: S, state: State) {
    let service = hyper::service::service_fn(move |request| handle(request, state.clone()));
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(15))
        .max_buf_size(64 * 1024);
    builder
        .http2()
        .enable_connect_protocol()
        .max_concurrent_streams(1024);
    match timeout(
        MAX_CONNECTION_AGE,
        builder.serve_connection_with_upgrades(TokioIo::new(stream), service),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) => tracing::debug!(
            stage = "ingress_http",
            "gateway client connection closed with an HTTP error"
        ),
        Err(_) => tracing::warn!(
            stage = "ingress_timeout",
            "gateway connection age limit reached"
        ),
    }
}

async fn handle(request: Request<Incoming>, state: State) -> Result<Response<Body>, Infallible> {
    let request_id = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut result = handle_request(request, state, request_id).await?;
    result.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).expect("numeric request ID"),
    );
    Ok(result)
}

async fn handle_request(
    mut request: Request<Incoming>,
    state: State,
    request_id: u64,
) -> Result<Response<Body>, Infallible> {
    let started = Instant::now();
    let extended_websocket = request.version() == hyper::Version::HTTP_2
        && request.method() == Method::CONNECT
        && request.extensions().get::<hyper::ext::Protocol>().is_some();
    if extended_websocket {
        if request
            .extensions()
            .get::<hyper::ext::Protocol>()
            .unwrap()
            .as_str()
            != "websocket"
        {
            return Ok(failure(
                &state,
                request_id,
                StatusCode::BAD_REQUEST,
                "Unsupported extended CONNECT protocol.",
            ));
        }
        *request.method_mut() = Method::GET;
        *request.version_mut() = hyper::Version::HTTP_11;
        request
            .headers_mut()
            .insert("upgrade", HeaderValue::from_static("websocket"));
        request
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
    }
    let connect = request.method() == Method::CONNECT;
    count_request(&state, connect);
    let mode = if state.legacy.is_some() {
        crate::config::TransportMode::Auto
    } else {
        crate::config::TransportMode::Masque
    };
    let selected = match selected_transport(request.headers(), mode) {
        Ok(selected) => selected,
        Err(message) => {
            state.metrics.inc_dispatch("invalid");
            tracing::warn!(
                request_id,
                stage = "transport_selection",
                "invalid destination transport; no connection attempted"
            );
            return Ok(failure(
                &state,
                request_id,
                StatusCode::BAD_REQUEST,
                message,
            ));
        }
    };
    state.metrics.inc_dispatch(selected.label());
    tracing::debug!(
        request_id,
        transport = selected.label(),
        "gateway selected destination transport"
    );
    let permit = match state.active.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return Ok(failure(
                &state,
                request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                "Gateway capacity is temporarily exhausted.",
            ));
        }
    };
    let target = match parse_target(&request) {
        Ok(target) => target,
        Err(error) => {
            match error.header {
                Some(NODE) => state.metrics.inc_denied_invalid_endpoint(),
                Some(PORT) => state.metrics.inc_denied_invalid_target_port(),
                Some(header) => state.metrics.inc_denied_missing_header_name(header),
                None => {}
            }
            return Ok(failure(
                &state,
                request_id,
                StatusCode::BAD_REQUEST,
                error.message,
            ));
        }
    };
    let mut peer = EndpointAddr::new(target.peer);
    if let Some(addresses) = state.peers.get(&target.peer) {
        for address in addresses {
            peer = peer.with_ip_addr(*address);
        }
    }
    let cancel = CancellationToken::new();
    let mut tunnel = match timeout(SETUP_TIMEOUT, async {
        match selected {
            DestinationTransport::Masque => state
                .transport
                .connect_tcp(peer, DestinationId::tcp(target.port), cancel.clone())
                .await
                .map(|tunnel| Box::new(tunnel) as Box<dyn TunnelIo>)
                .map_err(|error| (transport_status(&error), transport_error_kind(&error))),
            DestinationTransport::Legacy => {
                let destination = EndpointAuthority::new(
                    target.peer,
                    iroh_proxy_utils::Authority::new(target.connect_host.clone(), target.port),
                );
                let proxy = state
                    .legacy
                    .as_ref()
                    .expect("auto mode has legacy transport");
                proxy
                    .create_tunnel(&destination)
                    .await
                    .map(|streams| {
                        Box::new(LegacyTunnel(streams, proxy.metrics().clone()))
                            as Box<dyn TunnelIo>
                    })
                    .map_err(|error| {
                        (
                            error.response_status().unwrap_or(StatusCode::BAD_GATEWAY),
                            "legacy_connect",
                        )
                    })
            }
        }
    })
    .await
    {
        Ok(Ok(tunnel)) => tunnel,
        Ok(Err((status, error_kind))) => {
            cancel.cancel();
            state.metrics.inc_dispatch_failure(selected.label());
            tracing::warn!(request_id, transport=selected.label(), peer=%target.peer, port=target.port, stage="upstream_connect", error_kind, status=status.as_u16(), elapsed_ms=started.elapsed().as_millis() as u64, "gateway tunnel establishment failed; no fallback");
            return Ok(failure(
                &state,
                request_id,
                status,
                "The advertised service is unavailable through this gateway.",
            ));
        }
        Err(_) => {
            cancel.cancel();
            state.metrics.inc_dispatch_failure(selected.label());
            tracing::warn!(
                request_id,
                transport = selected.label(),
                stage = "upstream_connect",
                "gateway tunnel establishment timed out; no fallback"
            );
            return Ok(failure(
                &state,
                request_id,
                StatusCode::GATEWAY_TIMEOUT,
                "The Connector did not respond in time.",
            ));
        }
    };
    tracing::info!(request_id, transport=selected.label(), peer=%target.peer, port=target.port, elapsed_ms=started.elapsed().as_millis() as u64, "gateway upstream tunnel established");
    if selected == DestinationTransport::Masque
        && let Some(diagnostics) = state.transport.peer_diagnostics(target.peer)
    {
        tracing::info!(request_id, peer=%target.peer, port=target.port, path=?diagnostics.path, rtt_us=diagnostics.latency.map(|value| value.as_micros() as u64), "gateway MASQUE connection established");
    }
    if connect {
        let upgrade = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            let _permit = permit;
            let _cancel_on_drop = cancel.drop_guard();
            let upgraded = match timeout(SETUP_TIMEOUT, upgrade).await {
                Ok(Ok(upgraded)) => upgraded,
                _ => {
                    tracing::warn!(
                        request_id,
                        stage = "connect_upgrade",
                        "gateway CONNECT upgrade failed"
                    );
                    return;
                }
            };
            let mut client = TokioIo::new(upgraded);
            match timeout(
                MAX_CONNECTION_AGE,
                tokio::io::copy_bidirectional(&mut client, &mut tunnel),
            )
            .await
            {
                Ok(Ok((sent, received))) => {
                    tracing::info!(request_id, peer=%target.peer, port=target.port, bytes_sent=sent, bytes_received=received, elapsed_ms=started.elapsed().as_millis() as u64, "gateway CONNECT closed")
                }
                Ok(Err(_)) => tracing::warn!(
                    request_id,
                    stage = "connect_copy",
                    "gateway CONNECT forwarding failed"
                ),
                Err(_) => tracing::warn!(
                    request_id,
                    stage = "connect_timeout",
                    "gateway CONNECT age limit reached"
                ),
            }
        });
        state.metrics.inc_status_code(StatusCode::OK);
        return Ok(response(StatusCode::OK, ""));
    }

    let ingress_upgrade = request
        .headers()
        .contains_key("upgrade")
        .then(|| hyper::upgrade::on(&mut request));
    strip_headers(request.headers_mut());
    if ingress_upgrade.is_some() {
        request
            .headers_mut()
            .insert("upgrade", HeaderValue::from_static("websocket"));
        request
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
    }
    if let Some(original_host) = request.headers_mut().remove(HOST) {
        request
            .headers_mut()
            .insert("x-forwarded-host", original_host);
    }
    request.headers_mut().insert(
        HOST,
        target.host.expect("origin targets include validated Host"),
    );
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    *request.uri_mut() = Uri::from_str(path).unwrap_or_else(|_| Uri::from_static("/"));
    *request.version_mut() = hyper::Version::HTTP_11;
    let (mut sender, driver) = match timeout(
        SETUP_TIMEOUT,
        hyper::client::conn::http1::handshake(TokioIo::new(tunnel)),
    )
    .await
    {
        Ok(Ok(result)) => result,
        _ => {
            cancel.cancel();
            return Ok(failure(
                &state,
                request_id,
                StatusCode::BAD_GATEWAY,
                "The origin HTTP connection could not be established.",
            ));
        }
    };
    let response_cancel = cancel.clone();
    let cancel_guard = response_cancel.clone().drop_guard();
    tokio::spawn(async move {
        let result = tokio::select! {
            result = timeout(MAX_CONNECTION_AGE, driver.with_upgrades()) => result,
            _ = cancel.cancelled() => return,
        };
        if !matches!(result, Ok(Ok(()))) {
            cancel.cancel();
            tracing::debug!(
                request_id,
                stage = "origin_http",
                "gateway origin connection ended with an error or timeout"
            );
        }
    });
    let mut upstream = match timeout(RESPONSE_TIMEOUT, sender.send_request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => {
            response_cancel.cancel();
            return Ok(failure(
                &state,
                request_id,
                StatusCode::BAD_GATEWAY,
                "The origin did not return a valid HTTP response.",
            ));
        }
        Err(_) => {
            response_cancel.cancel();
            return Ok(failure(
                &state,
                request_id,
                StatusCode::GATEWAY_TIMEOUT,
                "The origin response timed out.",
            ));
        }
    };
    if upstream.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = ingress_upgrade else {
            return Ok(failure(
                &state,
                request_id,
                StatusCode::BAD_GATEWAY,
                "The origin returned an unsolicited protocol upgrade.",
            ));
        };
        if !websocket_headers(upstream.headers()) {
            return Ok(failure(
                &state,
                request_id,
                StatusCode::BAD_GATEWAY,
                "The origin returned an invalid WebSocket upgrade.",
            ));
        }
        let origin_upgrade = hyper::upgrade::on(&mut upstream);
        strip_headers(upstream.headers_mut());
        if extended_websocket {
            *upstream.status_mut() = StatusCode::OK;
        } else {
            upstream
                .headers_mut()
                .insert("upgrade", HeaderValue::from_static("websocket"));
            upstream
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("upgrade"));
        }
        tokio::spawn(async move {
            let _permit = permit;
            let _cancel = cancel_guard;
            let upgrades = timeout(SETUP_TIMEOUT, async {
                tokio::try_join!(client_upgrade, origin_upgrade)
            })
            .await;
            let (client, origin) = match upgrades {
                Ok(Ok(pair)) => pair,
                _ => {
                    tracing::warn!(
                        request_id,
                        stage = "websocket_upgrade",
                        "gateway WebSocket upgrade failed"
                    );
                    return;
                }
            };
            match timeout(
                MAX_CONNECTION_AGE,
                tokio::io::copy_bidirectional(&mut TokioIo::new(client), &mut TokioIo::new(origin)),
            )
            .await
            {
                Ok(Ok((sent, received))) => tracing::info!(
                    request_id,
                    bytes_sent = sent,
                    bytes_received = received,
                    "gateway WebSocket closed"
                ),
                _ => tracing::warn!(
                    request_id,
                    stage = "websocket_copy",
                    "gateway WebSocket forwarding ended with error or timeout"
                ),
            }
        });
        state.metrics.inc_status_code(upstream.status());
        return Ok(upstream.map(|_| {
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed_unsync()
        }));
    }
    strip_headers(upstream.headers_mut());
    let status = upstream.status();
    state.metrics.inc_status_code(status);
    tracing::info!(request_id, peer=%target.peer, port=target.port, status=status.as_u16(), elapsed_ms=started.elapsed().as_millis() as u64, "gateway origin response headers received");
    Ok(upstream.map(|body| {
        CancelBody {
            inner: body,
            _cancel: cancel_guard,
            _permit: permit,
        }
        .map_err(io::Error::other)
        .boxed_unsync()
    }))
}

/// Dropping a downstream response also closes its MASQUE association.
struct CancelBody {
    inner: Incoming,
    _cancel: tokio_util::sync::DropGuard,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl hyper::body::Body for CancelBody {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

struct Target {
    peer: EndpointId,
    port: u16,
    host: Option<HeaderValue>,
    connect_host: String,
}
#[derive(Debug)]
struct InvalidTarget {
    header: Option<&'static str>,
    message: &'static str,
}

fn invalid(header: Option<&'static str>, message: &'static str) -> InvalidTarget {
    InvalidTarget { header, message }
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, InvalidTarget> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| invalid(Some(name), "A required gateway routing header is missing."))?;
    if values.next().is_some() {
        return Err(invalid(
            Some(name),
            "Duplicate gateway routing headers are not allowed.",
        ));
    }
    value
        .to_str()
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(Some(name), "A gateway routing header is invalid."))
}

fn parse_target<B>(request: &Request<B>) -> Result<Target, InvalidTarget> {
    let peer = single_header(request.headers(), NODE)?
        .parse()
        .map_err(|_| invalid(Some(NODE), "Invalid Connector public key."))?;
    if request.method() == Method::CONNECT {
        if request.uri().scheme().is_some() || request.uri().path_and_query().is_some() {
            return Err(invalid(None, "CONNECT requires a HOST:PORT authority."));
        }
        let authority = request
            .uri()
            .authority()
            .ok_or_else(|| invalid(None, "CONNECT requires a HOST:PORT authority."))?;
        if authority.host().is_empty() || authority.as_str().contains('@') {
            return Err(invalid(None, "Invalid CONNECT authority."));
        }
        let port = authority
            .port_u16()
            .filter(|port| *port != 0)
            .ok_or_else(|| invalid(Some(PORT), "CONNECT requires a nonzero TCP port."))?;
        // Reject ambiguity even though CONNECT routes by authority, not these optional headers.
        for name in [HOST_HEADER, PORT] {
            if request.headers().contains_key(name) {
                let value = single_header(request.headers(), name)?;
                if name == PORT
                    && value
                        .parse::<u16>()
                        .ok()
                        .filter(|port| *port != 0)
                        .is_none()
                {
                    return Err(invalid(
                        Some(PORT),
                        "Target port must be an integer from 1 to 65535.",
                    ));
                }
                if name == HOST_HEADER && !valid_target_host(value) {
                    return Err(invalid(Some(HOST_HEADER), "Invalid target Host header."));
                }
            }
        }
        return Ok(Target {
            peer,
            port,
            host: None,
            connect_host: authority.host().to_owned(),
        });
    }
    if request.headers().contains_key("upgrade")
        && (request.method() != Method::GET
            || request.version() != hyper::Version::HTTP_11
            || !websocket_headers(request.headers()))
    {
        return Err(invalid(
            None,
            "Only valid HTTP/1.1 WebSocket upgrades are supported.",
        ));
    }
    let host = single_header(request.headers(), HOST_HEADER)?;
    let authority = Authority::from_str(host)
        .map_err(|_| invalid(Some(HOST_HEADER), "Invalid target Host header."))?;
    if authority.host().is_empty()
        || authority.port().is_some()
        || host.contains('@')
        || host.contains(',')
    {
        return Err(invalid(
            Some(HOST_HEADER),
            "Target host must contain only a hostname or bracketed IPv6 address.",
        ));
    }
    let port = single_header(request.headers(), PORT)?
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            invalid(
                Some(PORT),
                "Target port must be an integer from 1 to 65535.",
            )
        })?;
    let connect_host = host.to_owned();
    let host = HeaderValue::from_str(&format!("{host}:{port}"))
        .map_err(|_| invalid(Some(HOST_HEADER), "Invalid target Host header."))?;
    Ok(Target {
        peer,
        port,
        host: Some(host),
        connect_host,
    })
}

fn valid_target_host(host: &str) -> bool {
    Authority::from_str(host).is_ok_and(|authority| {
        !authority.host().is_empty()
            && authority.port().is_none()
            && !host.contains('@')
            && !host.contains(',')
    })
}

fn websocket_headers(headers: &HeaderMap) -> bool {
    let mut upgrade = headers.get_all("upgrade").iter();
    let valid_upgrade = upgrade
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && upgrade.next().is_none();
    valid_upgrade
        && headers
            .get_all(CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case("upgrade"))
}

fn strip_headers(headers: &mut HeaderMap) {
    let connection_names: Vec<_> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| hyper::header::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in connection_names {
        headers.remove(name);
    }
    let internal: Vec<_> = headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with("x-datum-") || name.as_str().starts_with("x-iroh-")
        })
        .cloned()
        .collect();
    for name in internal {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn transport_status(error: &connect_transport::Error) -> StatusCode {
    match error {
        connect_transport::Error::Timeout => StatusCode::GATEWAY_TIMEOUT,
        connect_transport::Error::Rejected(status)
            if *status == StatusCode::FORBIDDEN || *status == StatusCode::NOT_FOUND =>
        {
            *status
        }
        _ => StatusCode::BAD_GATEWAY,
    }
}

fn transport_error_kind(error: &connect_transport::Error) -> &'static str {
    match error {
        connect_transport::Error::DatagramTooLarge => "oversize",
        connect_transport::Error::Timeout => "timeout",
        connect_transport::Error::Rejected(StatusCode::FORBIDDEN) => "access_denied",
        connect_transport::Error::Rejected(StatusCode::NOT_FOUND) => "destination_not_advertised",
        connect_transport::Error::Rejected(_) => "peer_rejected",
        connect_transport::Error::Protocol(detail)
            if detail.to_ascii_lowercase().contains("alpn")
                || detail.to_ascii_lowercase().contains("application protocol") =>
        {
            "protocol_negotiation"
        }
        connect_transport::Error::Protocol(_) => "transport_protocol",
        connect_transport::Error::Closed => "closed",
        connect_transport::Error::Io(_) => "transport_io",
        connect_transport::Error::InvalidDestinationId
        | connect_transport::Error::MissingDestination => "invalid_destination",
    }
}

fn response(status: StatusCode, message: &'static str) -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::from_static(message.as_bytes()))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn failure(
    state: &State,
    request_id: u64,
    status: StatusCode,
    message: &'static str,
) -> Response<Body> {
    state.metrics.inc_status_code(status);
    tracing::warn!(
        request_id,
        status = status.as_u16(),
        "gateway request rejected"
    );
    response(status, message)
}

fn count_request(state: &State, connect: bool) {
    if state.unix {
        #[cfg(unix)]
        state.metrics.inc_uds_requests();
    } else {
        state.metrics.inc_tcp_requests();
    }
    if connect {
        state.metrics.inc_tunnel_requests();
        if state.unix {
            #[cfg(unix)]
            state.metrics.inc_tunnel_uds_requests();
        } else {
            state.metrics.inc_tunnel_tcp_requests();
        }
    } else {
        state.metrics.inc_origin_requests();
        if state.unix {
            #[cfg(unix)]
            state.metrics.inc_origin_uds_requests();
        } else {
            state.metrics.inc_origin_tcp_requests();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_selection_is_explicit_and_fail_closed() {
        use crate::config::TransportMode;
        let mut headers = HeaderMap::new();
        assert_eq!(
            selected_transport(&headers, TransportMode::Auto).unwrap(),
            DestinationTransport::Legacy
        );
        for (value, expected) in [
            ("legacy", DestinationTransport::Legacy),
            ("masque-v1", DestinationTransport::Masque),
        ] {
            headers.insert(TRANSPORT_HEADER, value.parse().unwrap());
            assert_eq!(
                selected_transport(&headers, TransportMode::Auto).unwrap(),
                expected
            );
        }
        assert!(selected_transport(&headers, TransportMode::Legacy).is_err());
        for value in [
            "",
            "masque",
            "masque-v2",
            "MASQUE-V1",
            "legacy,masque-v1",
            " masque-v1",
        ] {
            headers.insert(TRANSPORT_HEADER, value.parse().unwrap());
            assert!(
                selected_transport(&headers, TransportMode::Auto).is_err(),
                "{value}"
            );
        }
        headers.insert(TRANSPORT_HEADER, "legacy".parse().unwrap());
        headers.append(TRANSPORT_HEADER, "legacy".parse().unwrap());
        assert!(selected_transport(&headers, TransportMode::Auto).is_err());
        headers.insert(TRANSPORT_HEADER, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(selected_transport(&headers, TransportMode::Auto).is_err());
        headers.clear();
        assert_eq!(
            selected_transport(&headers, TransportMode::Masque).unwrap(),
            DestinationTransport::Masque
        );
    }

    #[tokio::test]
    async fn one_listener_routes_legacy_and_masque_without_fallback() {
        use connect_transport::{
            Access, DestinationPolicy, Policy, Target as OriginTarget, TransportConfig,
        };
        use iroh_proxy_utils::upstream::{AuthError, AuthHandler, UpstreamProxy};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[derive(Debug, Clone)]
        struct AllowGateway(EndpointId);
        impl AuthHandler for AllowGateway {
            async fn authorize<'a>(
                &'a self,
                remote: EndpointId,
                _: &'a iroh_proxy_utils::HttpProxyRequest,
            ) -> n0_error::Result<(), AuthError> {
                if remote == self.0 {
                    Ok(())
                } else {
                    Err(AuthError::Forbidden)
                }
            }
        }

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = origin.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        match socket.read_u8().await {
                            Ok(byte) => header.push(byte),
                            Err(_) => return,
                        }
                    }
                    let text = String::from_utf8_lossy(&header).to_lowercase();
                    assert!(!text.contains("x-datum-"));
                    assert!(!text.contains("x-iroh-"));
                    if text.contains("upgrade: websocket") {
                        socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
                        let mut bytes = [0; 4];
                        socket.read_exact(&mut bytes).await.unwrap();
                        socket.write_all(&bytes).await.unwrap();
                    } else {
                        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").await.unwrap();
                    }
                });
            }
        });
        let gateway = Transport::bind(
            TransportConfig::new(iroh::SecretKey::generate())
                .bind_addr("127.0.0.1:0".parse().unwrap()),
        )
        .await
        .unwrap();
        let legacy_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Empty)
            .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let legacy_id = legacy_endpoint.id();
        let legacy_addr = legacy_endpoint.addr();
        let router = iroh::protocol::Router::builder(legacy_endpoint)
            .accept(
                iroh_proxy_utils::ALPN,
                UpstreamProxy::new(AllowGateway(gateway.endpoint_id())).unwrap(),
            )
            .spawn();
        let remote = Transport::bind(
            TransportConfig::new(iroh::SecretKey::generate())
                .bind_addr("127.0.0.1:0".parse().unwrap()),
        )
        .await
        .unwrap();
        let mut policy = Policy::default();
        policy.destinations.insert(
            DestinationId::tcp(origin_addr.port()),
            DestinationPolicy {
                target: OriginTarget::Tcp(origin_addr),
                access: Access::Peers([gateway.endpoint_id()].into()),
            },
        );
        remote.replace_policy(policy).await.unwrap();
        gateway.endpoint().address_lookup().unwrap().add(
            iroh::address_lookup::memory::MemoryLookup::from_endpoint_info([
                legacy_addr.clone(),
                remote.endpoint().addr(),
            ]),
        );
        let proxy = DownstreamProxy::new(gateway.endpoint(), Default::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(GatewayMetrics::default());
        let task = tokio::spawn(serve(
            listener,
            gateway.clone(),
            HashMap::from([
                (legacy_id, legacy_addr.ip_addrs().copied().collect()),
                (
                    remote.endpoint_id(),
                    remote.connection_details().direct_addresses,
                ),
            ]),
            metrics.clone(),
            Some(proxy),
        ));

        timeout(Duration::from_secs(45), async {
            // One HTTP/1 keep-alive connection switches protocols per request.
            let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut sender, driver) = hyper::client::conn::http1::handshake(TokioIo::new(socket)).await.unwrap();
            let driver = tokio::spawn(driver.with_upgrades());
            for (id, selection, expected) in [
                (legacy_id, None, StatusCode::OK),
                (remote.endpoint_id(), Some("masque-v1"), StatusCode::OK),
                (legacy_id, Some("legacy"), StatusCode::OK),
                (legacy_id, Some("unknown"), StatusCode::BAD_REQUEST),
                (legacy_id, Some(""), StatusCode::BAD_REQUEST),
                // Wrong profile must fail, even though legacy would succeed.
                (legacy_id, Some("masque-v1"), StatusCode::BAD_GATEWAY),
                (remote.endpoint_id(), None, StatusCode::GATEWAY_TIMEOUT),
            ] {
                let mut req = Request::builder().uri("/probe").header(NODE, id.to_string()).header(HOST_HEADER, "127.0.0.1").header(PORT, origin_addr.port()).body(Full::new(Bytes::new())).unwrap();
                if let Some(value) = selection { req.headers_mut().insert(TRANSPORT_HEADER, value.parse().unwrap()); }
                let response = sender.send_request(req).await.unwrap();
                // Legacy library maps negotiation failures to gateway timeout.
                assert_eq!(response.status(), expected, "selection {selection:?}, peer {id}");
                let body = response.into_body().collect().await.unwrap().to_bytes();
                if expected == StatusCode::OK { assert_eq!(body, "hello"); }
            }
            driver.abort();
            for (id, selection) in [(legacy_id, ""), (remote.endpoint_id(), "x-datum-connect-transport: masque-v1\r\n")] {
                // Ordinary CONNECT and WebSocket upgrades on the same listener.
                for websocket in [false, true] {
                    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
                    let start = if websocket { "GET / HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n".to_owned() } else { format!("CONNECT {origin_addr} HTTP/1.1\r\n") };
                    socket.write_all(format!("{start}Host: public.example\r\nx-iroh-endpoint-id: {id}\r\nx-datum-target-host: 127.0.0.1\r\nx-datum-target-port: {}\r\n{selection}\r\n", origin_addr.port()).as_bytes()).await.unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") { header.push(socket.read_u8().await.unwrap()); }
                    if websocket {
                        assert!(header.starts_with(b"HTTP/1.1 101"));
                        socket.write_all(b"echo").await.unwrap();
                        let mut echoed = [0;4]; socket.read_exact(&mut echoed).await.unwrap(); assert_eq!(&echoed, b"echo");
                    } else {
                        assert!(header.starts_with(b"HTTP/1.1 200"));
                        socket.write_all(b"GET / HTTP/1.1\r\nHost: origin\r\n\r\n").await.unwrap();
                        let mut response = Vec::new(); socket.read_to_end(&mut response).await.unwrap(); assert!(response.ends_with(b"hello"));
                    }
                }
            }
            // Envoy uses HTTP/2 CONNECT: verify both upstream profiles.
            let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut sender, driver) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(socket)).await.unwrap();
            let driver = tokio::spawn(driver);
            for (id, selection) in [(legacy_id, "legacy"), (remote.endpoint_id(), "masque-v1")] {
                let req = Request::builder().method(Method::CONNECT).uri(origin_addr.to_string()).header(NODE, id.to_string()).header(TRANSPORT_HEADER, selection).body(Full::new(Bytes::new())).unwrap();
                let response = sender.send_request(req).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let mut stream = TokioIo::new(hyper::upgrade::on(response).await.unwrap());
                stream.write_all(b"GET / HTTP/1.1\r\nHost: origin\r\n\r\n").await.unwrap();
                let mut body = Vec::new(); stream.read_to_end(&mut body).await.unwrap(); assert!(body.ends_with(b"hello"));
            }
            driver.abort();
        }).await.unwrap();
        let rendered = metrics.render_dispatch();
        assert!(rendered.contains("protocol=\"invalid\"} 2"));
        task.abort();
        origin_task.abort();
        router.shutdown().await.unwrap();
        gateway.shutdown().await;
        remote.shutdown().await;
    }
    fn request() -> Request<()> {
        Request::builder()
            .uri("/hello?world=1")
            .header(
                NODE,
                iroh::SecretKey::from_bytes(&[7; 32]).public().to_string(),
            )
            .header(HOST_HEADER, "localhost")
            .header(PORT, "8080")
            .body(())
            .unwrap()
    }
    #[test]
    fn origin_uses_only_advertised_port_and_host_header() {
        let mut req = request();
        *req.uri_mut() = "http://attacker.invalid/hello".parse().unwrap();
        let target = parse_target(&req).unwrap();
        assert_eq!(target.port, 8080);
        assert_eq!(target.host.unwrap(), "localhost:8080");
    }
    #[test]
    fn rejects_missing_malformed_duplicate_and_zero_routing_headers() {
        for name in [NODE, HOST_HEADER, PORT] {
            let mut req = request();
            req.headers_mut().remove(name);
            assert!(parse_target(&req).is_err());
            let mut req = request();
            let value = req.headers()[name].clone();
            req.headers_mut().append(name, value);
            assert!(parse_target(&req).is_err());
        }
        for (name, value) in [
            (NODE, "invalid"),
            (PORT, "0"),
            (PORT, "65536"),
            (PORT, "80,443"),
            (HOST_HEADER, "a:80"),
            (HOST_HEADER, "user@host"),
            (HOST_HEADER, "host/path"),
        ] {
            let mut req = request();
            req.headers_mut().insert(name, value.parse().unwrap());
            assert!(parse_target(&req).is_err(), "{name}: {value}");
        }
    }
    #[test]
    fn connect_uses_authority_and_rejects_invalid_ports() {
        let mut req = request();
        *req.method_mut() = Method::CONNECT;
        *req.uri_mut() = "example.test:443".parse().unwrap();
        assert_eq!(parse_target(&req).unwrap().port, 443);
        for uri in [
            "example.test:0",
            "example.test",
            "http://example.test:443/",
            "user@example.test:443",
        ] {
            *req.uri_mut() = uri.parse().unwrap();
            assert!(parse_target(&req).is_err(), "{uri}");
        }
    }
    #[test]
    fn strips_internal_and_hop_headers_without_removing_application_auth() {
        let mut req = request();
        req.headers_mut()
            .insert("connection", "x-hop".parse().unwrap());
        req.headers_mut()
            .insert("x-hop", "private".parse().unwrap());
        req.headers_mut()
            .insert("x-datum-unknown", "private".parse().unwrap());
        req.headers_mut()
            .insert("authorization", "Bearer origin-secret".parse().unwrap());
        strip_headers(req.headers_mut());
        assert_eq!(req.headers().len(), 1);
        assert!(req.headers().contains_key("authorization"));
    }
    #[test]
    fn error_status_mapping_is_fail_closed() {
        assert_eq!(
            transport_status(&connect_transport::Error::Timeout),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            transport_status(&connect_transport::Error::Rejected(StatusCode::FORBIDDEN)),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            transport_status(&connect_transport::Error::Protocol("private".into())),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            response(StatusCode::BAD_REQUEST, "invalid").status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn validates_websocket_upgrade_headers() {
        let mut req = request();
        req.headers_mut()
            .insert("upgrade", "websocket".parse().unwrap());
        assert!(parse_target(&req).is_err());
        req.headers_mut()
            .insert(CONNECTION, "keep-alive, Upgrade".parse().unwrap());
        assert!(parse_target(&req).is_ok());
        req.headers_mut()
            .append("upgrade", "websocket".parse().unwrap());
        assert!(parse_target(&req).is_err());
    }

    #[tokio::test]
    async fn websocket_upgrade_relays_bytes_over_real_masque() {
        use connect_transport::{
            Access, DestinationPolicy, Policy, Target as OriginTarget, TransportConfig,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut socket, _) = origin.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(socket.read_u8().await.unwrap());
            }
            let header = String::from_utf8(header).unwrap().to_lowercase();
            assert!(!header.contains("x-datum-"));
            assert!(!header.contains("x-iroh-"));
            assert!(header.contains("host: localhost:8080\r\n"));
            assert!(header.contains("x-forwarded-host: public.example\r\n"));
            socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
            let mut data = [0; 8];
            socket.read_exact(&mut data).await.unwrap();
            socket.write_all(&data).await.unwrap();
        });
        let remote = Transport::bind(
            TransportConfig::new(iroh::SecretKey::from_bytes(&[81; 32]))
                .bind_addr("127.0.0.1:0".parse().unwrap()),
        )
        .await
        .unwrap();
        let gateway = Transport::bind(
            TransportConfig::new(iroh::SecretKey::from_bytes(&[82; 32]))
                .bind_addr("127.0.0.1:0".parse().unwrap()),
        )
        .await
        .unwrap();
        let mut policy = Policy::default();
        policy.destinations.insert(
            DestinationId::tcp(8080),
            DestinationPolicy {
                target: OriginTarget::Tcp(origin_addr),
                access: Access::Peers([gateway.endpoint_id()].into()),
            },
        );
        remote.replace_policy(policy).await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peers = HashMap::from([(
            remote.endpoint_id(),
            remote.connection_details().direct_addresses,
        )]);
        let task = tokio::spawn(serve(
            listener,
            gateway.clone(),
            peers,
            super::super::metrics::shared_gateway_metrics(),
            None,
        ));
        timeout(Duration::from_secs(15), async {
            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            client.write_all(format!("GET / HTTP/1.1\r\nHost: public.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nx-iroh-endpoint-id: {}\r\nx-datum-target-host: localhost\r\nx-datum-target-port: 8080\r\n\r\n", remote.endpoint_id()).as_bytes()).await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") { header.push(client.read_u8().await.unwrap()); }
            assert!(header.starts_with(b"HTTP/1.1 101"));
            assert!(String::from_utf8_lossy(&header).contains("x-request-id:"));
            client.write_all(b"ws-bytes").await.unwrap();
            let mut echoed = [0; 8]; client.read_exact(&mut echoed).await.unwrap(); assert_eq!(&echoed, b"ws-bytes");
        }).await.unwrap();
        origin_task.await.unwrap();
        task.abort();
        gateway.shutdown().await;
        remote.shutdown().await;
    }
}
