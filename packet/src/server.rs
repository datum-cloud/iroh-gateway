//! The packet session listener.

use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, Incoming, RecvStream, SendStream, VarInt},
};
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinHandle,
    time::{Instant, sleep, timeout, timeout_at},
};
use tracing::{debug, info, warn};

use crate::{
    admission::{GrantTable, Ipv6Prefix, Principal, RejectReason},
    backend::{BackendSession, PacketBackend, SessionId, SessionInfo},
    wire::{self, AdmitAccept, AdmitRequest, FrameHeader},
};

/// Smallest datagram a session must be able to send: the type byte plus a
/// minimum-MTU IPv6 packet.
pub const REQUIRED_DATAGRAM_SIZE: usize = wire::DGRAM_PREFIX_LEN + wire::IPV6_MIN_MTU as usize;

/// Listener configuration.
#[derive(Debug, Clone)]
pub struct PacketServerConfig {
    /// Credentials and grants.
    pub grants: GrantTable,
    /// Largest session MTU to offer. At least 1280.
    pub max_session_mtu: u16,
    /// Time from connection to a complete `ADMIT_REQUEST`.
    pub admission_timeout: Duration,
    /// How long to wait for path MTU discovery to reach
    /// [`REQUIRED_DATAGRAM_SIZE`] before rejecting.
    pub mtu_wait: Duration,
    /// How long a rejected client gets to read the rejection.
    pub reject_linger: Duration,
    /// Packets queued from the backend to one client.
    pub to_client_queue: usize,
}

impl PacketServerConfig {
    /// A configuration with default limits.
    pub fn new(grants: GrantTable) -> Self {
        Self {
            grants,
            max_session_mtu: wire::IPV6_MIN_MTU,
            admission_timeout: Duration::from_secs(5),
            mtu_wait: Duration::from_secs(5),
            reject_linger: Duration::from_secs(1),
            to_client_queue: 256,
        }
    }
}

/// Something the listener decided, for logs and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionEvent {
    /// A session was admitted and its backend session opened.
    Admitted {
        /// Session id.
        session: SessionId,
        /// Authenticated client endpoint id.
        remote: EndpointId,
        /// Admitted principal.
        principal: Principal,
        /// VPC.
        vpc: String,
        /// Offered session MTU.
        mtu: u16,
        /// `max_datagram_size` right after the handshake.
        initial_max_datagram_size: Option<usize>,
        /// `max_datagram_size` when admission was decided.
        max_datagram_size: usize,
        /// Whether every open path of the connection went through a relay.
        relay_only: bool,
    },
    /// A connection was rejected. No backend session was opened.
    Rejected {
        /// Authenticated client endpoint id.
        remote: EndpointId,
        /// Reason.
        reason: RejectReason,
        /// `max_datagram_size` when the rejection was decided.
        max_datagram_size: Option<usize>,
    },
    /// A session ended and its backend session was released.
    Released {
        /// Session id.
        session: SessionId,
    },
}

/// A running packet listener on its own iroh endpoint.
///
/// The endpoint must use a key of its own; it must never be the HTTP proxy's
/// endpoint or key. [`PacketServer::spawn`] replaces the endpoint's ALPN list
/// with [`wire::ALPN`] alone, so connections for any other protocol fail the
/// TLS handshake.
#[derive(Debug)]
pub struct PacketServer {
    endpoint: Endpoint,
    events: broadcast::Sender<AdmissionEvent>,
    accept_task: JoinHandle<()>,
}

struct Shared {
    config: PacketServerConfig,
    backend: Arc<dyn PacketBackend>,
    events: broadcast::Sender<AdmissionEvent>,
    live: Mutex<HashSet<(Principal, String)>>,
    next_id: AtomicU64,
}

impl Shared {
    fn emit(&self, ev: AdmissionEvent) {
        let _ = self.events.send(ev);
    }
}

impl PacketServer {
    /// Starts accepting packet sessions on `endpoint`.
    pub fn spawn(
        endpoint: Endpoint,
        config: PacketServerConfig,
        backend: Arc<dyn PacketBackend>,
    ) -> Self {
        assert!(
            config.max_session_mtu >= wire::IPV6_MIN_MTU,
            "max_session_mtu below the IPv6 minimum MTU"
        );
        endpoint.set_alpns(vec![wire::ALPN.to_vec()]);
        let (events, _) = broadcast::channel(1024);
        let shared = Arc::new(Shared {
            config,
            backend,
            events: events.clone(),
            live: Mutex::new(HashSet::new()),
            next_id: AtomicU64::new(1),
        });
        let ep = endpoint.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                tokio::spawn(handle(incoming, shared.clone()));
            }
        });
        info!(endpoint_id = %endpoint.id().fmt_short(), "iroh packet listener started");
        Self {
            endpoint,
            events,
            accept_task,
        }
    }

    /// The listener's endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Subscribes to admission events.
    pub fn subscribe(&self) -> broadcast::Receiver<AdmissionEvent> {
        self.events.subscribe()
    }

    /// Stops accepting and closes every connection.
    pub async fn shutdown(self) {
        self.accept_task.abort();
        self.endpoint.close().await;
    }
}

/// Removes a live-session reservation when dropped.
struct Reservation {
    shared: Arc<Shared>,
    key: (Principal, String),
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.shared.live.lock().expect("poisoned").remove(&self.key);
    }
}

struct Admitted {
    info: SessionInfo,
    routes: Vec<Ipv6Prefix>,
    send: SendStream,
    recv: RecvStream,
    accept_frame: Bytes,
    backend: Box<dyn BackendSession>,
    to_client: mpsc::Receiver<Bytes>,
    _reservation: Reservation,
}

struct Rejection {
    reason: RejectReason,
    send: Option<SendStream>,
}

impl Rejection {
    fn new(reason: RejectReason, send: Option<SendStream>) -> Self {
        Self { reason, send }
    }
}

async fn handle(incoming: Incoming, shared: Arc<Shared>) {
    let conn = match incoming.accept() {
        Ok(accepting) => match accepting.await {
            Ok(conn) => conn,
            Err(err) => {
                debug!(%err, "packet handshake failed");
                return;
            }
        },
        Err(err) => {
            debug!(%err, "packet connection refused");
            return;
        }
    };
    if conn.alpn() != wire::ALPN {
        // Unreachable while the endpoint only offers our ALPN; kept so a
        // misconfigured endpoint can never hand another protocol a session.
        conn.close(
            VarInt::from(u32::from(wire::REJECT_UNEXPECTED_FRAME)),
            b"alpn",
        );
        return;
    }
    let remote = conn.remote_id();
    let initial_mds = conn.max_datagram_size();
    match admit(&conn, remote, initial_mds, &shared).await {
        Ok(admitted) => run_session(conn, admitted, shared).await,
        Err(rejection) => {
            let mds = conn.max_datagram_size();
            debug!(remote = %remote.fmt_short(), reason = ?rejection.reason, "packet session rejected");
            shared.emit(AdmissionEvent::Rejected {
                remote,
                reason: rejection.reason,
                max_datagram_size: mds,
            });
            reject(conn, rejection, shared.config.reject_linger).await;
        }
    }
}

async fn read_request(
    recv: &mut RecvStream,
    deadline: Instant,
) -> Result<AdmitRequest, RejectReason> {
    let mut header = [0u8; wire::FRAME_HEADER_LEN];
    match timeout_at(deadline, recv.read_exact(&mut header)).await {
        Err(_) => return Err(RejectReason::Timeout),
        Ok(Err(_)) => return Err(RejectReason::Malformed),
        Ok(Ok(())) => {}
    }
    let header = FrameHeader::decode(header);
    if header.version != wire::FRAME_VERSION {
        return Err(RejectReason::UnsupportedVersion);
    }
    if header.frame_type != wire::FRAME_ADMIT_REQUEST {
        return Err(RejectReason::UnexpectedFrame);
    }
    let len = usize::from(header.length);
    if len > wire::MAX_CONTROL_PAYLOAD {
        return Err(RejectReason::FrameTooLarge);
    }
    let mut payload = vec![0u8; len];
    match timeout_at(deadline, recv.read_exact(&mut payload)).await {
        Err(_) => return Err(RejectReason::Timeout),
        Ok(Err(_)) => return Err(RejectReason::Malformed),
        Ok(Ok(())) => {}
    }
    AdmitRequest::decode(&payload).map_err(|_| RejectReason::Malformed)
}

/// Waits for the connection to carry [`REQUIRED_DATAGRAM_SIZE`] bytes in one
/// datagram. Returns the last observed size.
async fn wait_for_datagram_size(conn: &Connection, wait: Duration) -> Result<usize, RejectReason> {
    let deadline = Instant::now() + wait;
    loop {
        let Some(mds) = conn.max_datagram_size() else {
            return Err(RejectReason::DatagramsUnsupported);
        };
        if mds >= REQUIRED_DATAGRAM_SIZE {
            return Ok(mds);
        }
        if Instant::now() >= deadline {
            return Err(RejectReason::PathMtuTooSmall);
        }
        sleep(Duration::from_millis(20)).await;
    }
}

fn relay_only(conn: &Connection) -> bool {
    let paths = conn.paths();
    let mut any = false;
    for p in &paths {
        if !p.is_relay() {
            return false;
        }
        any = true;
    }
    any
}

async fn admit(
    conn: &Connection,
    remote: EndpointId,
    initial_mds: Option<usize>,
    shared: &Arc<Shared>,
) -> Result<Admitted, Rejection> {
    let cfg = &shared.config;
    if !cfg.grants.knows_endpoint(&remote) {
        return Err(Rejection::new(RejectReason::UnknownEndpoint, None));
    }
    let deadline = Instant::now() + cfg.admission_timeout;
    let (send, mut recv) = match timeout_at(deadline, conn.accept_bi()).await {
        Ok(Ok(streams)) => streams,
        Ok(Err(_)) => return Err(Rejection::new(RejectReason::Malformed, None)),
        Err(_) => return Err(Rejection::new(RejectReason::Timeout, None)),
    };
    let request = match read_request(&mut recv, deadline).await {
        Ok(r) => r,
        Err(reason) => return Err(Rejection::new(reason, Some(send))),
    };
    let (principal, grant) = match cfg.grants.authorize(remote, &request.token, &request.vpc) {
        Ok(v) => v,
        Err(reason) => return Err(Rejection::new(reason, Some(send))),
    };
    let key = (principal.clone(), grant.vpc.clone());
    if !shared.live.lock().expect("poisoned").insert(key.clone()) {
        return Err(Rejection::new(RejectReason::SessionExists, Some(send)));
    }
    let reservation = Reservation {
        shared: shared.clone(),
        key,
    };
    let mds = match wait_for_datagram_size(conn, cfg.mtu_wait).await {
        Ok(mds) => mds,
        Err(reason) => return Err(Rejection::new(reason, Some(send))),
    };
    let mtu = cfg
        .max_session_mtu
        .min(u16::try_from(mds - wire::DGRAM_PREFIX_LEN).unwrap_or(u16::MAX));
    let info = SessionInfo {
        id: SessionId(shared.next_id.fetch_add(1, Ordering::Relaxed)),
        principal: principal.clone(),
        vpc: grant.vpc.clone(),
        remote,
        addresses: grant.addresses.clone(),
        mtu,
    };
    let accept_frame = AdmitAccept {
        mtu,
        addresses: grant.addresses.iter().map(|p| (p.addr, p.len)).collect(),
        routes: grant.routes.iter().map(|p| (p.addr, p.len)).collect(),
    }
    .encode_frame();
    let (to_client_tx, to_client) = mpsc::channel(cfg.to_client_queue);
    let backend = match shared.backend.open_session(&info, to_client_tx) {
        Ok(b) => b,
        Err(err) => {
            warn!(%err, "backend refused admitted session");
            return Err(Rejection::new(RejectReason::BackendUnavailable, Some(send)));
        }
    };
    shared.emit(AdmissionEvent::Admitted {
        session: info.id,
        remote,
        principal,
        vpc: grant.vpc.clone(),
        mtu,
        initial_max_datagram_size: initial_mds,
        max_datagram_size: mds,
        relay_only: relay_only(conn),
    });
    Ok(Admitted {
        info,
        routes: grant.routes,
        send,
        recv,
        accept_frame,
        backend,
        to_client,
        _reservation: reservation,
    })
}

async fn reject(conn: Connection, rejection: Rejection, linger: Duration) {
    let code = rejection.reason.code();
    if let Some(mut send) = rejection.send {
        let _ = timeout(linger, async {
            if send.write_all(&wire::encode_reject(code)).await.is_ok() {
                let _ = send.finish();
                // Let the client read the frame and close first.
                conn.closed().await;
            }
        })
        .await;
    }
    conn.close(VarInt::from(u32::from(code)), b"rejected");
}

/// Checks a client datagram and returns the IPv6 packet inside it.
fn inbound_packet(dgram: &Bytes, info: &SessionInfo, routes: &[Ipv6Prefix]) -> Option<Bytes> {
    let pkt = dgram.get(wire::DGRAM_PREFIX_LEN..)?;
    if dgram[0] != wire::DGRAM_IPV6 {
        return None;
    }
    let (src, dst) = ipv6_header(pkt, info.mtu)?;
    if !info.addresses.iter().any(|p| p.contains(src)) || !routes.iter().any(|p| p.contains(dst)) {
        return None;
    }
    Some(dgram.slice(wire::DGRAM_PREFIX_LEN..))
}

/// Validates the fixed IPv6 header and returns its addresses.
fn ipv6_header(pkt: &[u8], mtu: u16) -> Option<(std::net::Ipv6Addr, std::net::Ipv6Addr)> {
    if pkt.len() < 40 || pkt.len() > usize::from(mtu) || pkt[0] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    if payload_len + 40 != pkt.len() {
        return None;
    }
    let src = <[u8; 16]>::try_from(&pkt[8..24]).ok()?.into();
    let dst = <[u8; 16]>::try_from(&pkt[24..40]).ok()?.into();
    Some((src, dst))
}

async fn run_session(conn: Connection, admitted: Admitted, shared: Arc<Shared>) {
    let Admitted {
        info,
        routes,
        mut send,
        mut recv,
        accept_frame,
        mut backend,
        mut to_client,
        _reservation,
    } = admitted;
    let mut close = (wire::CLOSE_NORMAL, &b"session ended"[..]);
    if send.write_all(&accept_frame).await.is_ok() {
        info!(session = %info.id, principal = %info.principal, vpc = %info.vpc, "packet session admitted");
        let mut ctl = [0u8; 64];
        loop {
            tokio::select! {
                dgram = conn.read_datagram() => match dgram {
                    Ok(d) => {
                        if let Some(pkt) = inbound_packet(&d, &info, &routes) {
                            backend.deliver(pkt);
                        }
                    }
                    Err(_) => break,
                },
                pkt = to_client.recv() => match pkt {
                    Some(pkt) => {
                        if let Some((_, dst)) = ipv6_header(&pkt, info.mtu)
                            && info.addresses.iter().any(|p| p.contains(dst))
                        {
                            // A path change can shrink the datagram size below
                            // what the session was admitted with; end the
                            // session rather than drop its packets unseen.
                            if conn.max_datagram_size().is_none_or(|m| m < REQUIRED_DATAGRAM_SIZE) {
                                close = (
                                    u32::from(RejectReason::PathMtuTooSmall.code()),
                                    b"path no longer carries the session MTU",
                                );
                                break;
                            }
                            let mut d = BytesMut::with_capacity(wire::DGRAM_PREFIX_LEN + pkt.len());
                            d.put_u8(wire::DGRAM_IPV6);
                            d.put_slice(&pkt);
                            if let Err(err) = conn.send_datagram(d.freeze()) {
                                debug!(%err, session = %info.id, "dropping packet to client");
                            }
                        }
                    }
                    None => break,
                },
                r = recv.read(&mut ctl) => {
                    if let Ok(Some(_)) = r {
                        close = (u32::from(wire::REJECT_MALFORMED), b"unexpected control data");
                    }
                    break;
                }
            }
        }
    }
    drop(backend);
    info!(session = %info.id, "packet session released");
    shared.emit(AdmissionEvent::Released { session: info.id });
    conn.close(VarInt::from(close.0), close.1);
}
