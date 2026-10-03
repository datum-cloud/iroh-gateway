//! Bounded, per-source CONNECT-UDP forwarding to one operator-selected service.
use std::{
    collections::HashMap,
    fmt::Write,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use connect_transport::{DestinationId, MAX_DATAGRAM_PAYLOAD, Transport};
use iroh::EndpointAddr;
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    task::{Id, JoinSet},
    time::{Instant, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug)]
pub(super) struct UdpOptions {
    pub max_associations: usize,
    pub idle_timeout: Duration,
    pub queue_capacity: usize,
}

impl Default for UdpOptions {
    fn default() -> Self {
        Self {
            max_associations: 128,
            idle_timeout: Duration::from_secs(60),
            queue_capacity: 32,
        }
    }
}

#[derive(Default)]
pub(super) struct UdpMetrics {
    active: AtomicU64,
    opened: AtomicU64,
    attempts: AtomicU64,
    closed: [AtomicU64; 7],
    sent_packets: AtomicU64,
    sent_bytes: AtomicU64,
    received_packets: AtomicU64,
    received_bytes: AtomicU64,
    dropped: [AtomicU64; 3],
    connection_errors: AtomicU64,
    sequence: AtomicU64,
}

impl UdpMetrics {
    pub(super) fn render(&self) -> String {
        let mut out = String::new();
        for (name, kind, value) in [
            ("active_associations", "gauge", &self.active),
            ("associations_opened_total", "counter", &self.opened),
            ("connection_attempts_total", "counter", &self.attempts),
            ("packets_sent_total", "counter", &self.sent_packets),
            ("bytes_sent_total", "counter", &self.sent_bytes),
            ("packets_received_total", "counter", &self.received_packets),
            ("bytes_received_total", "counter", &self.received_bytes),
            (
                "connection_errors_total",
                "counter",
                &self.connection_errors,
            ),
        ] {
            let _ = writeln!(
                out,
                "# TYPE iroh_gateway_udp_{name} {kind}\niroh_gateway_udp_{name} {}",
                value.load(Ordering::Relaxed)
            );
        }
        out.push_str("# TYPE iroh_gateway_udp_associations_closed_total counter\n");
        for reason in Close::ALL {
            let _ = writeln!(
                out,
                "iroh_gateway_udp_associations_closed_total{{reason=\"{}\"}} {}",
                reason.label(),
                self.closed[reason as usize].load(Ordering::Relaxed)
            );
        }
        out.push_str("# TYPE iroh_gateway_udp_dropped_total counter\n");
        for (index, reason) in ["queue_full", "association_limit", "oversize"]
            .iter()
            .enumerate()
        {
            let _ = writeln!(
                out,
                "iroh_gateway_udp_dropped_total{{reason=\"{reason}\"}} {}",
                self.dropped[index].load(Ordering::Relaxed)
            );
        }
        out
    }

    fn drop_packet(&self, reason: usize) {
        self.dropped[reason].fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            reason = ["queue_full", "association_limit", "oversize"][reason],
            "gateway UDP packet dropped"
        );
    }
}

#[derive(Clone, Copy)]
enum Close {
    Idle,
    Cancelled,
    PeerClosed,
    ConnectError,
    SendError,
    SocketError,
    TaskFailure,
}
impl Close {
    const ALL: [Self; 7] = [
        Self::Idle,
        Self::Cancelled,
        Self::PeerClosed,
        Self::ConnectError,
        Self::SendError,
        Self::SocketError,
        Self::TaskFailure,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Cancelled => "cancelled",
            Self::PeerClosed => "peer_closed",
            Self::ConnectError => "connect_error",
            Self::SendError => "send_error",
            Self::SocketError => "socket_error",
            Self::TaskFailure => "task_failure",
        }
    }
}

struct Association {
    session: u64,
    task: Id,
    queue: mpsc::Sender<Vec<u8>>,
}

struct AssociationGuard {
    metrics: Arc<UdpMetrics>,
    session: u64,
    reason: Close,
}
impl Drop for AssociationGuard {
    fn drop(&mut self) {
        self.metrics.active.fetch_sub(1, Ordering::Relaxed);
        self.metrics.closed[self.reason as usize].fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            session_id = self.session,
            reason = self.reason.label(),
            "gateway UDP association closed"
        );
    }
}

pub(super) async fn serve(
    socket: UdpSocket,
    transport: Transport,
    peer: EndpointAddr,
    target_port: u16,
    options: UdpOptions,
    metrics: Arc<UdpMetrics>,
    cancel: CancellationToken,
) -> io::Result<()> {
    if target_port == 0
        || options.max_associations == 0
        || options.queue_capacity == 0
        || options.idle_timeout.is_zero()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP port, association limit, queue capacity, and idle timeout must be positive",
        ));
    }
    let socket = Arc::new(socket);
    let worker_cancel = cancel.child_token();
    let _cancel_guard = worker_cancel.clone().drop_guard();
    let mut associations: HashMap<SocketAddr, Association> = HashMap::new();
    let mut tasks = JoinSet::new();
    // UDP payload length cannot exceed this buffer; oversized input is discarded,
    // never truncated into a seemingly valid datagram.
    let mut buffer = vec![0; 65536];
    let result = loop {
        tokio::select! {
            biased;
            _ = worker_cancel.cancelled() => break Ok(()),
            done = tasks.join_next_with_id(), if !tasks.is_empty() => {
                match done {
                    Some(Ok((_, (source, session)))) => { if associations.get(&source).is_some_and(|entry| entry.session == session) { associations.remove(&source); } }
                    Some(Err(error)) => { associations.retain(|_, entry| entry.task != error.id()); tracing::warn!(stage="udp_task", "gateway UDP association task failed"); }
                    None => {}
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let (length, source) = match received { Ok(value) => value, Err(error) => break Err(error) };
                if length > MAX_DATAGRAM_PAYLOAD { metrics.drop_packet(2); continue; }
                if associations.get(&source).is_some_and(|entry| entry.queue.is_closed()) { associations.remove(&source); }
                if !associations.contains_key(&source) {
                    if associations.len() >= options.max_associations { metrics.drop_packet(1); continue; }
                    let session = metrics.sequence.fetch_add(1, Ordering::Relaxed) + 1;
                    let (queue, receiver) = mpsc::channel(options.queue_capacity);
                    metrics.active.fetch_add(1, Ordering::Relaxed);
                    let guard = AssociationGuard { metrics: metrics.clone(), session, reason: Close::TaskFailure };
                    let task = tasks.spawn(association(socket.clone(), source, transport.clone(), peer.clone(), target_port, options.idle_timeout, receiver, worker_cancel.child_token(), guard));
                    associations.insert(source, Association { session, task: task.id(), queue });
                }
                if let Some(entry) = associations.get(&source) {
                    match entry.queue.try_send(buffer[..length].to_vec()) {
                        Ok(()) => {},
                        Err(mpsc::error::TrySendError::Full(_)) => metrics.drop_packet(0),
                        Err(mpsc::error::TrySendError::Closed(_)) => { associations.remove(&source); }
                    }
                }
            }
        }
    };
    worker_cancel.cancel();
    associations.clear();
    // Cooperative cancellation interrupts connect, queue backpressure, receive,
    // and local sends. The JoinSet owns every association until it finishes.
    while tasks.join_next().await.is_some() {}
    result
}

#[allow(clippy::too_many_arguments)]
async fn association(
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    transport: Transport,
    peer: EndpointAddr,
    port: u16,
    idle: Duration,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
    mut guard: AssociationGuard,
) -> (SocketAddr, u64) {
    let _cancel_guard = cancel.clone().drop_guard();
    let session = guard.session;
    guard.metrics.attempts.fetch_add(1, Ordering::Relaxed);
    let tunnel = tokio::select! {
        _ = cancel.cancelled() => { guard.reason = Close::Cancelled; return (source, session); }
        result = timeout(Duration::from_secs(30), transport.connect_udp(peer.clone(), DestinationId::udp(port), cancel.clone())) => match result {
            Ok(Ok(tunnel)) => tunnel,
            failed => {
                guard.reason = Close::ConnectError;
                guard.metrics.connection_errors.fetch_add(1, Ordering::Relaxed);
                let category = match failed { Ok(Err(ref error)) => error_kind(error), _ => "timeout" };
                tracing::warn!(session_id=session, peer=%peer.id, port, error_kind=category, stage="udp_connect", "gateway UDP association failed");
                return (source, session);
            }
        }
    };
    guard.metrics.opened.fetch_add(1, Ordering::Relaxed);
    let path = transport.peer_diagnostics(peer.id);
    tracing::info!(session_id=session, peer=%peer.id, port, path=?path.as_ref().map(|value| value.path), rtt_us=path.and_then(|value| value.latency).map(|value| value.as_micros() as u64), "gateway UDP association established");
    let mut deadline = Instant::now() + idle;
    guard.reason = loop {
        tokio::select! {
            _ = cancel.cancelled() => break Close::Cancelled,
            _ = sleep_until(deadline) => break Close::Idle,
            packet = outgoing.recv() => {
                let Some(packet) = packet else { break Close::Cancelled; };
                let length = packet.len();
                let result = tokio::select! {
                    _ = cancel.cancelled() => break Close::Cancelled,
                    _ = sleep_until(deadline) => break Close::Idle,
                    result = tunnel.send(packet) => result,
                };
                match result {
                    Ok(()) => { guard.metrics.sent_packets.fetch_add(1, Ordering::Relaxed); guard.metrics.sent_bytes.fetch_add(length as u64, Ordering::Relaxed); deadline = Instant::now() + idle; }
                    Err(connect_transport::Error::DatagramTooLarge) => guard.metrics.drop_packet(2),
                    Err(error) => { tracing::warn!(session_id=session, error_kind=error_kind(&error), stage="udp_send", "gateway UDP association failed"); break Close::SendError; }
                }
            }
            packet = tunnel.recv() => {
                let Some(packet) = packet else { break Close::PeerClosed; };
                if packet.len() > MAX_DATAGRAM_PAYLOAD { guard.metrics.drop_packet(2); continue; }
                let result = tokio::select! {
                    _ = cancel.cancelled() => break Close::Cancelled,
                    _ = sleep_until(deadline) => break Close::Idle,
                    result = socket.send_to(&packet, source) => result,
                };
                match result {
                    Ok(length) => { guard.metrics.received_packets.fetch_add(1, Ordering::Relaxed); guard.metrics.received_bytes.fetch_add(length as u64, Ordering::Relaxed); deadline = Instant::now() + idle; }
                    Err(_) => break Close::SocketError,
                }
            }
        }
    };
    (source, session)
}

fn error_kind(error: &connect_transport::Error) -> &'static str {
    match error {
        connect_transport::Error::Rejected(status) if status.as_u16() == 403 => "access_denied",
        connect_transport::Error::Rejected(status) if status.as_u16() == 404 => {
            "destination_not_advertised"
        }
        connect_transport::Error::Timeout => "timeout",
        connect_transport::Error::Closed => "closed",
        connect_transport::Error::DatagramTooLarge => "oversize",
        connect_transport::Error::Io(_) => "io",
        _ => "protocol",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use connect_transport::{Access, DestinationPolicy, Policy, Target, TransportConfig};
    use iroh::SecretKey;

    struct Fixture {
        remote: Transport,
        gateway: Transport,
        origin: SocketAddr,
        address: SocketAddr,
        metrics: Arc<UdpMetrics>,
        cancel: CancellationToken,
        worker: tokio::task::JoinHandle<io::Result<()>>,
        echo: tokio::task::JoinHandle<()>,
    }

    impl Fixture {
        async fn new(options: UdpOptions) -> Self {
            let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let origin_addr = origin.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let mut data = vec![0; 65536];
                loop {
                    let (length, source) = origin.recv_from(&mut data).await.unwrap();
                    origin.send_to(&data[..length], source).await.unwrap();
                }
            });
            let remote = Transport::bind(
                TransportConfig::new(SecretKey::from_bytes(&[71; 32]))
                    .bind_addr("127.0.0.1:0".parse().unwrap()),
            )
            .await
            .unwrap();
            let gateway = Transport::bind(
                TransportConfig::new(SecretKey::from_bytes(&[72; 32]))
                    .bind_addr("127.0.0.1:0".parse().unwrap()),
            )
            .await
            .unwrap();
            let mut peer = EndpointAddr::new(remote.endpoint_id());
            for address in remote.connection_details().direct_addresses {
                peer = peer.with_ip_addr(address);
            }
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();
            let metrics = Arc::new(UdpMetrics::default());
            let cancel = CancellationToken::new();
            let worker = tokio::spawn(serve(
                socket,
                gateway.clone(),
                peer,
                9000,
                options,
                metrics.clone(),
                cancel.clone(),
            ));
            let fixture = Self {
                remote,
                gateway,
                origin: origin_addr,
                address,
                metrics,
                cancel,
                worker,
                echo,
            };
            fixture.authorize(true).await;
            fixture
        }
        async fn authorize(&self, allowed: bool) {
            let mut policy = Policy::default();
            policy.destinations.insert(
                DestinationId::udp(9000),
                DestinationPolicy {
                    target: Target::Udp(self.origin),
                    access: Access::Peers(if allowed {
                        [self.gateway.endpoint_id()].into()
                    } else {
                        Default::default()
                    }),
                },
            );
            self.remote.replace_policy(policy).await.unwrap();
        }
        async fn client(&self) -> UdpSocket {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.connect(self.address).await.unwrap();
            client
        }
        async fn close(self) {
            self.cancel.cancel();
            timeout(Duration::from_secs(3), self.worker)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(self.metrics.active.load(Ordering::Relaxed), 0);
            self.echo.abort();
            self.gateway.shutdown().await;
            self.remote.shutdown().await;
        }
    }

    async fn echo(client: &UdpSocket, packet: &[u8]) {
        client.send(packet).await.unwrap();
        let mut response = [0; 2048];
        let size = timeout(Duration::from_secs(10), client.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..size], packet);
    }

    async fn wait_for(mut ready: impl FnMut() -> bool) {
        timeout(Duration::from_secs(8), async {
            while !ready() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn defaults_and_metrics_are_bounded_and_payload_free() {
        let options = UdpOptions::default();
        assert_eq!(options.max_associations, 128);
        assert_eq!(options.queue_capacity, 32);
        assert_eq!(options.idle_timeout, Duration::from_secs(60));
        let output = UdpMetrics::default().render();
        assert!(output.contains("iroh_gateway_udp_active_associations 0"));
        assert!(output.contains("iroh_gateway_udp_dropped_total{reason=\"oversize\"} 0"));
    }

    #[tokio::test]
    async fn real_udp_sources_are_isolated_bounded_expire_and_cancel() {
        let fixture = Fixture::new(UdpOptions {
            max_associations: 2,
            idle_timeout: Duration::from_secs(2),
            queue_capacity: 2,
        })
        .await;
        let first = fixture.client().await;
        let second = fixture.client().await;
        let third = fixture.client().await;
        // Concurrent ingress uses independent CONNECT-UDP associations.
        tokio::join!(
            echo(&first, b"first-source"),
            echo(&second, b"second-source")
        );
        echo(&first, b"").await;
        assert_eq!(fixture.metrics.active.load(Ordering::Relaxed), 2);
        third.send(b"over-cap").await.unwrap();
        wait_for(|| fixture.metrics.dropped[1].load(Ordering::Relaxed) > 0).await;
        first
            .send(&vec![0; MAX_DATAGRAM_PAYLOAD + 1])
            .await
            .unwrap();
        wait_for(|| fixture.metrics.dropped[2].load(Ordering::Relaxed) > 0).await;
        echo(&first, b"still-healthy").await;
        assert_eq!(
            fixture.metrics.opened.load(Ordering::Relaxed),
            2,
            "oversize must not replace the association"
        );
        wait_for(|| fixture.metrics.active.load(Ordering::Relaxed) == 0).await;
        assert_eq!(
            fixture.metrics.closed[Close::Idle as usize].load(Ordering::Relaxed),
            2
        );
        echo(&third, b"capacity-recovered").await;
        assert!(fixture.metrics.sent_bytes.load(Ordering::Relaxed) > 0);
        assert!(fixture.metrics.received_bytes.load(Ordering::Relaxed) > 0);
        fixture.close().await;
    }

    #[tokio::test]
    async fn rejected_and_revoked_associations_are_evicted() {
        let fixture = Fixture::new(UdpOptions::default()).await;
        fixture.authorize(false).await;
        let client = fixture.client().await;
        client.send(b"denied").await.unwrap();
        wait_for(|| {
            fixture.metrics.connection_errors.load(Ordering::Relaxed) > 0
                && fixture.metrics.active.load(Ordering::Relaxed) == 0
        })
        .await;
        fixture.authorize(true).await;
        echo(&client, b"authorized-later").await;
        fixture.authorize(false).await;
        wait_for(|| fixture.metrics.active.load(Ordering::Relaxed) == 0).await;
        assert!(fixture.metrics.closed[Close::PeerClosed as usize].load(Ordering::Relaxed) > 0);
        client.send(b"still-denied").await.unwrap();
        wait_for(|| fixture.metrics.connection_errors.load(Ordering::Relaxed) >= 2).await;
        fixture.close().await;
    }

    #[tokio::test]
    async fn unpublished_port_is_denied_without_stale_association() {
        let fixture = Fixture::new(UdpOptions::default()).await;
        fixture
            .remote
            .replace_policy(Policy::default())
            .await
            .unwrap();
        let client = fixture.client().await;
        client.send(b"unpublished").await.unwrap();
        wait_for(|| {
            fixture.metrics.connection_errors.load(Ordering::Relaxed) == 1
                && fixture.metrics.active.load(Ordering::Relaxed) == 0
        })
        .await;
        fixture.close().await;
    }
}
