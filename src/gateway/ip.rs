//! Static, explicitly approved CONNECT-IP grants and Linux packet injection.
//! This prototype never enables host forwarding, installs default routes, or
//! trusts a peer-supplied route/address assignment.
use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::process::Command;

use connect_ip_adapter::{IpNet, Tun};
use connect_transport::ip::{self, Grant, Incoming};
use iroh::{Endpoint, EndpointId};
use serde::Deserialize;
use tokio::{io::AsyncReadExt, sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info_span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IpConfig {
    pub grants: Vec<IpGrant>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IpGrant {
    pub network: String,
    pub peer: EndpointId,
    pub client_address: IpNet,
    pub gateway_address: IpNet,
    pub routes: Vec<IpNet>,
    #[serde(default)]
    pub peer_routes: Vec<IpNet>,
    pub interface_name: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

impl IpGrant {
    fn advertised_routes(&self) -> impl Iterator<Item = &IpNet> {
        self.routes.iter().chain(&self.peer_routes)
    }

    fn advertises(&self, address: IpAddr) -> bool {
        self.advertised_routes()
            .any(|route| route.contains(&address))
    }
}
fn default_mtu() -> u16 {
    1280
}

impl IpConfig {
    pub(crate) fn validate_relay_only(&self) -> io::Result<()> {
        if self
            .grants
            .iter()
            .flat_map(|grant| &grant.routes)
            .any(|route| {
                (route.addr().is_ipv4() && route.prefix_len() < 2)
                    || (route.addr().is_ipv6() && route.prefix_len() < 2)
            })
        {
            return Err(invalid(
                "relay-only CONNECT-IP gateways cannot advertise default or near-default routes",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_underlay(&self, underlay: IpAddr) -> io::Result<()> {
        if self.grants.iter().any(|grant| {
            underlay == grant.client_address.addr()
                || underlay == grant.gateway_address.addr()
                || grant.routes.iter().any(|route| route.contains(&underlay))
        }) {
            return Err(invalid(
                "CONNECT-IP underlay bind must not overlap any grant's advertised routes or assigned client/gateway addresses",
            ));
        }
        Ok(())
    }

    pub(crate) async fn load(path: &Path) -> io::Result<Self> {
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options.open(path).await?;
        let metadata = file.metadata().await?;
        if !metadata.is_file() || metadata.len() > 1024 * 1024 {
            return Err(invalid(
                "IP grants must be a regular JSON file no larger than 1 MiB",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o022 != 0
                || (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() })
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "IP grants must be owned by root or the current user and not group/world writable",
                ));
            }
        }
        let mut contents = Vec::new();
        file.take(1024 * 1024 + 1)
            .read_to_end(&mut contents)
            .await?;
        if contents.len() > 1024 * 1024 {
            return Err(invalid("IP grant file exceeds 1 MiB"));
        }
        let config: Self = serde_json::from_slice(&contents)
            .map_err(|_| invalid("IP grant file is not valid strict JSON"))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> io::Result<()> {
        if self.grants.len() > 64 {
            return Err(invalid("IP grants cannot contain more than 64 entries"));
        }
        let (mut identities, mut interfaces, mut addresses) =
            (HashSet::new(), HashSet::new(), HashSet::new());
        let available_clients: HashSet<_> = self
            .grants
            .iter()
            .map(|grant| (grant.network.clone(), grant.client_address.addr()))
            .collect();
        for grant in &self.grants {
            let advertised: Vec<_> = grant.advertised_routes().cloned().collect();
            if grant.client_address.addr().is_ipv4() != grant.gateway_address.addr().is_ipv4()
                || advertised
                    .iter()
                    .any(|route| route.addr().is_ipv4() != grant.client_address.addr().is_ipv4())
            {
                return Err(invalid(
                    "each IP grant must use one address family for client, gateway, and routes",
                ));
            }
            if advertised.len() > 32 {
                return Err(invalid(
                    "IP grants cannot advertise more than 32 VPC and peer routes",
                ));
            }
            if grant.network.is_empty()
                || grant.network.len() > 63
                || !grant
                    .network
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(invalid("invalid IP network name"));
            }
            connect_ip_adapter::validate(
                &grant.interface_name,
                grant.gateway_address,
                grant.mtu,
                &advertised,
            )?;
            connect_ip_adapter::validate(
                &grant.interface_name,
                grant.client_address,
                grant.mtu,
                &[],
            )?;
            if grant.routes.is_empty()
                || advertised
                    .iter()
                    .any(|route| route.contains(&grant.client_address.addr()))
            {
                return Err(invalid(
                    "IP routes must be nonempty and cannot include the assigned client address",
                ));
            }
            for (index, route) in advertised.iter().enumerate() {
                if advertised[..index].iter().any(|other| {
                    route.contains(&other.network()) || other.contains(&route.network())
                }) {
                    return Err(invalid("overlapping IP routes are unsupported"));
                }
            }
            for route in &grant.peer_routes {
                let host_prefix = if route.addr().is_ipv4() { 32 } else { 128 };
                if route.prefix_len() != host_prefix
                    || !available_clients.contains(&(grant.network.clone(), route.addr()))
                {
                    return Err(invalid(
                        "peer routes must be host routes for another grant on the same network",
                    ));
                }
            }
            if !identities.insert((grant.peer, grant.network.clone()))
                || !interfaces.insert(grant.interface_name.clone())
                || !addresses.insert(grant.client_address.addr())
                || !addresses.insert(grant.gateway_address.addr())
            {
                return Err(invalid(
                    "IP grants must use unique peer/network pairs, interface names, and assigned addresses",
                ));
            }
        }
        Ok(())
    }

    fn protocol_grants(&self) -> io::Result<Vec<Grant>> {
        self.grants
            .iter()
            .map(|grant| {
                Ok(Grant {
                    peer: grant.peer,
                    network: grant.network.clone(),
                    address: grant.client_address.addr(),
                    routes: grant
                        .advertised_routes()
                        .map(|route| route.to_string().parse().map_err(io::Error::other))
                        .collect::<io::Result<_>>()?,
                    mtu: grant.mtu,
                })
            })
            .collect()
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

struct ActivePeer {
    generation: u64,
    sender: mpsc::Sender<Vec<u8>>,
}

struct PeerRouter {
    allowed: HashMap<IpAddr, HashSet<IpAddr>>,
    active: Arc<Mutex<HashMap<IpAddr, ActivePeer>>>,
    generation: AtomicU64,
}

impl PeerRouter {
    fn new(config: &IpConfig) -> Self {
        let allowed = config
            .grants
            .iter()
            .map(|grant| {
                (
                    grant.client_address.addr(),
                    grant.peer_routes.iter().map(IpNet::addr).collect(),
                )
            })
            .collect();
        Self {
            allowed,
            active: Arc::new(Mutex::new(HashMap::new())),
            generation: AtomicU64::new(1),
        }
    }

    fn register(&self, address: IpAddr) -> (PeerRegistration, mpsc::Receiver<Vec<u8>>) {
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(64);
        self.active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(address, ActivePeer { generation, sender });
        (
            PeerRegistration {
                active: self.active.clone(),
                address,
                generation,
            },
            receiver,
        )
    }

    fn is_peer_route(&self, source: IpAddr, destination: IpAddr) -> bool {
        self.allowed
            .get(&source)
            .is_some_and(|destinations| destinations.contains(&destination))
    }

    fn forward(&self, source: IpAddr, destination: IpAddr, packet: &[u8]) -> bool {
        if !self.is_peer_route(source, destination) {
            return false;
        }
        let sender = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&destination)
            .map(|entry| entry.sender.clone());
        let Some(sender) = sender else {
            return false;
        };
        // A slow peer must not stall another Connector's session. The bounded
        // queue deliberately drops when the destination cannot keep up.
        sender.try_send(packet.to_vec()).is_ok()
    }
}

struct PeerRegistration {
    active: Arc<Mutex<HashMap<IpAddr, ActivePeer>>>,
    address: IpAddr,
    generation: u64,
}

impl Drop for PeerRegistration {
    fn drop(&mut self) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if active
            .get(&self.address)
            .is_some_and(|entry| entry.generation == self.generation)
        {
            active.remove(&self.address);
        }
    }
}

#[derive(Default)]
pub(super) struct IpMetrics {
    active: AtomicU64,
    opened: AtomicU64,
    errors: AtomicU64,
    protocol_errors: AtomicU64,
    dropped: AtomicU64,
    injected_packets: AtomicU64,
    injected_bytes: AtomicU64,
    returned_packets: AtomicU64,
    returned_bytes: AtomicU64,
    datagrams_sent: AtomicU64,
    datagrams_received: AtomicU64,
    mtu_errors: AtomicU64,
    // Interface names are unique for active grants. Keep a minimum across all
    // sessions instead of exposing whichever session happened to update last.
    capacities: Mutex<HashMap<String, usize>>,
}
struct ActiveSession(Arc<IpMetrics>, String);
impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
        self.0
            .capacities
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.1);
    }
}
impl IpMetrics {
    fn record_protocol_delta(&self, previous: &mut ip::Stats, current: ip::Stats) {
        self.dropped.fetch_add(
            current
                .packets_dropped
                .saturating_sub(previous.packets_dropped),
            Ordering::Relaxed,
        );
        self.protocol_errors.fetch_add(
            current
                .protocol_errors
                .saturating_sub(previous.protocol_errors),
            Ordering::Relaxed,
        );
        for (counter, now, before) in [
            (
                &self.datagrams_sent,
                current.datagrams_sent,
                previous.datagrams_sent,
            ),
            (
                &self.datagrams_received,
                current.datagrams_received,
                previous.datagrams_received,
            ),
            (&self.mtu_errors, current.mtu_errors, previous.mtu_errors),
        ] {
            counter.fetch_add(now.saturating_sub(before), Ordering::Relaxed);
        }
        *previous = current;
    }

    fn record_capacity(&self, interface: &str, capacity: usize) {
        self.capacities
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(interface.to_owned(), capacity);
    }

    pub(super) fn render(&self) -> String {
        let mut output = String::new();
        for (name, kind, value) in [
            ("active_sessions", "gauge", &self.active),
            ("sessions_opened_total", "counter", &self.opened),
            ("errors_total", "counter", &self.errors),
            ("protocol_errors_total", "counter", &self.protocol_errors),
            ("packets_dropped_total", "counter", &self.dropped),
            ("packets_injected_total", "counter", &self.injected_packets),
            ("bytes_injected_total", "counter", &self.injected_bytes),
            ("packets_returned_total", "counter", &self.returned_packets),
            ("bytes_returned_total", "counter", &self.returned_bytes),
            ("datagrams_sent_total", "counter", &self.datagrams_sent),
            (
                "datagrams_received_total",
                "counter",
                &self.datagrams_received,
            ),
            ("mtu_errors_total", "counter", &self.mtu_errors),
        ] {
            let _ = writeln!(
                output,
                "# TYPE iroh_gateway_ip_{name} {kind}\niroh_gateway_ip_{name} {}",
                value.load(Ordering::Relaxed)
            );
        }
        let capacity = self
            .capacities
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .copied()
            .min()
            .unwrap_or(0);
        let _ = writeln!(
            output,
            "# HELP iroh_gateway_ip_effective_datagram_ip_capacity_min Minimum usable IP datagram bytes across active sessions; zero when no sessions are active.\n# TYPE iroh_gateway_ip_effective_datagram_ip_capacity_min gauge\niroh_gateway_ip_effective_datagram_ip_capacity_min {capacity}"
        );
        output
    }
}

// Keep transport-rejected packets visible even though they never reach the TUN
// loop. A final delta is collected on ordinary exit, cancellation, and unwind.
struct ProtocolMetrics<'a> {
    session: &'a ip::IpSession,
    metrics: &'a IpMetrics,
    observed: ip::Stats,
    interface: &'a str,
}
impl ProtocolMetrics<'_> {
    fn flush(&mut self) {
        let current = self.session.stats();
        self.metrics
            .record_capacity(self.interface, current.effective_datagram_ip_capacity);
        self.metrics
            .record_protocol_delta(&mut self.observed, current);
    }
}
impl Drop for ProtocolMetrics<'_> {
    fn drop(&mut self) {
        self.flush();
    }
}

pub(super) async fn serve(
    endpoint: Endpoint,
    config: IpConfig,
    metrics: Arc<IpMetrics>,
    cancel: CancellationToken,
) -> io::Result<()> {
    config.validate()?;
    if !cfg!(target_os = "linux") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "CONNECT-IP gateway requires Linux TUN support",
        ));
    }
    let owned_cancel = cancel.child_token();
    let _guard = owned_cancel.clone().drop_guard();
    let (sender, mut incoming) = mpsc::channel::<Incoming>(64);
    let protocol = ip::serve(
        endpoint,
        config.protocol_grants()?,
        sender,
        owned_cancel.clone(),
    );
    tokio::pin!(protocol);
    let peer_router = Arc::new(PeerRouter::new(&config));
    let mut active = HashSet::new();
    let mut sessions = JoinSet::new();
    let result = loop {
        tokio::select! {
            _ = owned_cancel.cancelled() => break Ok(()),
            result = &mut protocol => break result.map_err(io::Error::other),
            done = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Ok(name)) = done { active.remove(&name); }
                // A panicking session is not reused. The exclusive interface FD
                // still drops; keeping its slot denied is the fail-closed choice.
            }
            next = incoming.recv() => {
                let Some(request) = next else { break Err(io::Error::other("CONNECT-IP receiver stopped")); };
                let grant = config.grants.iter().find(|grant| grant.peer == request.peer && grant.network == request.network);
                let Some(grant) = grant else { request.session.cancel(); let _ = request.ready.send(false); continue; };
                if !active.insert(grant.interface_name.clone()) { request.session.cancel(); let _ = request.ready.send(false); metrics.errors.fetch_add(1, Ordering::Relaxed); continue; }
                sessions.spawn(session(request, grant.clone(), metrics.clone(), peer_router.clone(), owned_cancel.child_token()));
            }
        }
    };
    owned_cancel.cancel();
    while sessions.join_next().await.is_some() {}
    result
}

/// Install narrowly scoped stateful source NAT so VPC workloads can return
/// traffic to an overlay Connector without requiring every VPC router to learn
/// a per-Connector route. The per-session nftables table is removed on close.
struct EgressNat {
    table: String,
    family: &'static str,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct NatCounters {
    packets: u64,
    bytes: u64,
}

impl EgressNat {
    async fn create(grant: &IpGrant, interface: &str) -> io::Result<Self> {
        let table = format!("datum_{}", grant.interface_name);
        let family = if grant.client_address.addr().is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        ensure_ip_forwarding(family).await?;
        nft(&["add", "table", family, &table]).await?;
        let result = async {
            nft(&[
                "add",
                "chain",
                family,
                &table,
                "postrouting",
                "{ type nat hook postrouting priority srcnat; policy accept; }",
            ])
            .await?;
            for route in &grant.routes {
                let rule = nat_rule(
                    &table,
                    family,
                    interface,
                    &grant.client_address.addr().to_string(),
                    &route.to_string(),
                );
                nft(&rule).await?;
            }
            Ok::<(), io::Error>(())
        }
        .await;
        if let Err(error) = result {
            let _ = nft(&["delete", "table", family, &table]).await;
            return Err(error);
        }
        Ok(Self { table, family })
    }

    async fn remove(self) -> io::Result<()> {
        nft(&["delete", "table", self.family, &self.table]).await
    }

    async fn counters(&self) -> io::Result<NatCounters> {
        let output = tokio::time::timeout(
            Duration::from_secs(2),
            Command::new("nft")
                .args(["list", "table", self.family, &self.table])
                .output(),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "nft counter query timed out"))??;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "nft counter query failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        parse_nat_counters(&String::from_utf8_lossy(&output.stdout))
            .ok_or_else(|| io::Error::other("nft output did not contain NAT rule counters"))
    }
}

fn parse_nat_counters(output: &str) -> Option<NatCounters> {
    let mut counters = NatCounters::default();
    let mut found = false;
    for line in output.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let Some(index) = fields.iter().position(|field| *field == "counter") else {
            continue;
        };
        if fields.get(index + 1) != Some(&"packets") || fields.get(index + 3) != Some(&"bytes") {
            continue;
        }
        let packets = fields.get(index + 2)?.parse().ok()?;
        let bytes = fields.get(index + 4)?.parse().ok()?;
        counters.packets = counters.packets.saturating_add(packets);
        counters.bytes = counters.bytes.saturating_add(bytes);
        found = true;
    }
    found.then_some(counters)
}

fn nat_rule(table: &str, family: &str, tun: &str, client: &str, route: &str) -> Vec<String> {
    vec![
        "add".into(),
        "rule".into(),
        family.into(),
        table.into(),
        "postrouting".into(),
        "iifname".into(),
        tun.into(),
        "oifname".into(),
        "eth0".into(),
        family.into(),
        "saddr".into(),
        client.into(),
        family.into(),
        "daddr".into(),
        route.into(),
        "counter".into(),
        "masquerade".into(),
    ]
}

async fn ensure_ip_forwarding(family: &str) -> io::Result<()> {
    let path = match family {
        "ip" => "/proc/sys/net/ipv4/ip_forward",
        "ip6" => "/proc/sys/net/ipv6/conf/all/forwarding",
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported NAT address family",
            ));
        }
    };
    let current = tokio::fs::read_to_string(path).await?;
    if current.trim() != "1" {
        tokio::fs::write(path, "1").await?;
    }
    Ok(())
}

async fn nft(args: &[impl AsRef<std::ffi::OsStr>]) -> io::Result<()> {
    let output = Command::new("nft").args(args).output().await?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "nft {} failed: {}",
        args.iter()
            .map(|arg| arg.as_ref().to_string_lossy())
            .collect::<Vec<_>>()
            .join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

async fn session(
    incoming: Incoming,
    grant: IpGrant,
    metrics: Arc<IpMetrics>,
    peer_router: Arc<PeerRouter>,
    cancel: CancellationToken,
) -> String {
    let span = info_span!(
        "connect_ip.gateway_session",
        peer = %incoming.peer,
        network = %incoming.network,
        session_id = %incoming.session_id
    );
    let _ = span.set_parent(incoming.trace_context.clone());
    session_inner(incoming, grant, metrics, peer_router, cancel)
        .instrument(span)
        .await
}

async fn session_inner(
    incoming: Incoming,
    grant: IpGrant,
    metrics: Arc<IpMetrics>,
    peer_router: Arc<PeerRouter>,
    cancel: CancellationToken,
) -> String {
    let Incoming {
        peer,
        network,
        session_id,
        trace_context: _,
        session,
        ready,
    } = incoming;
    let client_routes = [grant.client_address];
    let tun = tokio::select! {
        _ = cancel.cancelled() => { session.cancel(); let _ = ready.send(false); return grant.interface_name; }
        result = tokio::time::timeout(Duration::from_secs(8), Tun::create(&grant.interface_name, grant.gateway_address, grant.mtu, &client_routes)) => match result {
            Ok(Ok(tun)) => tun,
            failed => {
                let kind = match failed { Ok(Err(error)) => error.kind(), _ => io::ErrorKind::TimedOut };
                metrics.errors.fetch_add(1, Ordering::Relaxed); tracing::warn!(%peer, %network, %session_id, interface=%grant.interface_name, error_kind=?kind, stage="ip_tun_setup", "CONNECT-IP gateway TUN setup failed"); session.cancel(); let _ = ready.send(false); return grant.interface_name;
            }
        }
    };
    let nat = tokio::select! {
        _ = cancel.cancelled() => { session.cancel(); let _ = ready.send(false); return grant.interface_name; }
        result = EgressNat::create(&grant, tun.name()) => match result {
            Ok(nat) => {
                tracing::info!(%peer, %network, %session_id, interface=%tun.name(), client_address=%grant.client_address, routes=?grant.routes, family=%nat.family, stage="ip_nat_ready", "CONNECT-IP VPC return path ready");
                nat
            },
            Err(error) => {
                metrics.errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%peer, %network, %session_id, interface=%tun.name(), %error, stage="ip_nat_setup", "CONNECT-IP VPC return path setup failed");
                session.cancel();
                let _ = ready.send(false);
                return grant.interface_name;
            }
        }
    };
    let (_peer_registration, mut peer_packets) = peer_router.register(grant.client_address.addr());
    if ready.send(true).is_err() {
        session.cancel();
        if let Err(error) = nat.remove().await {
            tracing::warn!(%peer, %network, %session_id, %error, stage="ip_nat_cleanup", "CONNECT-IP VPC return path cleanup failed");
        }
        return grant.interface_name;
    }
    metrics.active.fetch_add(1, Ordering::Relaxed);
    let _active_guard = ActiveSession(metrics.clone(), grant.interface_name.clone());
    metrics.opened.fetch_add(1, Ordering::Relaxed);
    let initial_stats = session.stats();
    tracing::info!(%peer, %network, %session_id, interface=%tun.name(), delivery_mode=initial_stats.delivery_mode,
        configured_mtu=grant.mtu, effective_datagram_ip_capacity=initial_stats.effective_datagram_ip_capacity,
        "CONNECT-IP gateway session ready");
    let session_started = tokio::time::Instant::now();
    let mut protocol_metrics = ProtocolMetrics {
        session: &session,
        metrics: &metrics,
        observed: ip::Stats::default(),
        interface: &grant.interface_name,
    };
    protocol_metrics.flush();
    let mut telemetry_tick = tokio::time::interval(Duration::from_secs(1));
    telemetry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut health_tick = tokio::time::interval(Duration::from_secs(10));
    health_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buffer = vec![0; usize::from(grant.mtu)];
    let mut failure = None;
    let close_reason;
    let (mut packets_to_vpc, mut packets_from_vpc) = (0u64, 0u64);
    let (mut bytes_to_vpc, mut bytes_from_vpc) = (0u64, 0u64);
    let (mut policy_drops_to_vpc, mut policy_drops_from_vpc) = (0u64, 0u64);
    let mut policy_drop_reasons = HashMap::<&'static str, u64>::new();
    let (mut last_to_vpc_at_ms, mut last_from_vpc_at_ms) = (None, None);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => { close_reason = "gateway_shutdown"; break; },
            _ = telemetry_tick.tick() => protocol_metrics.flush(),
            _ = health_tick.tick() => {
                let stats = session.stats();
                let (nat_postrouting_packets, nat_postrouting_bytes, nat_counter_error) =
                    match nat.counters().await {
                        Ok(counters) => (Some(counters.packets), Some(counters.bytes), None),
                        Err(error) => (None, None, Some(error.to_string())),
                    };
                let health_span = tracing::info_span!("connect_ip.health_snapshot", %peer, %network, %session_id);
                health_span.in_scope(|| tracing::info!(%peer, %network, %session_id, interface=%tun.name(),
                    quic_datagrams_received=stats.datagrams_received,
                    quic_datagrams_sent=stats.datagrams_sent,
                    packets_injected_into_vpc=packets_to_vpc,
                    packets_returned_from_vpc=packets_from_vpc,
                    bytes_injected_into_vpc=bytes_to_vpc,
                    bytes_returned_from_vpc=bytes_from_vpc,
                    policy_drops_to_vpc, policy_drops_from_vpc,
                    policy_drop_reasons=?policy_drop_reasons,
                    nat_postrouting_packets, nat_postrouting_bytes,
                    nat_counter_error=?nat_counter_error,
                    protocol_drops=stats.packets_dropped,
                    protocol_errors=stats.protocol_errors,
                    last_packet_injected_at_unix_ms=last_to_vpc_at_ms,
                    last_packet_returned_at_unix_ms=last_from_vpc_at_ms,
                    stage="connect_ip_health", "CONNECT-IP gateway directional health snapshot"));
            },
            packet = session.recv() => {
                let Some(packet) = packet else {
                    failure = session.last_error();
                    close_reason = if failure.is_some() { "transport_error" } else { "peer_closed" };
                    break;
                };
                if let Some(reason) = packet_drop_reason(&packet, &grant, true) {
                    metrics.dropped.fetch_add(1, Ordering::Relaxed);
                    policy_drops_to_vpc += 1;
                    *policy_drop_reasons.entry(reason).or_default() += 1;
                    continue;
                }
                let (_, destination) = packet_addresses(&packet).expect("accepted packet has addresses");
                if peer_router.is_peer_route(grant.client_address.addr(), destination) {
                    if peer_router.forward(grant.client_address.addr(), destination, &packet) {
                        tracing::debug!(%peer, %network, %session_id, %destination, stage="connect_ip_peer_forward", "CONNECT-IP packet forwarded to peer Connector");
                    } else {
                        metrics.dropped.fetch_add(1, Ordering::Relaxed);
                        *policy_drop_reasons.entry("peer_offline").or_default() += 1;
                    }
                    continue;
                }
                let result = tokio::select! { _ = cancel.cancelled() => { close_reason = "gateway_shutdown"; break; }, result = tun.write_packet(&packet) => result };
                if let Err(error) = result { close_reason = "tun_write_failed"; failure = Some(format!("TUN write failed: {}", error.kind())); break; }
                metrics.injected_packets.fetch_add(1, Ordering::Relaxed); metrics.injected_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                packets_to_vpc += 1;
                bytes_to_vpc = bytes_to_vpc.saturating_add(packet.len() as u64);
                last_to_vpc_at_ms = Some(unix_time_ms());
            }
            peer_packet = peer_packets.recv() => {
                let Some(packet) = peer_packet else { close_reason = "peer_router_closed"; break; };
                if let Some(reason) = packet_drop_reason(&packet, &grant, false) {
                    metrics.dropped.fetch_add(1, Ordering::Relaxed);
                    *policy_drop_reasons.entry(reason).or_default() += 1;
                    continue;
                }
                match session.send(packet).await {
                    Ok(()) => {},
                    Err(ip::Error::InvalidPacket | ip::Error::PacketTooLarge | ip::Error::AddressPolicy) => {
                        metrics.dropped.fetch_add(1, Ordering::Relaxed);
                    },
                    Err(error) => { close_reason = "peer_datagram_send_failed"; failure = Some(error.to_string()); break; }
                }
            }
            received = tun.read_packet(&mut buffer) => {
                let length = match received {
                    Ok(0) => { close_reason = "tun_read_eof"; failure = Some("TUN read returned end of file".to_owned()); break; },
                    Err(error) => { close_reason = "tun_read_failed"; failure = Some(format!("TUN read failed: {}", error.kind())); break; },
                    Ok(length) => length
                };
                if let Some(reason) = packet_drop_reason(&buffer[..length], &grant, false) {
                    metrics.dropped.fetch_add(1, Ordering::Relaxed);
                    policy_drops_from_vpc += 1;
                    *policy_drop_reasons.entry(reason).or_default() += 1;
                    continue;
                }
                let result = tokio::select! { _ = cancel.cancelled() => { close_reason = "gateway_shutdown"; break; }, result = session.send(buffer[..length].to_vec()) => result };
                match result {
                    Ok(()) => {
                        metrics.returned_packets.fetch_add(1, Ordering::Relaxed);
                        metrics.returned_bytes.fetch_add(length as u64, Ordering::Relaxed);
                        packets_from_vpc += 1;
                        bytes_from_vpc = bytes_from_vpc.saturating_add(length as u64);
                        last_from_vpc_at_ms = Some(unix_time_ms());
                    }
                    // IpSession::send already counts these drops; the periodic
                    // delta collector records them once in gateway metrics.
                    Err(ip::Error::InvalidPacket | ip::Error::PacketTooLarge | ip::Error::AddressPolicy) => { tracing::debug!(%peer, %network, reason="packet_policy", "CONNECT-IP packet dropped"); }
                    Err(error) => { close_reason = "datagram_send_failed"; failure = Some(error.to_string()); break; }
                }
            }
        }
    }
    session.cancel();
    protocol_metrics.flush();
    if let Err(error) = nat.remove().await {
        tracing::warn!(%peer, %network, %error, stage="ip_nat_cleanup", "CONNECT-IP VPC return path cleanup failed");
    } else {
        tracing::info!(%peer, %network, %session_id, stage="ip_nat_closed", "CONNECT-IP VPC return path removed");
    }
    let final_stats = session.stats();
    let failure = session.last_error().or(failure);
    if let Some(error) = failure.as_deref() {
        metrics.errors.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%peer, %network, %session_id, interface=%tun.name(), delivery_mode=final_stats.delivery_mode,
            configured_mtu=grant.mtu, effective_datagram_ip_capacity=final_stats.effective_datagram_ip_capacity,
            %error, "CONNECT-IP gateway session failed");
    }
    tracing::info!(%peer, %network, %session_id, interface=%tun.name(),
        duration_ms=session_started.elapsed().as_millis() as u64, close_reason,
        packets_injected_into_vpc=packets_to_vpc, packets_returned_from_vpc=packets_from_vpc,
        bytes_injected_into_vpc=bytes_to_vpc, bytes_returned_from_vpc=bytes_from_vpc,
        policy_drops_to_vpc, policy_drops_from_vpc,
        delivery_mode=final_stats.delivery_mode,
        datagrams_sent=final_stats.datagrams_sent, datagrams_received=final_stats.datagrams_received,
        mtu_errors=final_stats.mtu_errors, stage="connect_ip_session_closed",
        "CONNECT-IP gateway session closed");
    drop(protocol_metrics);
    grant.interface_name
}

fn packet_allowed(packet: &[u8], grant: &IpGrant, from_client: bool) -> bool {
    packet_drop_reason(packet, grant, from_client).is_none()
}

fn packet_addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20
            && packet[0] & 15 == 5
            && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len() =>
        {
            Some((
                Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).into(),
                Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).into(),
            ))
        }
        6 if packet.len() >= 40
            && usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len() =>
        {
            Some((
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).into(),
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).into(),
            ))
        }
        _ => None,
    }
}

fn packet_drop_reason(packet: &[u8], grant: &IpGrant, from_client: bool) -> Option<&'static str> {
    if packet.is_empty() || packet.len() > usize::from(grant.mtu) {
        return Some("empty_or_oversized_packet");
    }
    // The transport performs full header/protocol checks. Check lengths and
    // address policy again at the TUN boundary, without parsing packet payloads.
    let Some((source, destination)) = packet_addresses(packet) else {
        return Some("malformed_ip_header");
    };
    if from_client {
        if source != grant.client_address.addr() {
            Some("source_outside_assigned_address")
        } else if !grant.advertises(destination) {
            Some("destination_outside_advertised_routes")
        } else {
            None
        }
    } else {
        if destination != grant.client_address.addr() {
            Some("destination_not_assigned_to_connector")
        } else if !grant.advertises(source) {
            Some("source_outside_advertised_routes")
        } else {
            None
        }
    }
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> IpConfig {
        IpConfig {
            grants: vec![IpGrant {
                network: "local-vpc".into(),
                peer: iroh::SecretKey::from_bytes(&[9; 32]).public(),
                client_address: "192.0.2.2/32".parse().unwrap(),
                gateway_address: "192.0.2.1/32".parse().unwrap(),
                routes: vec!["10.78.0.0/24".parse().unwrap()],
                peer_routes: vec![],
                interface_name: "dtun0".into(),
                mtu: 1280,
            }],
        }
    }

    fn peer_config() -> IpConfig {
        let mut cfg = config();
        cfg.grants[0].peer_routes = vec!["192.0.2.3/32".parse().unwrap()];
        cfg.grants.push(IpGrant {
            network: "local-vpc".into(),
            peer: iroh::SecretKey::from_bytes(&[8; 32]).public(),
            client_address: "192.0.2.3/32".parse().unwrap(),
            gateway_address: "192.0.2.4/32".parse().unwrap(),
            routes: vec!["10.78.0.0/24".parse().unwrap()],
            peer_routes: vec!["192.0.2.2/32".parse().unwrap()],
            interface_name: "dtun1".into(),
            mtu: 1280,
        });
        cfg
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> [u8; 20] {
        let mut packet = [0; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[test]
    fn peer_routes_are_validated_and_advertised() {
        let cfg = peer_config();
        cfg.validate().unwrap();
        let grants = cfg.protocol_grants().unwrap();
        assert_eq!(
            grants[0]
                .routes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.78.0.0/24", "192.0.2.3/32"]
        );

        let mut invalid = cfg.clone();
        invalid.grants[0].peer_routes = vec!["192.0.2.99/32".parse().unwrap()];
        assert!(invalid.validate().is_err());
        let mut invalid = cfg.clone();
        invalid.grants[0].peer_routes = vec!["192.0.2.0/24".parse().unwrap()];
        assert!(invalid.validate().is_err());
        let mut invalid = cfg;
        invalid.grants[1].network = "other-vpc".into();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn peer_router_forwards_only_authorized_active_destinations() {
        let cfg = peer_config();
        let router = PeerRouter::new(&cfg);
        let source = "192.0.2.2".parse().unwrap();
        let destination = "192.0.2.3".parse().unwrap();
        let packet = ipv4_packet([192, 0, 2, 2], [192, 0, 2, 3]);

        assert!(!router.forward(source, destination, &packet));
        let (registration, mut received) = router.register(destination);
        assert!(router.forward(source, destination, &packet));
        assert_eq!(received.try_recv().unwrap(), packet);
        assert!(!router.forward(destination, destination, &packet));
        drop(registration);
        assert!(!router.forward(source, destination, &packet));

        // Dropping an old registration cannot remove a newer session that
        // reconnected using the same assigned address.
        let (old, _) = router.register(destination);
        let (_current, mut current_received) = router.register(destination);
        drop(old);
        assert!(router.forward(source, destination, &packet));
        assert_eq!(current_received.try_recv().unwrap(), packet);
    }

    #[test]
    fn packet_policy_allows_peer_routes_without_weakening_source_checks() {
        let cfg = peer_config();
        let first = &cfg.grants[0];
        let second = &cfg.grants[1];
        let packet = ipv4_packet([192, 0, 2, 2], [192, 0, 2, 3]);
        assert!(packet_allowed(&packet, first, true));
        assert!(packet_allowed(&packet, second, false));

        let spoofed = ipv4_packet([192, 0, 2, 9], [192, 0, 2, 3]);
        assert!(!packet_allowed(&spoofed, first, true));
        let unrelated = ipv4_packet([192, 0, 2, 2], [192, 0, 2, 9]);
        assert!(!packet_allowed(&unrelated, first, true));
    }

    #[test]
    fn egress_nat_is_scoped_to_the_client_route_and_vpc_interface() {
        assert_eq!(
            nat_rule("datum_dc1234", "ip6", "dc1234", "fdc4::1", "fd20:0:2a::/48"),
            [
                "add",
                "rule",
                "ip6",
                "datum_dc1234",
                "postrouting",
                "iifname",
                "dc1234",
                "oifname",
                "eth0",
                "ip6",
                "saddr",
                "fdc4::1",
                "ip6",
                "daddr",
                "fd20:0:2a::/48",
                "counter",
                "masquerade"
            ]
            .map(str::to_owned)
        );
        let ipv4 = nat_rule("datum_dc1234", "ip", "dc1234", "192.0.2.1", "10.0.0.0/8");
        assert!(ipv4.windows(2).any(|pair| pair == ["ip", "saddr"]));
        assert!(ipv4.windows(2).any(|pair| pair == ["ip", "daddr"]));
    }

    #[test]
    fn parses_and_sums_nft_postrouting_counters() {
        let output = "table ip6 datum_dcip0 {\n chain postrouting {\n  counter packets 3 bytes 180 masquerade\n  counter packets 7 bytes 420 masquerade\n }\n}";
        assert_eq!(
            parse_nat_counters(output),
            Some(NatCounters {
                packets: 10,
                bytes: 600,
            })
        );
        assert_eq!(
            parse_nat_counters("table ip6 datum_dcip0 { chain postrouting { } }"),
            None
        );
    }

    fn ipv6_config() -> IpConfig {
        let mut cfg = config();
        cfg.grants[0].client_address = "fd79::2/128".parse().unwrap();
        cfg.grants[0].gateway_address = "fd79::1/128".parse().unwrap();
        cfg.grants[0].routes = vec!["fd78::/64".parse().unwrap()];
        cfg
    }

    #[test]
    fn relay_only_grants_reject_default_routes() {
        let mut cfg = ipv6_config();
        cfg.validate_relay_only().unwrap();
        cfg.grants[0].routes = vec!["::/0".parse().unwrap()];
        assert!(cfg.validate_relay_only().is_err());
        cfg.grants[0].routes = vec!["0.0.0.0/1".parse().unwrap()];
        assert!(cfg.validate_relay_only().is_err());
    }

    #[test]
    fn ipv6_grants_are_single_family_and_preserve_underlay_isolation() {
        let cfg = ipv6_config();
        cfg.validate().unwrap();
        let grants = cfg.protocol_grants().unwrap();
        assert_eq!(grants[0].address, "fd79::2".parse::<IpAddr>().unwrap());
        assert_eq!(grants[0].routes[0].to_string(), "fd78::/64");
        // Inner and outer IP address families are intentionally independent.
        cfg.validate_underlay("172.20.0.3".parse().unwrap())
            .unwrap();
        cfg.validate_underlay("fd80::3".parse().unwrap()).unwrap();
        for address in ["fd79::1", "fd79::2", "fd78::3"] {
            assert!(cfg.validate_underlay(address.parse().unwrap()).is_err());
        }
        for route in [
            "::/0",
            "fe80::/64",
            "ff02::/64",
            "::ffff:10.0.0.0/104",
            "10.78.0.0/24",
        ] {
            let mut invalid = ipv6_config();
            invalid.grants[0].routes = vec![route.parse().unwrap()];
            assert!(invalid.validate().is_err(), "{route}");
        }
        let mut mixed = ipv6_config();
        mixed.grants[0].gateway_address = "192.0.2.1/32".parse().unwrap();
        assert!(mixed.validate().is_err());
    }

    #[test]
    fn ipv6_packet_policy_checks_both_directions_and_lengths() {
        let grant = &ipv6_config().grants[0];
        let mut packet = [0; 48];
        packet[0] = 0x60;
        packet[5] = 8;
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"fd79::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"fd78::3".parse::<Ipv6Addr>().unwrap().octets());
        assert!(packet_allowed(&packet, grant, true));
        assert_eq!(
            packet_drop_reason(&packet, grant, false),
            Some("destination_not_assigned_to_connector")
        );
        assert!(!packet_allowed(&packet, grant, false));
        assert!(!packet_allowed(&packet, &config().grants[0], true));
        packet[23] = 3;
        assert!(!packet_allowed(&packet, grant, true));
        packet[8..24].copy_from_slice(&"fd78::3".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"fd79::2".parse::<Ipv6Addr>().unwrap().octets());
        assert!(packet_allowed(&packet, grant, false));
        packet[39] = 3;
        assert_eq!(
            packet_drop_reason(&packet, grant, false),
            Some("destination_not_assigned_to_connector")
        );
        assert!(!packet_allowed(&packet, grant, false));
        packet[39] = 2;
        packet[8..24].copy_from_slice(&"fd79::3".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(
            packet_drop_reason(&packet, grant, false),
            Some("source_outside_advertised_routes")
        );
        packet[39] = 2;
        packet[5] = 7;
        assert!(!packet_allowed(&packet, grant, false));
        assert!(!packet_allowed(&packet[..39], grant, false));
        assert!(!packet_allowed(&[], grant, false));
    }
    #[test]
    fn rejects_overlapping_or_unsafe_grants() {
        IpConfig { grants: Vec::new() }.validate().unwrap();
        let mut cfg = config();
        cfg.validate().unwrap();
        cfg.grants.push(cfg.grants[0].clone());
        assert!(cfg.validate().is_err());
        let mut cfg = config();
        cfg.grants[0].routes = vec!["0.0.0.0/0".parse().unwrap()];
        assert!(cfg.validate().is_err());
        let mut cfg = config();
        cfg.grants[0].routes = vec!["192.0.2.0/24".parse().unwrap()];
        assert!(cfg.validate().is_err());
        assert!(serde_json::from_str::<IpConfig>("{\"grants\":[],\"unexpected\":true}").is_err());
        let mut cfg = config();
        cfg.grants[0].routes = (0..33)
            .map(|index| format!("10.78.0.{index}/32").parse().unwrap())
            .collect();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn underlay_must_stay_outside_all_overlay_addresses_and_routes() {
        let cfg = config();
        cfg.validate_underlay("172.20.0.3".parse().unwrap())
            .unwrap();
        for address in ["192.0.2.1", "192.0.2.2", "10.78.0.2"] {
            assert!(cfg.validate_underlay(address.parse().unwrap()).is_err());
        }
        let mut cfg = cfg;
        let mut other = cfg.grants[0].clone();
        other.routes = vec!["172.20.0.0/16".parse().unwrap()];
        cfg.grants.push(other);
        assert!(
            cfg.validate_underlay("172.20.0.3".parse().unwrap())
                .is_err()
        );
        IpConfig { grants: Vec::new() }
            .validate_underlay("172.20.0.3".parse().unwrap())
            .unwrap();
    }

    #[test]
    fn protocol_metric_deltas_do_not_double_count_repeated_or_final_flushes() {
        let metrics = IpMetrics::default();
        // One packet rejected locally before IpSession::send remains separate.
        metrics.dropped.fetch_add(1, Ordering::Relaxed);
        let mut previous = ip::Stats::default();
        let first = ip::Stats {
            packets_dropped: 3,
            protocol_errors: 2,
            datagrams_sent: 10,
            datagrams_received: 11,
            mtu_errors: 1,
            ..Default::default()
        };
        metrics.record_protocol_delta(&mut previous, first);
        metrics.record_protocol_delta(&mut previous, first);
        assert_eq!(metrics.dropped.load(Ordering::Relaxed), 4);
        assert_eq!(metrics.protocol_errors.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.datagrams_sent.load(Ordering::Relaxed), 10);
        assert_eq!(metrics.datagrams_received.load(Ordering::Relaxed), 11);
        assert_eq!(metrics.mtu_errors.load(Ordering::Relaxed), 1);
        let final_snapshot = ip::Stats {
            packets_dropped: 4,
            protocol_errors: 3,
            datagrams_sent: 14,
            datagrams_received: 15,
            mtu_errors: 2,
            ..Default::default()
        };
        metrics.record_protocol_delta(&mut previous, final_snapshot);
        metrics.record_protocol_delta(&mut previous, final_snapshot);
        assert_eq!(metrics.dropped.load(Ordering::Relaxed), 5);
        assert_eq!(metrics.protocol_errors.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.datagrams_sent.load(Ordering::Relaxed), 14);
        assert_eq!(metrics.datagrams_received.load(Ordering::Relaxed), 15);
        assert_eq!(metrics.mtu_errors.load(Ordering::Relaxed), 2);
        // A new session has its own cursor; previous session totals are retained.
        metrics.record_protocol_delta(&mut ip::Stats::default(), first);
        assert_eq!(metrics.dropped.load(Ordering::Relaxed), 8);
        assert_eq!(metrics.datagrams_sent.load(Ordering::Relaxed), 24);
        assert_eq!(metrics.datagrams_received.load(Ordering::Relaxed), 26);
        assert_eq!(metrics.mtu_errors.load(Ordering::Relaxed), 3);
        assert!(
            metrics
                .render()
                .contains("iroh_gateway_ip_protocol_errors_total 5")
        );
        assert!(
            metrics
                .render()
                .contains("iroh_gateway_ip_mtu_errors_total 3")
        );
        assert!(
            metrics
                .render()
                .contains("iroh_gateway_ip_datagrams_sent_total 24")
        );
        assert!(
            metrics
                .render()
                .contains("iroh_gateway_ip_datagrams_received_total 26")
        );
    }

    #[test]
    fn capacity_reports_the_minimum_live_session_and_cleans_up_on_drop() {
        let metrics = Arc::new(IpMetrics::default());
        let capacity = |expected| {
            assert!(metrics.render().contains(&format!(
                "iroh_gateway_ip_effective_datagram_ip_capacity_min {expected}\n"
            )))
        };
        capacity(0);
        metrics.active.store(2, Ordering::Relaxed);
        let first = ActiveSession(metrics.clone(), "dtun0".into());
        let second = ActiveSession(metrics.clone(), "dtun1".into());
        metrics.record_capacity("dtun0", 1400);
        metrics.record_capacity("dtun1", 1300);
        capacity(1300);
        // A path shrink must become visible, not remain at its setup capacity.
        metrics.record_capacity("dtun0", 1100);
        capacity(1100);
        drop(first);
        capacity(1300);
        drop(second);
        capacity(0);
        assert_eq!(metrics.active.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn packet_policy_rejects_spoofed_addresses_and_non_vpc_destinations() {
        let grant = &config().grants[0];
        let mut packet = [0; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[12..16].copy_from_slice(&[192, 0, 2, 2]);
        packet[16..20].copy_from_slice(&[10, 78, 0, 3]);
        assert!(packet_allowed(&packet, grant, true));
        assert!(!packet_allowed(&packet, grant, false));
        packet[15] = 3;
        assert_eq!(
            packet_drop_reason(&packet, grant, true),
            Some("source_outside_assigned_address")
        );
        assert!(!packet_allowed(&packet, grant, true));
        packet[15] = 2;
        packet[16] = 8;
        assert_eq!(
            packet_drop_reason(&packet, grant, true),
            Some("destination_outside_advertised_routes")
        );
        assert!(!packet_allowed(&packet, grant, true));
    }
}
