//! End-to-end tests of `galactic/iroh-packet/1` through the public protocol.
//!
//! The server side is started through the crate's public API. The client is
//! the independent implementation in `tests/client`, which does not import
//! the crate.

mod client;

use std::{net::Ipv6Addr, sync::Arc, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{Connection, presets},
};
use iroh_packet::{
    AdmissionEvent, EchoBackend, Grant, GrantTable, PacketServer, PacketServerConfig, RejectReason,
    SessionId,
};
use iroh_relay::{
    RelayConfig,
    server::{Server as RelayServer, ServerConfig, testing::relay_config},
    tls::CaTlsConfig,
};
use tokio::sync::broadcast::{self, error::TryRecvError};

const SERVER_KEY: [u8; 32] = [0x51; 32];
const ALICE_KEY: [u8; 32] = [0xa1; 32];
const BOB_KEY: [u8; 32] = [0xb0; 32];
const MALLORY_KEY: [u8; 32] = [0xee; 32];

const ALICE_TOKEN: &str = "synthetic-token-alice-0001";
const BOB_TOKEN: &str = "synthetic-token-bob-0001";
const VPC_A: &str = "vpc-alpha";
const VPC_B: &str = "vpc-beta";

/// The proxy's ALPN, which the packet listener must refuse.
const PROXY_ALPN: &[u8] = b"iroh-http-proxy/1";

const WAIT: Duration = Duration::from_secs(10);

fn alice_addr() -> Ipv6Addr {
    "2001:db8:a::10".parse().unwrap()
}

fn echo_target() -> Ipv6Addr {
    "2001:db8:a::1".parse().unwrap()
}

fn id(key: [u8; 32]) -> iroh::EndpointId {
    SecretKey::from_bytes(&key).public()
}

fn grants() -> GrantTable {
    let mut t = GrantTable::new();
    t.bind_token(ALICE_TOKEN, "alice");
    t.bind_endpoint(id(ALICE_KEY), "alice");
    t.grant(
        "alice",
        Grant {
            vpc: VPC_A.into(),
            addresses: vec!["2001:db8:a::10/128".parse().unwrap()],
            routes: vec![
                "2001:db8:a::/64".parse().unwrap(),
                "fd00:a::/48".parse().unwrap(),
            ],
        },
    )
    .unwrap();
    t.bind_token(BOB_TOKEN, "bob");
    t.bind_endpoint(id(BOB_KEY), "bob");
    t.grant(
        "bob",
        Grant {
            vpc: VPC_B.into(),
            addresses: vec!["2001:db8:b::10/128".parse().unwrap()],
            routes: vec!["2001:db8:b::/64".parse().unwrap()],
        },
    )
    .unwrap();
    t
}

enum Path {
    Direct,
    Relay {
        map: RelayMap,
        url: RelayUrl,
        _server: RelayServer,
    },
}

struct Harness {
    server: PacketServer,
    backend: EchoBackend,
    addr: EndpointAddr,
    events: broadcast::Receiver<AdmissionEvent>,
    path: Path,
}

async fn direct_endpoint(key: [u8; 32]) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&key))
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

async fn relay_endpoint(key: [u8; 32], map: RelayMap) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&key))
        .relay_mode(RelayMode::Custom(map))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .clear_ip_transports()
        .bind()
        .await
        .unwrap()
}

/// Starts a local relay with no QUIC address discovery.
async fn local_relay() -> (RelayMap, RelayUrl, RelayServer) {
    let mut config = ServerConfig::default();
    config.relay = Some(relay_config());
    let server = RelayServer::spawn(config).await.unwrap();
    let url: RelayUrl = format!("https://{}", server.https_addr().unwrap())
        .parse()
        .unwrap();
    let map: RelayMap = RelayConfig::new(url.clone(), None).into();
    (map, url, server)
}

impl Harness {
    async fn direct() -> Self {
        let ep = direct_endpoint(SERVER_KEY).await;
        let sock = ep.bound_sockets()[0];
        let addr = EndpointAddr::new(ep.id()).with_ip_addr(sock);
        Self::start(ep, addr, Path::Direct)
    }

    async fn relay() -> Self {
        let (map, url, relay) = local_relay().await;
        let ep = relay_endpoint(SERVER_KEY, map.clone()).await;
        tokio::time::timeout(WAIT, ep.online())
            .await
            .expect("server reaches the relay");
        // Relay URL only: the client has no IP address to try.
        let addr = EndpointAddr::new(ep.id()).with_relay_url(url.clone());
        Self::start(
            ep,
            addr,
            Path::Relay {
                map,
                url,
                _server: relay,
            },
        )
    }

    fn start(ep: Endpoint, addr: EndpointAddr, path: Path) -> Self {
        let backend = EchoBackend::new();
        let server = PacketServer::spawn(
            ep,
            PacketServerConfig::new(grants()),
            Arc::new(backend.clone()),
        );
        let events = server.subscribe();
        Self {
            server,
            backend,
            addr,
            events,
            path,
        }
    }

    async fn client(&self, key: [u8; 32]) -> Endpoint {
        match &self.path {
            Path::Direct => direct_endpoint(key).await,
            Path::Relay { map, .. } => relay_endpoint(key, map.clone()).await,
        }
    }

    async fn next_event(&mut self) -> AdmissionEvent {
        tokio::time::timeout(WAIT, self.events.recv())
            .await
            .expect("event in time")
            .expect("event channel open")
    }

    async fn expect_rejected(&mut self, reason: RejectReason) {
        match self.next_event().await {
            AdmissionEvent::Rejected { reason: r, .. } => assert_eq!(r, reason),
            other => panic!("expected rejection {reason:?}, got {other:?}"),
        }
        assert!(
            self.backend.opened().is_empty(),
            "a rejected connection opened a backend session"
        );
    }

    async fn expect_admitted(&mut self) -> (SessionId, usize, Option<usize>, bool) {
        match self.next_event().await {
            AdmissionEvent::Admitted {
                session,
                max_datagram_size,
                initial_max_datagram_size,
                relay_only,
                ..
            } => (
                session,
                max_datagram_size,
                initial_max_datagram_size,
                relay_only,
            ),
            other => panic!("expected admission, got {other:?}"),
        }
    }

    async fn wait_no_active(&self) {
        let mut rx = self.backend.watch_active();
        tokio::time::timeout(WAIT, rx.wait_for(|n| *n == 0))
            .await
            .expect("backend released the session in time")
            .unwrap();
    }
}

fn path_kinds(conn: &Connection) -> (usize, usize) {
    let paths = conn.paths();
    let relay = paths.iter().filter(|p| p.is_relay()).count();
    let ip = paths.iter().filter(|p| p.is_ip()).count();
    (relay, ip)
}

/// Admits alice, sends one 1280-byte echo request and checks the reply.
/// Returns the client endpoint too: dropping it would discard the client's
/// close frame and leave the server waiting for the idle timeout.
async fn echo_1280(h: &mut Harness, label: &str) -> (Endpoint, Box<client::Session>) {
    let ep = h.client(ALICE_KEY).await;
    let session = client::admit(&ep, h.addr.clone(), ALICE_TOKEN, VPC_A)
        .await
        .unwrap()
        .admitted();
    let (sid, server_mds, server_initial_mds, server_relay_only) = h.expect_admitted().await;
    assert_eq!(session.mtu, 1280);
    assert_eq!(session.addresses, vec![(alice_addr(), 128)]);
    assert_eq!(session.routes.len(), 2);

    let client_initial = session.conn.max_datagram_size();
    let client_mds = session
        .wait_datagram_size(1 + 1280, WAIT)
        .await
        .expect("client path carries a 1280-byte packet");

    let req = client::echo_request(alice_addr(), echo_target(), 0x1234, 1, 1280);
    assert_eq!(req.len(), 1280);
    session.send_packet(&req).unwrap();
    let reply = session.recv_packet(WAIT).await.unwrap();
    let reply = client::parse_echo_reply(&reply).expect("valid echo reply");
    assert_eq!(
        reply,
        client::EchoReply {
            src: echo_target(),
            dst: alice_addr(),
            ident: 0x1234,
            seq: 1,
            total_len: 1280,
        }
    );
    assert_eq!(h.backend.echoed(sid), 1);

    // Let path MTU discovery finish its search before reading the settled size.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let client_settled = session.conn.max_datagram_size();
    let (relay, ip) = path_kinds(&session.conn);
    println!(
        "[{label}] server max_datagram_size: initial={server_initial_mds:?} at_admission={server_mds}; \
         client max_datagram_size: initial={client_initial:?} after_wait={client_mds} settled={client_settled:?}; \
         client paths: relay={relay} ip={ip}; server relay_only={server_relay_only}; \
         1280-byte ICMPv6 echo: ok"
    );
    (ep, session)
}

#[tokio::test]
async fn direct_path_echoes_1280_byte_packet() {
    let mut h = Harness::direct().await;
    let (_ep, session) = echo_1280(&mut h, "direct").await;
    let (relay, ip) = path_kinds(&session.conn);
    assert_eq!(relay, 0);
    assert!(ip >= 1);
    session.conn.close(0u32.into(), b"done");
    h.wait_no_active().await;
    h.server.shutdown().await;
}

#[tokio::test]
async fn relay_path_echoes_1280_byte_packet() {
    let mut h = Harness::relay().await;
    let (_ep, session) = echo_1280(&mut h, "relay").await;
    // Neither endpoint has an IP transport, so every path is the relay.
    let (relay, ip) = path_kinds(&session.conn);
    assert_eq!(ip, 0, "client has a direct path");
    assert!(relay >= 1);
    if let Path::Relay { url, .. } = &h.path {
        assert!(h.addr.relay_urls().all(|u| u == url));
        assert_eq!(h.addr.ip_addrs().count(), 0);
    }
    session.conn.close(0u32.into(), b"done");
    h.wait_no_active().await;
    h.server.shutdown().await;
}

#[tokio::test]
async fn relay_path_reports_relay_only_to_server() {
    let mut h = Harness::relay().await;
    let ep = h.client(ALICE_KEY).await;
    let _session = client::admit(&ep, h.addr.clone(), ALICE_TOKEN, VPC_A)
        .await
        .unwrap()
        .admitted();
    let (_, _, _, relay_only) = h.expect_admitted().await;
    assert!(relay_only, "server saw a non-relay path");
    h.server.shutdown().await;
}

#[tokio::test]
async fn rejects_unknown_token() {
    let mut h = Harness::direct().await;
    let ep = h.client(ALICE_KEY).await;
    let code = client::admit(&ep, h.addr.clone(), "synthetic-token-unknown", VPC_A)
        .await
        .unwrap()
        .rejected();
    assert_eq!(code, client::REJECT_UNAUTHORIZED);
    h.expect_rejected(RejectReason::UnknownToken).await;
}

#[tokio::test]
async fn rejects_token_of_another_principal() {
    let mut h = Harness::direct().await;
    let ep = h.client(ALICE_KEY).await;
    let code = client::admit(&ep, h.addr.clone(), BOB_TOKEN, VPC_B)
        .await
        .unwrap()
        .rejected();
    assert_eq!(code, client::REJECT_UNAUTHORIZED);
    h.expect_rejected(RejectReason::PrincipalMismatch).await;
}

#[tokio::test]
async fn rejects_unknown_endpoint_with_valid_token() {
    let mut h = Harness::direct().await;
    let ep = h.client(MALLORY_KEY).await;
    let code = client::admit(&ep, h.addr.clone(), ALICE_TOKEN, VPC_A)
        .await
        .unwrap()
        .rejected();
    assert_eq!(code, client::REJECT_UNAUTHORIZED);
    h.expect_rejected(RejectReason::UnknownEndpoint).await;
}

#[tokio::test]
async fn rejects_vpc_not_granted() {
    let mut h = Harness::direct().await;
    let ep = h.client(ALICE_KEY).await;
    let code = client::admit(&ep, h.addr.clone(), ALICE_TOKEN, VPC_B)
        .await
        .unwrap()
        .rejected();
    assert_eq!(code, client::REJECT_VPC_NOT_GRANTED);
    h.expect_rejected(RejectReason::VpcNotGranted).await;
}

#[tokio::test]
async fn rejects_oversized_control_frame() {
    let mut h = Harness::direct().await;
    let ep = h.client(ALICE_KEY).await;
    // A valid header announcing a 65535-byte payload, followed by more bytes
    // than the server will ever read.
    let mut frame = vec![1u8, 0x01, 0xff, 0xff];
    frame.extend(std::iter::repeat_n(b'a', 2048));
    let code = client::admit_raw(&ep, h.addr.clone(), &frame)
        .await
        .unwrap()
        .rejected();
    assert_eq!(code, client::REJECT_FRAME_TOO_LARGE);
    h.expect_rejected(RejectReason::FrameTooLarge).await;
}

#[tokio::test]
async fn rejects_malformed_control_frame() {
    let mut h = Harness::direct().await;
    let ep = h.client(ALICE_KEY).await;
    // token_len says 10 but the payload ends after 3 token bytes.
    let frame = [1u8, 0x01, 0x00, 0x05, 0x00, 0x0a, b'a', b'b', b'c'];
    let code = client::admit_raw(&ep, h.addr.clone(), &frame)
        .await
        .unwrap()
        .rejected();
    assert_eq!(code, client::REJECT_MALFORMED);
    h.expect_rejected(RejectReason::Malformed).await;
}

#[tokio::test]
async fn rejects_proxy_alpn() {
    let mut h = Harness::direct().await;
    let ep = h.client(ALICE_KEY).await;
    let res = tokio::time::timeout(WAIT, ep.connect(h.addr.clone(), PROXY_ALPN))
        .await
        .expect("handshake finishes in time");
    assert!(res.is_err(), "packet listener accepted the proxy ALPN");
    // The handshake fails before any session handler runs.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(matches!(h.events.try_recv(), Err(TryRecvError::Empty)));
    assert!(h.backend.opened().is_empty());
}

#[tokio::test]
async fn rejects_second_session_for_same_principal_and_vpc() {
    let mut h = Harness::direct().await;
    let ep = h.client(ALICE_KEY).await;
    let _first = client::admit(&ep, h.addr.clone(), ALICE_TOKEN, VPC_A)
        .await
        .unwrap()
        .admitted();
    h.expect_admitted().await;
    let code = client::admit(&ep, h.addr.clone(), ALICE_TOKEN, VPC_A)
        .await
        .unwrap()
        .rejected();
    assert_eq!(code, 0x0012);
    match h.next_event().await {
        AdmissionEvent::Rejected { reason, .. } => assert_eq!(reason, RejectReason::SessionExists),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(h.backend.opened().len(), 1);
}

#[tokio::test]
async fn drops_spoofed_source_and_unrouted_destination() {
    let mut h = Harness::direct().await;
    let ep = h.client(ALICE_KEY).await;
    let session = client::admit(&ep, h.addr.clone(), ALICE_TOKEN, VPC_A)
        .await
        .unwrap()
        .admitted();
    let (sid, ..) = h.expect_admitted().await;
    session.wait_datagram_size(1 + 1280, WAIT).await.unwrap();
    let spoofed = client::echo_request("2001:db8:b::10".parse().unwrap(), echo_target(), 1, 1, 100);
    session.send_packet(&spoofed).unwrap();
    let unrouted = client::echo_request(alice_addr(), "2001:db8:ff::1".parse().unwrap(), 1, 2, 100);
    session.send_packet(&unrouted).unwrap();
    assert!(
        session
            .recv_packet(Duration::from_millis(500))
            .await
            .is_err()
    );
    assert_eq!(h.backend.echoed(sid), 0);
    // A legitimate packet on the same session still works.
    let ok = client::echo_request(alice_addr(), "fd00:a::1".parse().unwrap(), 1, 3, 100);
    session.send_packet(&ok).unwrap();
    let reply = client::parse_echo_reply(&session.recv_packet(WAIT).await.unwrap()).unwrap();
    assert_eq!(reply.seq, 3);
}

#[tokio::test]
async fn closing_connection_releases_backend_session() {
    let mut h = Harness::direct().await;
    let ep = h.client(ALICE_KEY).await;
    let session = client::admit(&ep, h.addr.clone(), ALICE_TOKEN, VPC_A)
        .await
        .unwrap()
        .admitted();
    let (sid, ..) = h.expect_admitted().await;
    assert_eq!(h.backend.active().len(), 1);

    session.conn.close(0u32.into(), b"client done");
    h.wait_no_active().await;
    assert_eq!(h.backend.released(), vec![sid]);
    assert_eq!(
        h.next_event().await,
        AdmissionEvent::Released { session: sid }
    );

    // The live-session reservation is gone, so the principal can rejoin.
    let again = client::admit(&ep, h.addr.clone(), ALICE_TOKEN, VPC_A)
        .await
        .unwrap()
        .admitted();
    let (sid2, ..) = h.expect_admitted().await;
    assert_ne!(sid, sid2);
    drop(again);
}

#[tokio::test]
async fn finishing_control_stream_releases_backend_session() {
    let mut h = Harness::direct().await;
    let ep = h.client(ALICE_KEY).await;
    let mut session = client::admit(&ep, h.addr.clone(), ALICE_TOKEN, VPC_A)
        .await
        .unwrap()
        .admitted();
    let (sid, ..) = h.expect_admitted().await;

    session.control_send.finish().unwrap();
    h.wait_no_active().await;
    assert_eq!(h.backend.released(), vec![sid]);
    // The server closes the connection with the normal close code.
    let err = tokio::time::timeout(WAIT, session.conn.closed())
        .await
        .unwrap();
    assert!(
        matches!(&err, iroh::endpoint::ConnectionError::ApplicationClosed(c) if c.error_code.into_inner() == 0),
        "unexpected close {err:?}"
    );
}
