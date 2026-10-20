//! Packet backends: where admitted sessions send and receive packets.

use std::{
    collections::HashMap,
    fmt,
    net::Ipv6Addr,
    sync::{Arc, Mutex},
};

use bytes::{Bytes, BytesMut};
use iroh::EndpointId;
use tokio::sync::{mpsc, watch};

use crate::admission::{Ipv6Prefix, Principal};

/// Server-local identifier of an admitted session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s{}", self.0)
    }
}

/// What the backend learns about an admitted session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// Session id.
    pub id: SessionId,
    /// Admitted principal.
    pub principal: Principal,
    /// VPC the session belongs to.
    pub vpc: String,
    /// Authenticated iroh endpoint id of the client.
    pub remote: EndpointId,
    /// Addresses assigned to the client.
    pub addresses: Vec<Ipv6Prefix>,
    /// Session IPv6 MTU.
    pub mtu: u16,
}

/// Error opening a backend session.
#[derive(Debug, Clone, thiserror::Error)]
#[error("backend refused session: {0}")]
pub struct BackendError(pub String);

/// A VPC-facing packet sink and source.
///
/// The server calls [`PacketBackend::open_session`] only after admission
/// succeeds. Packets for the client go into `to_client`; the server drops the
/// returned [`BackendSession`] when the connection or control stream ends,
/// which must release every resource the backend holds for the session.
pub trait PacketBackend: Send + Sync + 'static {
    /// Opens the VPC side of a session.
    fn open_session(
        &self,
        info: &SessionInfo,
        to_client: mpsc::Sender<Bytes>,
    ) -> Result<Box<dyn BackendSession>, BackendError>;
}

/// One open session in a backend. Dropping it releases the session.
pub trait BackendSession: Send + 'static {
    /// Delivers one validated IPv6 packet from the client. Must not block.
    fn deliver(&mut self, packet: Bytes);
}

/// A test backend that answers ICMPv6 echo requests on each session.
///
/// It keeps a record of opened and released sessions so tests can observe
/// cleanup through the public protocol.
#[derive(Clone, Default)]
pub struct EchoBackend {
    inner: Arc<EchoInner>,
}

#[derive(Default)]
struct EchoInner {
    state: Mutex<EchoState>,
    active_tx: watch::Sender<usize>,
}

#[derive(Default)]
struct EchoState {
    active: HashMap<SessionId, SessionInfo>,
    opened: Vec<SessionId>,
    released: Vec<SessionId>,
    echoed: HashMap<SessionId, u64>,
}

impl fmt::Debug for EchoBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.inner.state.lock().expect("poisoned");
        f.debug_struct("EchoBackend")
            .field("active", &s.active.len())
            .field("opened", &s.opened.len())
            .field("released", &s.released.len())
            .finish()
    }
}

impl EchoBackend {
    /// Creates an empty echo backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sessions currently open.
    pub fn active(&self) -> Vec<SessionInfo> {
        let s = self.inner.state.lock().expect("poisoned");
        let mut v: Vec<_> = s.active.values().cloned().collect();
        v.sort_by_key(|i| i.id);
        v
    }

    /// Every session ever opened, in order.
    pub fn opened(&self) -> Vec<SessionId> {
        self.inner.state.lock().expect("poisoned").opened.clone()
    }

    /// Every session released, in order.
    pub fn released(&self) -> Vec<SessionId> {
        self.inner.state.lock().expect("poisoned").released.clone()
    }

    /// Echo replies sent on a session.
    pub fn echoed(&self, id: SessionId) -> u64 {
        let s = self.inner.state.lock().expect("poisoned");
        s.echoed.get(&id).copied().unwrap_or(0)
    }

    /// Watches the number of open sessions.
    pub fn watch_active(&self) -> watch::Receiver<usize> {
        self.inner.active_tx.subscribe()
    }
}

impl PacketBackend for EchoBackend {
    fn open_session(
        &self,
        info: &SessionInfo,
        to_client: mpsc::Sender<Bytes>,
    ) -> Result<Box<dyn BackendSession>, BackendError> {
        let n = {
            let mut s = self.inner.state.lock().expect("poisoned");
            s.active.insert(info.id, info.clone());
            s.opened.push(info.id);
            s.active.len()
        };
        self.inner.active_tx.send_replace(n);
        Ok(Box::new(EchoSession {
            id: info.id,
            to_client,
            inner: self.inner.clone(),
        }))
    }
}

struct EchoSession {
    id: SessionId,
    to_client: mpsc::Sender<Bytes>,
    inner: Arc<EchoInner>,
}

impl BackendSession for EchoSession {
    fn deliver(&mut self, packet: Bytes) {
        let Some(reply) = icmpv6_echo_reply(&packet) else {
            return;
        };
        if self.to_client.try_send(reply).is_ok() {
            let mut s = self.inner.state.lock().expect("poisoned");
            *s.echoed.entry(self.id).or_default() += 1;
        }
    }
}

impl Drop for EchoSession {
    fn drop(&mut self) {
        let n = {
            let mut s = self.inner.state.lock().expect("poisoned");
            s.active.remove(&self.id);
            s.released.push(self.id);
            s.active.len()
        };
        self.inner.active_tx.send_replace(n);
    }
}

const IPV6_HEADER_LEN: usize = 40;
const NEXT_HEADER_ICMPV6: u8 = 58;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// Builds the echo reply to an ICMPv6 echo request without extension headers.
fn icmpv6_echo_reply(pkt: &[u8]) -> Option<Bytes> {
    if pkt.len() < IPV6_HEADER_LEN + 8
        || pkt[0] >> 4 != 6
        || pkt[6] != NEXT_HEADER_ICMPV6
        || pkt[IPV6_HEADER_LEN] != ICMPV6_ECHO_REQUEST
        || pkt[IPV6_HEADER_LEN + 1] != 0
    {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
    if icmpv6_checksum(src, dst, &pkt[IPV6_HEADER_LEN..]) != 0 {
        return None;
    }
    let mut out = BytesMut::from(pkt);
    out[7] = 64;
    out[8..24].copy_from_slice(&dst.octets());
    out[24..40].copy_from_slice(&src.octets());
    out[IPV6_HEADER_LEN] = ICMPV6_ECHO_REPLY;
    out[IPV6_HEADER_LEN + 2] = 0;
    out[IPV6_HEADER_LEN + 3] = 0;
    let sum = icmpv6_checksum(dst, src, &out[IPV6_HEADER_LEN..]);
    out[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&sum.to_be_bytes());
    Some(out.freeze())
}

/// RFC 4443 checksum over the IPv6 pseudo-header and `msg`. Returns zero for
/// a message whose checksum field is correct.
fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, msg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |b: &[u8]| {
        for chunk in b.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += u32::from(word);
        }
    };
    add(&src.octets());
    add(&dst.octets());
    add(&(msg.len() as u32).to_be_bytes());
    add(&[0, 0, 0, NEXT_HEADER_ICMPV6]);
    add(msg);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
