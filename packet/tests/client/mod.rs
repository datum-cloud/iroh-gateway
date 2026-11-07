//! An independent client for `galactic/iroh-packet/1`.
//!
//! This module implements the client side from the wire specification in
//! `src/wire.rs` alone. It deliberately does not import the `iroh_packet`
//! crate: every constant, encoder and decoder below is written out again so
//! that a server bug cannot hide behind shared code.

use std::{net::Ipv6Addr, time::Duration};

use bytes::{BufMut, Bytes, BytesMut};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, ConnectionError, ReadError, ReadExactError, RecvStream, SendStream},
};

pub const ALPN: &[u8] = b"galactic/iroh-packet/1";
const VERSION: u8 = 1;
const ADMIT_REQUEST: u8 = 0x01;
const ADMIT_ACCEPT: u8 = 0x02;
const ADMIT_REJECT: u8 = 0x03;
const MAX_PAYLOAD: usize = 1024;
const DGRAM_IPV6: u8 = 0x01;

pub const REJECT_MALFORMED: u16 = 0x0001;
pub const REJECT_FRAME_TOO_LARGE: u16 = 0x0002;
pub const REJECT_UNAUTHORIZED: u16 = 0x0010;
pub const REJECT_VPC_NOT_GRANTED: u16 = 0x0011;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// An admitted session.
#[derive(Debug)]
pub struct Session {
    pub conn: Connection,
    pub mtu: u16,
    pub addresses: Vec<(Ipv6Addr, u8)>,
    pub routes: Vec<(Ipv6Addr, u8)>,
    // Kept open for the life of the session; dropping or finishing ends it.
    pub control_send: SendStream,
    pub _control_recv: RecvStream,
}

/// Result of an admission attempt.
#[derive(Debug)]
pub enum Outcome {
    Admitted(Box<Session>),
    Rejected { code: u16 },
}

impl Outcome {
    pub fn admitted(self) -> Box<Session> {
        match self {
            Outcome::Admitted(s) => s,
            Outcome::Rejected { code } => panic!("expected admission, got rejection {code:#06x}"),
        }
    }

    pub fn rejected(self) -> u16 {
        match self {
            Outcome::Rejected { code } => code,
            Outcome::Admitted(_) => panic!("expected rejection, got admission"),
        }
    }
}

/// Encodes an `ADMIT_REQUEST` frame.
pub fn admit_request(token: &[u8], vpc: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(token.len() as u16).to_be_bytes());
    payload.extend_from_slice(token);
    payload.extend_from_slice(&(vpc.len() as u16).to_be_bytes());
    payload.extend_from_slice(vpc);
    let mut f = vec![VERSION, ADMIT_REQUEST];
    f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    f.extend_from_slice(&payload);
    f
}

/// Connects and admits with a well-formed request.
pub async fn admit(
    ep: &Endpoint,
    addr: EndpointAddr,
    token: &str,
    vpc: &str,
) -> Result<Outcome, Error> {
    admit_raw(ep, addr, &admit_request(token.as_bytes(), vpc.as_bytes())).await
}

fn close_code(err: &ConnectionError) -> Option<u16> {
    match err {
        ConnectionError::ApplicationClosed(c) => u16::try_from(c.error_code.into_inner()).ok(),
        _ => None,
    }
}

fn read_exact_code(err: &ReadExactError) -> Option<u16> {
    match err {
        ReadExactError::ReadError(ReadError::ConnectionLost(e)) => close_code(e),
        _ => None,
    }
}

/// Connects and sends `control` verbatim as the control stream's content.
pub async fn admit_raw(
    ep: &Endpoint,
    addr: EndpointAddr,
    control: &[u8],
) -> Result<Outcome, Error> {
    let conn = ep.connect(addr, ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(control).await?;

    let mut header = [0u8; 4];
    if let Err(err) = recv.read_exact(&mut header).await {
        return match read_exact_code(&err) {
            Some(code) => Ok(Outcome::Rejected { code }),
            None => Err(err.into()),
        };
    }
    if header[0] != VERSION {
        return Err("bad response version".into());
    }
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if len > MAX_PAYLOAD {
        return Err("oversized response".into());
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await?;
    match header[1] {
        ADMIT_REJECT => {
            if payload.len() != 2 {
                return Err("bad reject payload".into());
            }
            conn.close(0u32.into(), b"bye");
            Ok(Outcome::Rejected {
                code: u16::from_be_bytes([payload[0], payload[1]]),
            })
        }
        ADMIT_ACCEPT => {
            let (mtu, addresses, routes) = decode_accept(&payload)?;
            Ok(Outcome::Admitted(Box::new(Session {
                conn,
                mtu,
                addresses,
                routes,
                control_send: send,
                _control_recv: recv,
            })))
        }
        t => Err(format!("unexpected response type {t}").into()),
    }
}

type Prefixes = Vec<(Ipv6Addr, u8)>;

fn decode_accept(p: &[u8]) -> Result<(u16, Prefixes, Prefixes), Error> {
    let mut i = 0usize;
    let mut take = |n: usize| -> Result<&[u8], Error> {
        let s = p.get(i..i + n).ok_or("truncated accept")?;
        i += n;
        Ok(s)
    };
    let mtu = u16::from_be_bytes(take(2)?.try_into()?);
    let mut lists = Vec::new();
    for _ in 0..2 {
        let n = take(1)?[0] as usize;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let a: [u8; 16] = take(16)?.try_into()?;
            let l = take(1)?[0];
            v.push((Ipv6Addr::from(a), l));
        }
        lists.push(v);
    }
    if take(1).is_ok() {
        return Err("trailing bytes in accept".into());
    }
    let routes = lists.pop().unwrap();
    let addresses = lists.pop().unwrap();
    Ok((mtu, addresses, routes))
}

impl Session {
    /// Waits until the connection can carry `size` bytes per datagram.
    pub async fn wait_datagram_size(&self, size: usize, wait: Duration) -> Result<usize, Error> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let mds = self
                .conn
                .max_datagram_size()
                .ok_or("datagrams unsupported")?;
            if mds >= size {
                return Ok(mds);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!("max datagram size stuck at {mds}").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub fn send_packet(&self, pkt: &[u8]) -> Result<(), Error> {
        let mut d = BytesMut::with_capacity(1 + pkt.len());
        d.put_u8(DGRAM_IPV6);
        d.put_slice(pkt);
        self.conn.send_datagram(d.freeze())?;
        Ok(())
    }

    pub async fn recv_packet(&self, wait: Duration) -> Result<Bytes, Error> {
        let d = tokio::time::timeout(wait, self.conn.read_datagram()).await??;
        if d.first() != Some(&DGRAM_IPV6) {
            return Err("unknown datagram type".into());
        }
        Ok(d.slice(1..))
    }
}

/// Builds an ICMPv6 echo request whose IPv6 packet is exactly `total_len`
/// bytes long.
pub fn echo_request(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    ident: u16,
    seq: u16,
    total_len: usize,
) -> Vec<u8> {
    assert!(total_len >= 48);
    let icmp_len = total_len - 40;
    let mut p = vec![0u8; total_len];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    p[6] = 58;
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[40] = 128;
    p[44..46].copy_from_slice(&ident.to_be_bytes());
    p[46..48].copy_from_slice(&seq.to_be_bytes());
    for (i, b) in p[48..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let sum = checksum(src, dst, &p[40..]);
    p[42..44].copy_from_slice(&sum.to_be_bytes());
    p
}

/// A parsed, checksum-verified echo reply.
#[derive(Debug, PartialEq, Eq)]
pub struct EchoReply {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub ident: u16,
    pub seq: u16,
    pub total_len: usize,
}

pub fn parse_echo_reply(p: &[u8]) -> Option<EchoReply> {
    if p.len() < 48 || p[0] >> 4 != 6 || p[6] != 58 || p[40] != 129 {
        return None;
    }
    if usize::from(u16::from_be_bytes([p[4], p[5]])) + 40 != p.len() {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).ok()?);
    if checksum(src, dst, &p[40..]) != 0 {
        return None;
    }
    Some(EchoReply {
        src,
        dst,
        ident: u16::from_be_bytes([p[44], p[45]]),
        seq: u16::from_be_bytes([p[46], p[47]]),
        total_len: p.len(),
    })
}

fn checksum(src: Ipv6Addr, dst: Ipv6Addr, msg: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + msg.len() + 1);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(msg);
    if pseudo.len() % 2 == 1 {
        pseudo.push(0);
    }
    let mut sum: u32 = pseudo
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
