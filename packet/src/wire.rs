//! Wire format of the `galactic/iroh-packet/1` protocol.
//!
//! # ALPN
//!
//! The protocol is selected by the ALPN `galactic/iroh-packet/1`. The
//! `galactic/` namespace marks it as a data-plane protocol of the VPC fabric,
//! distinct from the `iroh-http-proxy/1` application proxy, and the trailing
//! `/1` is the protocol major version. An incompatible change gets a new ALPN,
//! so a peer that speaks another version fails the TLS handshake instead of
//! misreading frames. A packet listener accepts no other ALPN.
//!
//! # Control stream
//!
//! The client opens one bidirectional stream right after the handshake and
//! sends exactly one `ADMIT_REQUEST` frame on it. The server answers with one
//! `ADMIT_ACCEPT` or `ADMIT_REJECT` frame. Every control frame has a 4-byte
//! header followed by its payload:
//!
//! ```text
//! +---------+---------+------------------+------------------+
//! | version | type    | length (u16, BE) | payload          |
//! | 1 byte  | 1 byte  | 2 bytes          | `length` bytes   |
//! +---------+---------+------------------+------------------+
//! ```
//!
//! `version` is [`FRAME_VERSION`]. `length` is at most
//! [`MAX_CONTROL_PAYLOAD`]; the server rejects a larger value from the header
//! alone, without reading the payload. All integers are big-endian.
//!
//! `ADMIT_REQUEST` (`0x01`, client to server):
//!
//! ```text
//! u16 token_len   (1..=MAX_TOKEN_LEN)
//! token           (token_len bytes, visible ASCII 0x21..=0x7e)
//! u16 vpc_len     (1..=MAX_VPC_LEN)
//! vpc             (vpc_len bytes, ASCII a-z 0-9 '-' '.' '_' '/')
//! ```
//!
//! `ADMIT_ACCEPT` (`0x02`, server to client):
//!
//! ```text
//! u16 mtu                  IPv6 MTU of the session, >= 1280
//! u8  address_count        (1..=MAX_ADDRESSES)
//! address_count x { [u8; 16] address, u8 prefix_len (0..=128) }
//! u8  route_count          (0..=MAX_ROUTES)
//! route_count x { [u8; 16] prefix, u8 prefix_len (0..=128) }
//! ```
//!
//! `ADMIT_REJECT` (`0x03`, server to client): `u16 code`, one of the
//! `REJECT_*` constants.
//!
//! A payload with trailing bytes, out-of-range lengths or invalid characters
//! is malformed. Any frame type other than `ADMIT_REQUEST` from the client is
//! unexpected.
//!
//! After `ADMIT_ACCEPT` both sides keep the control stream open and send
//! nothing more on it. If either side finishes or resets it, or sends more
//! bytes, the session ends and the server closes the connection with
//! [`CLOSE_NORMAL`] (or [`REJECT_MALFORMED`] for extra bytes).
//!
//! After `ADMIT_REJECT` the server finishes the stream and closes the
//! connection with the rejection code as the application close code, so a
//! client that misses the frame still learns the reason.
//!
//! # Datagrams
//!
//! Once admitted, each QUIC datagram carries one IPv6 packet behind a
//! single type byte:
//!
//! ```text
//! +----------------------+---------------------------------+
//! | 0x01 (DGRAM_IPV6)    | IPv6 packet (40..=mtu bytes)     |
//! +----------------------+---------------------------------+
//! ```
//!
//! The type byte costs one byte per packet and leaves room for other
//! datagram kinds later without a new ALPN. Datagrams with another type byte,
//! a malformed IPv6 header, a length above `1 + mtu`, or (from the client) a
//! source address outside the assigned addresses are dropped. Datagrams that
//! arrive before `ADMIT_ACCEPT` may be dropped.
//!
//! A session needs a path that carries `1 + 1280` bytes per datagram. The
//! server rejects admission with [`REJECT_PATH_MTU_TOO_SMALL`] when the
//! connection's maximum datagram size stays below that.

use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};

/// ALPN of version 1 of the packet protocol.
pub const ALPN: &[u8] = b"galactic/iroh-packet/1";

/// Version byte of every control frame.
pub const FRAME_VERSION: u8 = 1;
/// Size of the control frame header.
pub const FRAME_HEADER_LEN: usize = 4;
/// Largest control frame payload either side accepts.
pub const MAX_CONTROL_PAYLOAD: usize = 1024;

/// Client admission request.
pub const FRAME_ADMIT_REQUEST: u8 = 0x01;
/// Server admission response.
pub const FRAME_ADMIT_ACCEPT: u8 = 0x02;
/// Server rejection.
pub const FRAME_ADMIT_REJECT: u8 = 0x03;

/// Longest bearer token.
pub const MAX_TOKEN_LEN: usize = 512;
/// Longest VPC selector.
pub const MAX_VPC_LEN: usize = 253;
/// Most addresses in one `ADMIT_ACCEPT`.
pub const MAX_ADDRESSES: usize = 16;
/// Most routes in one `ADMIT_ACCEPT`.
pub const MAX_ROUTES: usize = 32;

/// Datagram type byte for an IPv6 packet.
pub const DGRAM_IPV6: u8 = 0x01;
/// Bytes a datagram adds in front of the IPv6 packet.
pub const DGRAM_PREFIX_LEN: usize = 1;
/// The IPv6 minimum link MTU (RFC 8200, section 5).
pub const IPV6_MIN_MTU: u16 = 1280;

/// Application close code for a session that ended normally.
pub const CLOSE_NORMAL: u32 = 0;

/// The request frame could not be parsed.
pub const REJECT_MALFORMED: u16 = 0x0001;
/// The frame header announced a payload above [`MAX_CONTROL_PAYLOAD`].
pub const REJECT_FRAME_TOO_LARGE: u16 = 0x0002;
/// The frame version is not [`FRAME_VERSION`].
pub const REJECT_UNSUPPORTED_VERSION: u16 = 0x0003;
/// The frame type is not `ADMIT_REQUEST`.
pub const REJECT_UNEXPECTED_FRAME: u16 = 0x0004;
/// The token and remote endpoint id do not identify one principal.
pub const REJECT_UNAUTHORIZED: u16 = 0x0010;
/// The principal is not granted the requested VPC.
pub const REJECT_VPC_NOT_GRANTED: u16 = 0x0011;
/// The principal already has a live session in the VPC.
pub const REJECT_SESSION_EXISTS: u16 = 0x0012;
/// The connection cannot carry a 1280-byte IPv6 packet in one datagram.
pub const REJECT_PATH_MTU_TOO_SMALL: u16 = 0x0020;
/// The peer does not accept QUIC datagrams.
pub const REJECT_DATAGRAMS_UNSUPPORTED: u16 = 0x0021;
/// The request did not arrive in time.
pub const REJECT_TIMEOUT: u16 = 0x0030;
/// The packet backend refused the session.
pub const REJECT_BACKEND_UNAVAILABLE: u16 = 0x0031;

/// A parsed control frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Frame version byte.
    pub version: u8,
    /// Frame type byte.
    pub frame_type: u8,
    /// Payload length.
    pub length: u16,
}

impl FrameHeader {
    /// Decodes a header.
    pub fn decode(buf: [u8; FRAME_HEADER_LEN]) -> Self {
        Self {
            version: buf[0],
            frame_type: buf[1],
            length: u16::from_be_bytes([buf[2], buf[3]]),
        }
    }
}

/// A decoded `ADMIT_REQUEST` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitRequest {
    /// Bearer token.
    pub token: String,
    /// Requested VPC selector.
    pub vpc: String,
}

/// A decoded `ADMIT_ACCEPT` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitAccept {
    /// Session IPv6 MTU.
    pub mtu: u16,
    /// Addresses assigned to the client.
    pub addresses: Vec<(Ipv6Addr, u8)>,
    /// Routes the client may send to.
    pub routes: Vec<(Ipv6Addr, u8)>,
}

/// Why a payload failed to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed control frame: {0}")]
pub struct Malformed(pub &'static str);

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if self.buf.len() < n {
            return Err(Malformed("truncated"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Malformed> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn prefix(&mut self) -> Result<(Ipv6Addr, u8), Malformed> {
        let b: [u8; 16] = self.take(16)?.try_into().expect("16 bytes");
        let len = self.u8()?;
        if len > 128 {
            return Err(Malformed("prefix length above 128"));
        }
        Ok((Ipv6Addr::from(b), len))
    }

    fn finish(self) -> Result<(), Malformed> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Malformed("trailing bytes"))
        }
    }
}

fn valid_token(b: &[u8]) -> bool {
    !b.is_empty() && b.len() <= MAX_TOKEN_LEN && b.iter().all(|c| (0x21..=0x7e).contains(c))
}

fn valid_vpc(b: &[u8]) -> bool {
    !b.is_empty()
        && b.len() <= MAX_VPC_LEN
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-._/".contains(c))
}

impl AdmitRequest {
    /// Decodes an `ADMIT_REQUEST` payload.
    pub fn decode(payload: &[u8]) -> Result<Self, Malformed> {
        let mut r = Reader { buf: payload };
        let token_len = r.u16()? as usize;
        let token = r.take(token_len)?;
        if !valid_token(token) {
            return Err(Malformed("invalid token"));
        }
        let vpc_len = r.u16()? as usize;
        let vpc = r.take(vpc_len)?;
        if !valid_vpc(vpc) {
            return Err(Malformed("invalid vpc selector"));
        }
        r.finish()?;
        Ok(Self {
            token: String::from_utf8(token.to_vec()).expect("ascii"),
            vpc: String::from_utf8(vpc.to_vec()).expect("ascii"),
        })
    }
}

impl AdmitAccept {
    /// Encodes this response as a complete control frame.
    pub fn encode_frame(&self) -> Bytes {
        assert!(!self.addresses.is_empty() && self.addresses.len() <= MAX_ADDRESSES);
        assert!(self.routes.len() <= MAX_ROUTES);
        let mut p = BytesMut::new();
        p.put_u16(self.mtu);
        p.put_u8(self.addresses.len() as u8);
        for (addr, len) in &self.addresses {
            p.put_slice(&addr.octets());
            p.put_u8(*len);
        }
        p.put_u8(self.routes.len() as u8);
        for (addr, len) in &self.routes {
            p.put_slice(&addr.octets());
            p.put_u8(*len);
        }
        frame(FRAME_ADMIT_ACCEPT, &p)
    }

    /// Decodes an `ADMIT_ACCEPT` payload.
    pub fn decode(payload: &[u8]) -> Result<Self, Malformed> {
        let mut r = Reader { buf: payload };
        let mtu = r.u16()?;
        let n = r.u8()? as usize;
        if n == 0 || n > MAX_ADDRESSES {
            return Err(Malformed("address count"));
        }
        let addresses = (0..n).map(|_| r.prefix()).collect::<Result<_, _>>()?;
        let n = r.u8()? as usize;
        if n > MAX_ROUTES {
            return Err(Malformed("route count"));
        }
        let routes = (0..n).map(|_| r.prefix()).collect::<Result<_, _>>()?;
        r.finish()?;
        Ok(Self {
            mtu,
            addresses,
            routes,
        })
    }
}

/// Encodes an `ADMIT_REJECT` frame.
pub fn encode_reject(code: u16) -> Bytes {
    frame(FRAME_ADMIT_REJECT, &code.to_be_bytes())
}

fn frame(frame_type: u8, payload: &[u8]) -> Bytes {
    debug_assert!(payload.len() <= MAX_CONTROL_PAYLOAD);
    let mut b = BytesMut::with_capacity(FRAME_HEADER_LEN + payload.len());
    b.put_u8(FRAME_VERSION);
    b.put_u8(frame_type);
    b.put_u16(payload.len() as u16);
    b.put_slice(payload);
    b.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(token: &[u8], vpc: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&(token.len() as u16).to_be_bytes());
        p.extend_from_slice(token);
        p.extend_from_slice(&(vpc.len() as u16).to_be_bytes());
        p.extend_from_slice(vpc);
        p
    }

    #[test]
    fn request_round_trip() {
        let r = AdmitRequest::decode(&request(b"tok-a", b"vpc-a")).unwrap();
        assert_eq!(r.token, "tok-a");
        assert_eq!(r.vpc, "vpc-a");
    }

    #[test]
    fn request_rejects_bad_input() {
        assert!(AdmitRequest::decode(&request(b"", b"vpc")).is_err());
        assert!(AdmitRequest::decode(&request(b"tok en", b"vpc")).is_err());
        assert!(AdmitRequest::decode(&request(b"tok", b"VPC")).is_err());
        assert!(AdmitRequest::decode(&request(b"tok", b"")).is_err());
        let mut trailing = request(b"tok", b"vpc");
        trailing.push(0);
        assert!(AdmitRequest::decode(&trailing).is_err());
        assert!(AdmitRequest::decode(&[0, 10, b'a']).is_err());
        assert!(AdmitRequest::decode(&request(&[b'a'; MAX_TOKEN_LEN + 1], b"vpc")).is_err());
    }

    #[test]
    fn accept_round_trip() {
        let a = AdmitAccept {
            mtu: 1280,
            addresses: vec![("2001:db8:1::10".parse().unwrap(), 128)],
            routes: vec![("2001:db8:1::".parse().unwrap(), 64)],
        };
        let f = a.encode_frame();
        assert_eq!(f[0], FRAME_VERSION);
        assert_eq!(f[1], FRAME_ADMIT_ACCEPT);
        assert_eq!(u16::from_be_bytes([f[2], f[3]]) as usize, f.len() - 4);
        assert_eq!(AdmitAccept::decode(&f[4..]).unwrap(), a);
    }
}
