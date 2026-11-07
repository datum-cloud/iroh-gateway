//! Incoming iroh packet sessions.
//!
//! A tenant client opens an iroh connection with the [`wire::ALPN`] protocol,
//! asks to join exactly one VPC on a control stream, and, once admitted,
//! exchanges IPv6 packets with that VPC as QUIC datagrams.
//!
//! This crate is separate from the HTTP/TCP proxy in the parent crate. It
//! uses its own ALPN, expects its own endpoint key, and derives authorization
//! only from the TLS-authenticated remote endpoint id plus a bearer token
//! checked against a [`GrantTable`]. It never reads proxy headers and never
//! treats discovery or relay reachability as a grant.
//!
//! See [`wire`] for the protocol specification.

pub mod admission;
pub mod backend;
pub mod server;
pub mod wire;

pub use admission::{Grant, GrantTable, GrantTableError, Ipv6Prefix, Principal, RejectReason};
pub use backend::{
    BackendError, BackendSession, EchoBackend, PacketBackend, SessionId, SessionInfo,
};
pub use server::{AdmissionEvent, PacketServer, PacketServerConfig};
