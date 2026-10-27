//! Admission: who may join which VPC.
//!
//! A connection is admitted only when the TLS-authenticated remote endpoint id
//! and the bearer token each resolve to exactly one principal, both resolve to
//! the same principal, and that principal holds exactly one grant for the
//! requested VPC. Nothing else (proxy headers, discovery records, relay
//! reachability) contributes to the decision.

use std::{collections::HashMap, fmt, net::Ipv6Addr, str::FromStr};

use iroh::EndpointId;

use crate::wire;

/// An IPv6 address with a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Prefix {
    /// The address, with host bits possibly set.
    pub addr: Ipv6Addr,
    /// Prefix length, `0..=128`.
    pub len: u8,
}

impl Ipv6Prefix {
    /// Creates a prefix. Panics if `len > 128`.
    pub fn new(addr: Ipv6Addr, len: u8) -> Self {
        assert!(len <= 128, "prefix length above 128");
        Self { addr, len }
    }

    /// Whether `ip` falls inside this prefix.
    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        let mask = if self.len == 0 {
            0
        } else {
            u128::MAX << (128 - u32::from(self.len))
        };
        (u128::from(self.addr) & mask) == (u128::from(ip) & mask)
    }
}

impl FromStr for Ipv6Prefix {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s.split_once('/').ok_or("missing prefix length")?;
        let addr: Ipv6Addr = addr.parse().map_err(|e| format!("{e}"))?;
        let len: u8 = len.parse().map_err(|e| format!("{e}"))?;
        if len > 128 {
            return Err("prefix length above 128".into());
        }
        Ok(Self { addr, len })
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// Identifier of a tenant principal.
pub type Principal = String;

/// One principal's access to one VPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// VPC selector, as sent in `ADMIT_REQUEST`.
    pub vpc: String,
    /// Addresses assigned to the client inside the VPC.
    pub addresses: Vec<Ipv6Prefix>,
    /// Destinations the client may reach.
    pub routes: Vec<Ipv6Prefix>,
}

/// Why admission was refused. Several reasons share one wire code so that a
/// client cannot probe which half of its credentials was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The control frame could not be parsed.
    Malformed,
    /// The control frame header announced an oversized payload.
    FrameTooLarge,
    /// The control frame version is unknown.
    UnsupportedVersion,
    /// The control frame type was not `ADMIT_REQUEST`.
    UnexpectedFrame,
    /// The token is not in the table.
    UnknownToken,
    /// The token maps to more than one principal.
    AmbiguousToken,
    /// The remote endpoint id is not in the table.
    UnknownEndpoint,
    /// The remote endpoint id maps to more than one principal.
    AmbiguousEndpoint,
    /// Token and endpoint id belong to different principals.
    PrincipalMismatch,
    /// The principal has no grant for the VPC.
    VpcNotGranted,
    /// The principal has more than one grant for the VPC.
    AmbiguousGrant,
    /// The principal already has a live session in the VPC.
    SessionExists,
    /// The path cannot carry a minimum-MTU IPv6 packet.
    PathMtuTooSmall,
    /// The peer does not accept datagrams.
    DatagramsUnsupported,
    /// The request did not arrive in time.
    Timeout,
    /// The backend refused the session.
    BackendUnavailable,
}

impl RejectReason {
    /// The wire rejection code for this reason.
    pub fn code(self) -> u16 {
        use RejectReason::*;
        match self {
            Malformed => wire::REJECT_MALFORMED,
            FrameTooLarge => wire::REJECT_FRAME_TOO_LARGE,
            UnsupportedVersion => wire::REJECT_UNSUPPORTED_VERSION,
            UnexpectedFrame => wire::REJECT_UNEXPECTED_FRAME,
            UnknownToken | AmbiguousToken | UnknownEndpoint | AmbiguousEndpoint
            | PrincipalMismatch => wire::REJECT_UNAUTHORIZED,
            VpcNotGranted | AmbiguousGrant => wire::REJECT_VPC_NOT_GRANTED,
            SessionExists => wire::REJECT_SESSION_EXISTS,
            PathMtuTooSmall => wire::REJECT_PATH_MTU_TOO_SMALL,
            DatagramsUnsupported => wire::REJECT_DATAGRAMS_UNSUPPORTED,
            Timeout => wire::REJECT_TIMEOUT,
            BackendUnavailable => wire::REJECT_BACKEND_UNAVAILABLE,
        }
    }
}

/// Error building a [`GrantTable`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantTableError {
    /// A grant has no addresses, too many, or too many routes.
    #[error(
        "grant for {principal}/{vpc} must have 1..={max_addr} addresses and at most {max_routes} routes"
    )]
    GrantSize {
        /// Principal of the grant.
        principal: Principal,
        /// VPC of the grant.
        vpc: String,
        /// Address limit.
        max_addr: usize,
        /// Route limit.
        max_routes: usize,
    },
}

/// A static, in-memory table of credentials and grants.
///
/// Tokens and endpoint ids may be bound to several principals; such an entry
/// is ambiguous and never admits anyone.
#[derive(Debug, Clone, Default)]
pub struct GrantTable {
    tokens: HashMap<String, Vec<Principal>>,
    endpoints: HashMap<EndpointId, Vec<Principal>>,
    grants: HashMap<Principal, Vec<Grant>>,
}

impl GrantTable {
    /// Creates an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds a bearer token to a principal.
    pub fn bind_token(&mut self, token: impl Into<String>, principal: impl Into<Principal>) {
        self.tokens
            .entry(token.into())
            .or_default()
            .push(principal.into());
    }

    /// Binds an iroh endpoint id to a principal.
    pub fn bind_endpoint(&mut self, id: EndpointId, principal: impl Into<Principal>) {
        self.endpoints.entry(id).or_default().push(principal.into());
    }

    /// Grants a principal access to a VPC.
    pub fn grant(
        &mut self,
        principal: impl Into<Principal>,
        grant: Grant,
    ) -> Result<(), GrantTableError> {
        let principal = principal.into();
        if grant.addresses.is_empty()
            || grant.addresses.len() > wire::MAX_ADDRESSES
            || grant.routes.len() > wire::MAX_ROUTES
        {
            return Err(GrantTableError::GrantSize {
                principal,
                vpc: grant.vpc,
                max_addr: wire::MAX_ADDRESSES,
                max_routes: wire::MAX_ROUTES,
            });
        }
        self.grants.entry(principal).or_default().push(grant);
        Ok(())
    }

    /// Reports whether `id` is bound to any principal. The listener checks it
    /// before waiting for an admission request, so an unknown endpoint holds
    /// no admission slot.
    pub fn knows_endpoint(&self, id: &EndpointId) -> bool {
        self.endpoints.get(id).is_some_and(|p| !p.is_empty())
    }

    /// Decides admission for `remote` presenting `token` and asking for `vpc`.
    pub fn authorize(
        &self,
        remote: EndpointId,
        token: &str,
        vpc: &str,
    ) -> Result<(Principal, Grant), RejectReason> {
        let by_token = match self.tokens.get(token).map(Vec::as_slice) {
            None | Some([]) => return Err(RejectReason::UnknownToken),
            Some([p]) => p,
            Some(_) => return Err(RejectReason::AmbiguousToken),
        };
        let by_endpoint = match self.endpoints.get(&remote).map(Vec::as_slice) {
            None | Some([]) => return Err(RejectReason::UnknownEndpoint),
            Some([p]) => p,
            Some(_) => return Err(RejectReason::AmbiguousEndpoint),
        };
        if by_token != by_endpoint {
            return Err(RejectReason::PrincipalMismatch);
        }
        let mut matching = self
            .grants
            .get(by_token)
            .into_iter()
            .flatten()
            .filter(|g| g.vpc == vpc);
        match (matching.next(), matching.next()) {
            (None, _) => Err(RejectReason::VpcNotGranted),
            (Some(g), None) => Ok((by_token.clone(), g.clone())),
            (Some(_), Some(_)) => Err(RejectReason::AmbiguousGrant),
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn id(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn grant(vpc: &str) -> Grant {
        Grant {
            vpc: vpc.into(),
            addresses: vec!["2001:db8:1::10/128".parse().unwrap()],
            routes: vec!["2001:db8:1::/64".parse().unwrap()],
        }
    }

    fn table() -> GrantTable {
        let mut t = GrantTable::new();
        t.bind_token("tok-a", "alice");
        t.bind_endpoint(id(1), "alice");
        t.grant("alice", grant("vpc-a")).unwrap();
        t.bind_token("tok-b", "bob");
        t.bind_endpoint(id(2), "bob");
        t
    }

    #[test]
    fn admits_matching_principal() {
        let (p, g) = table().authorize(id(1), "tok-a", "vpc-a").unwrap();
        assert_eq!(p, "alice");
        assert_eq!(g.vpc, "vpc-a");
    }

    #[test]
    fn rejects_each_failure() {
        let mut t = table();
        assert_eq!(
            t.authorize(id(1), "nope", "vpc-a"),
            Err(RejectReason::UnknownToken)
        );
        assert_eq!(
            t.authorize(id(9), "tok-a", "vpc-a"),
            Err(RejectReason::UnknownEndpoint)
        );
        assert_eq!(
            t.authorize(id(1), "tok-b", "vpc-a"),
            Err(RejectReason::PrincipalMismatch)
        );
        assert_eq!(
            t.authorize(id(1), "tok-a", "vpc-b"),
            Err(RejectReason::VpcNotGranted)
        );
        t.bind_token("tok-a", "bob");
        assert_eq!(
            t.authorize(id(1), "tok-a", "vpc-a"),
            Err(RejectReason::AmbiguousToken)
        );
        let mut t = table();
        t.bind_endpoint(id(1), "bob");
        assert_eq!(
            t.authorize(id(1), "tok-a", "vpc-a"),
            Err(RejectReason::AmbiguousEndpoint)
        );
        let mut t = table();
        t.grant("alice", grant("vpc-a")).unwrap();
        assert_eq!(
            t.authorize(id(1), "tok-a", "vpc-a"),
            Err(RejectReason::AmbiguousGrant)
        );
    }

    #[test]
    fn prefix_contains() {
        let p: Ipv6Prefix = "2001:db8:1::/64".parse().unwrap();
        assert!(p.contains("2001:db8:1::99".parse().unwrap()));
        assert!(!p.contains("2001:db8:2::1".parse().unwrap()));
        let all: Ipv6Prefix = "::/0".parse().unwrap();
        assert!(all.contains("fd00::1".parse().unwrap()));
    }
}
