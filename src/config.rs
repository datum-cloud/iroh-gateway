use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    path::PathBuf,
};

use n0_error::{Result, StackResultExt, StdResultExt};
use serde::{Deserialize, Serialize};

/// The selected wire protocol. Never fall back between protocols implicitly.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    Legacy,
    Masque,
    /// Select each destination from trusted ingress metadata; absent means legacy.
    Auto,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    #[default]
    /// Use the built-in n0des discovery defaults.
    Default,
    /// Use only DNS discovery (_iroh.<z32-endpoint-id>.<origin>).
    Dns,
    /// Use both n0des defaults and DNS discovery.
    Hybrid,
    /// Disable discovery and relays. Use operator-supplied direct peer addresses.
    Static,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// The IPv4 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed
    /// port, e.g. to configure a firewall rule.
    pub ipv4_addr: Option<SocketAddrV4>,

    /// The IPv6 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed
    /// port, e.g. to configure a firewall rule.
    pub ipv6_addr: Option<SocketAddrV6>,

    /// How the gateway resolves endpoint connection details.
    #[serde(default)]
    pub discovery_mode: DiscoveryMode,

    /// DNS origin domain used for _iroh.<z32-endpoint-id>.<origin> lookups.
    ///
    /// Required when discovery_mode is `dns` or `hybrid`.
    #[serde(default)]
    pub dns_origin: Option<String>,

    /// Optional DNS resolver address for discovery lookups.
    ///
    /// Useful for local development (e.g. 127.0.0.1:53535).
    #[serde(default)]
    pub dns_resolver: Option<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GatewayConfig {
    #[serde(flatten)]
    pub common: Config,
    #[serde(default)]
    pub transport: TransportMode,
    /// Operator-supplied direct addresses, never taken from ingress headers.
    #[serde(default)]
    pub peers: HashMap<iroh::EndpointId, Vec<SocketAddr>>,
    /// Local UDP ingress. Each listener has one fixed Connector destination.
    #[serde(default)]
    pub udp_forwards: Vec<UdpForward>,
    #[serde(default = "default_udp_max_associations")]
    pub udp_max_associations: usize,
    #[serde(default = "default_udp_idle_timeout_secs")]
    pub udp_idle_timeout_secs: u64,
    /// Static CONNECT-IP grants. Linux TUN only; never inferred from ingress.
    #[serde(default)]
    pub ip_config: Option<PathBuf>,
}

fn default_udp_max_associations() -> usize {
    128
}
fn default_udp_idle_timeout_secs() -> u64 {
    60
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            common: Config::default(),
            transport: TransportMode::default(),
            peers: HashMap::new(),
            udp_forwards: Vec::new(),
            udp_max_associations: default_udp_max_associations(),
            udp_idle_timeout_secs: default_udp_idle_timeout_secs(),
            ip_config: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpForward {
    pub bind_addr: SocketAddr,
    pub connector: iroh::EndpointId,
    pub port: u16,
}

impl UdpForward {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !self.bind_addr.ip().is_loopback() {
            return Err(
                "UDP ingress must bind a loopback IP; public UDP ingress is not supported".into(),
            );
        }
        if self.bind_addr.port() == 0 || self.port == 0 {
            return Err("UDP listener and destination ports must be nonzero".into());
        }
        Ok(())
    }
}

impl std::str::FromStr for UdpForward {
    type Err = String;
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (bind, destination) = value
            .split_once('=')
            .ok_or("expected BIND_IP:PORT=CONNECTOR_ID:PORT")?;
        let (id, port) = destination
            .rsplit_once(':')
            .ok_or("destination must be CONNECTOR_ID:PORT")?;
        let forward = Self {
            bind_addr: bind
                .parse()
                .map_err(|_| "UDP listener must be an IP address and port")?,
            connector: id.parse().map_err(|_| "invalid UDP Connector public key")?,
            port: port.parse().map_err(|_| "invalid UDP destination port")?,
        };
        forward.validate()?;
        Ok(forward)
    }
}

impl Config {
    /// The configured underlay socket, if exactly one address family is set.
    pub fn ip_underlay_socket(&self) -> Option<SocketAddr> {
        match (self.ipv4_addr, self.ipv6_addr) {
            (Some(address), None) => Some(address.into()),
            (None, Some(address)) => Some(address.into()),
            _ => None,
        }
    }

    pub async fn from_file(path: PathBuf) -> Result<Self> {
        let config = tokio::fs::read_to_string(path)
            .await
            .context("reading config file")?;
        let config = serde_yml::from_str(&config).std_context("parsing config file")?;
        Ok(config)
    }

    pub async fn write(&self, path: PathBuf) -> Result<()> {
        let data = serde_yml::to_string(self).anyerr()?;
        fs::write(path, data)?;
        Ok(())
    }
}

impl GatewayConfig {
    pub fn validate(&self) -> std::io::Result<()> {
        let invalid = |message: &str| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, message.to_owned())
        };
        if matches!(self.transport, TransportMode::Legacy)
            && (!self.peers.is_empty() || !self.udp_forwards.is_empty() || self.ip_config.is_some())
        {
            return Err(invalid(
                "static peer addresses, UDP forwarding, and CONNECT-IP require --transport masque or auto",
            ));
        }
        if self.ip_config.is_some() {
            let address = self.common.ip_underlay_socket().ok_or_else(|| {
                invalid("CONNECT-IP requires exactly one underlay socket in ipv4_addr OR ipv6_addr")
            })?;
            let ip = address.ip();
            // Hosted gateways receive their VPC address dynamically. A relay-only
            // endpoint can safely bind the IPv6 wildcard because its direct-IP
            // transports are disabled below; all iroh traffic uses the relay and
            // cannot be captured by the TUN routes. Static discovery disables
            // relays and must therefore use a concrete address.
            if ip.is_unspecified()
                && ip.is_ipv6()
                && address.port() == 0
                && !matches!(self.common.discovery_mode, DiscoveryMode::Static)
            {
                // Grant routes are checked after the strict config file loads.
            } else {
                let valid = match ip {
                    std::net::IpAddr::V4(ip) => {
                        ip.octets()[0] != 0
                            && ip.octets()[0] < 224
                            && !ip.is_loopback()
                            && !ip.is_link_local()
                    }
                    std::net::IpAddr::V6(ip) => {
                        ip.segments()[0] & 0xe000 == 0x2000 || ip.segments()[0] & 0xfe00 == 0xfc00
                    }
                };
                if !valid {
                    return Err(invalid(
                        "CONNECT-IP underlay must use a specific unicast IPv4 address or global/ULA IPv6 address, or [::]:0 with relay discovery",
                    ));
                }
            }
        }
        if self.udp_forwards.len() > 32 {
            return Err(invalid("at most 32 UDP forwards are allowed"));
        }
        if !(1..=1024).contains(&self.udp_max_associations)
            || !(1..=3600).contains(&self.udp_idle_timeout_secs)
        {
            return Err(invalid(
                "UDP max associations must be 1–1024 and idle timeout must be 1–3600 seconds",
            ));
        }
        let mut listeners = HashSet::new();
        for forward in &self.udp_forwards {
            forward.validate().map_err(|message| invalid(&message))?;
            if !listeners.insert(forward.bind_addr) {
                return Err(invalid("duplicate UDP listener address"));
            }
        }
        Ok(())
    }
    pub async fn from_file(path: PathBuf) -> Result<Self> {
        let config = tokio::fs::read_to_string(path)
            .await
            .context("reading config file")?;
        let config = serde_yml::from_str(&config).std_context("parsing config file")?;
        Ok(config)
    }

    pub async fn write(&self, path: PathBuf) -> Result<()> {
        let data = serde_yml::to_string(self).anyerr()?;
        fs::write(path, data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_config_keeps_legacy_transport() {
        let config: GatewayConfig =
            serde_yml::from_str("discovery_mode: dns\ndns_origin: example.test\n").unwrap();
        assert!(matches!(config.transport, TransportMode::Legacy));
        assert!(config.peers.is_empty());
        assert_eq!(config.udp_max_associations, 128);
        assert_eq!(config.udp_idle_timeout_secs, 60);
        assert!(config.udp_forwards.is_empty());
        config.validate().unwrap();
    }

    #[test]
    fn auto_config_enables_both_transports_without_changing_old_defaults() {
        let config: GatewayConfig =
            serde_yml::from_str("transport: auto\ndiscovery_mode: hybrid\n").unwrap();
        assert!(matches!(config.transport, TransportMode::Auto));
        config.validate().unwrap();
        assert!(matches!(
            GatewayConfig::default().transport,
            TransportMode::Legacy
        ));
    }

    #[test]
    fn masque_config_preserves_static_peer_addresses() {
        let id = iroh::SecretKey::generate().public();
        let config: GatewayConfig = serde_yml::from_str(&format!(
            "transport: masque\ndiscovery_mode: static\npeers:\n  '{id}': ['127.0.0.1:9999', '[::1]:9999']\n"
        )).unwrap();
        assert!(matches!(config.transport, TransportMode::Masque));
        assert!(matches!(
            config.common.discovery_mode,
            DiscoveryMode::Static
        ));
        assert_eq!(config.peers[&id].len(), 2);
        let encoded = serde_yml::to_string(&config).unwrap();
        let decoded: GatewayConfig = serde_yml::from_str(&encoded).unwrap();
        assert_eq!(config.peers, decoded.peers);
    }

    #[test]
    fn udp_flags_and_yaml_require_safe_explicit_listeners() {
        let id = iroh::SecretKey::generate().public();
        for bind in [
            "0.0.0.0:9000",
            "192.0.2.1:9000",
            "[::]:9000",
            "localhost:9000",
            "127.0.0.1:0",
        ] {
            assert!(format!("{bind}={id}:53").parse::<UdpForward>().is_err());
        }
        assert!(
            format!("127.0.0.1:9000={id}:0")
                .parse::<UdpForward>()
                .is_err()
        );
        for bind in ["127.0.0.1:9000", "[::1]:9000"] {
            let forward: UdpForward = format!("{bind}={id}:53").parse().unwrap();
            let mut config = GatewayConfig {
                udp_forwards: vec![forward.clone()],
                ..Default::default()
            };
            assert!(config.validate().is_err());
            config.transport = TransportMode::Masque;
            config.validate().unwrap();
            config.udp_forwards.push(forward);
            assert!(config.validate().is_err());
        }
        let config: GatewayConfig = serde_yml::from_str(&format!(
            "transport: masque\nudp_forwards:\n  - bind_addr: '0.0.0.0:9000'\n    connector: '{id}'\n    port: 53\n"
        )).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn udp_limits_are_bounded() {
        for limit in [0, 1025] {
            assert!(
                GatewayConfig {
                    udp_max_associations: limit,
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        for secs in [0, 3601] {
            assert!(
                GatewayConfig {
                    udp_idle_timeout_secs: secs,
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn ip_requires_one_explicit_underlay_socket() {
        let mut config = GatewayConfig {
            transport: TransportMode::Masque,
            ip_config: Some("grants.json".into()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "169.254.1.2",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            config.common.ipv4_addr = Some(format!("{ip}:7777").parse().unwrap());
            assert!(
                config.validate().is_err(),
                "{ip} must not be an IP underlay bind"
            );
        }
        config.common.ipv4_addr = Some("172.20.0.3:7777".parse().unwrap());
        config.validate().unwrap();
        for ip in ["[::]:7777", "[2001:db8::1]:7777"] {
            config.common.ipv6_addr = Some(ip.parse().unwrap());
            assert!(config.validate().is_err());
        }
        config.common.ipv4_addr = None;
        for ip in [
            "[::]:7777",
            "[::1]:7777",
            "[fe80::1]:7777",
            "[ff02::1]:7777",
            "[::ffff:172.20.0.3]:7777",
            "[::172.20.0.3]:7777",
            "[fec0::1]:7777",
        ] {
            config.common.ipv6_addr = Some(ip.parse().unwrap());
            assert!(
                config.validate().is_err(),
                "{ip} must not be an IP underlay bind"
            );
        }
        for ip in ["[2001:db8::1]:7777", "[fd78::1]:7777"] {
            config.common.ipv6_addr = Some(ip.parse().unwrap());
            config.validate().unwrap();
            assert_eq!(config.common.ip_underlay_socket().unwrap().to_string(), ip);
        }
        config.common.ipv4_addr = None;
        config.common.ipv6_addr = Some("[::]:0".parse().unwrap());
        config.validate().unwrap();
        config.common.discovery_mode = DiscoveryMode::Static;
        assert!(config.validate().is_err());
        // Existing HTTP/UDP-only gateway binding remains unrestricted.
        config.ip_config = None;
        config.common.ipv4_addr = Some("0.0.0.0:7777".parse().unwrap());
        config.validate().unwrap();
    }
}
