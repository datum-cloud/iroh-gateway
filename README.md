# iroh-gateway

An HTTP/TCP and local UDP proxy gateway that forwards traffic through [iroh](https://github.com/n0-computer/iroh) peer-to-peer tunnels.

## How it works

iroh-gateway sits at the edge of the Datum Connect network and acts as the entry point for HTTP and CONNECT proxy traffic. Clients connect to it over TCP (or a Unix domain socket), send a standard HTTP proxy request, and the gateway resolves the target iroh endpoint and forwards the connection through an encrypted peer-to-peer tunnel.

```
client
  │  HTTP CONNECT / origin request
  ▼
iroh-gateway  ──── iroh tunnel ────►  datum-connect listen node
                                            │
                                            ▼
                                       local service
```

Two request modes are supported:

- **CONNECT (tunnel mode)** — the client sends `CONNECT` and the gateway upgrades to a raw TCP tunnel. Used for HTTPS and arbitrary TCP traffic.
- **Origin (proxy mode)** — the client sends a plain HTTP request with `x-iroh-endpoint-id`, `x-datum-target-host`, and `x-datum-target-port` headers. The gateway rewrites the request and forwards it to the upstream service.

The iroh endpoint identity of the target listen node is carried in the `x-iroh-endpoint-id` request header. The gateway strips all Datum-specific headers before forwarding.

## Running

```sh
iroh-gateway [OPTIONS]
```

On first run, a secret key is generated and written to `gateway_key` (or the path set by `--key-file`). This key is the stable identity of the gateway's iroh endpoint — keep it persistent across restarts.

### Options

| Flag | Default | Description |
|---|---|---|
| `--bind-addr` | `0.0.0.0` for legacy/auto; `127.0.0.1` for MASQUE | Proxy listener bind address |
| `--port` | `8080` | Proxy listener port |
| `--metrics-addr` | _(off)_ | Prometheus metrics bind address |
| `--metrics-port` | `9090` | Prometheus metrics port |
| `--uds` | _(off)_ | Unix domain socket path (Linux/macOS only) |
| `--key-file` | `gateway_key` | Path to the secret key file |
| `--config-file` | _(none)_ | Path to a YAML config file |
| `--discovery` | `default` | iroh discovery mode: `default`, `dns`, `hybrid`, or MASQUE-only `static` (explicit peers, no discovery or relay) |
| `--transport` | `legacy` | Upstream wire protocol: `legacy`, `masque`, or per-destination `auto` |
| `--peer` | _(none)_ | Repeatable static MASQUE peer address: `ENDPOINT_ID=IP:PORT` |
| `--print-endpoint-id` | _(off)_ | Print the public endpoint ID and exit, creating the configured key if needed |
| `--udp-forward` | _(none)_ | Repeatable MASQUE UDP listener: `LOOPBACK_ADDR:PORT=CONNECTOR_ID:TARGET_PORT` |
| `--udp-idle-timeout-secs` | `60` | Expire an inactive UDP client association after this many seconds |
| `--udp-max-associations` | `128` | Maximum concurrent UDP client associations per listener |
| `--dns-origin` | _(none)_ | DNS origin for `_iroh.<id>.<origin>` lookups |
| `--dns-resolver` | _(none)_ | Custom DNS resolver address (e.g. `127.0.0.1:53535`) |

### Environment variables

| Variable | Description |
|---|---|
| `IROH_GATEWAY_KEY_FILE` | Path to the secret key file (same as `--key-file`) |
| `IROH_GATEWAY_CONFIG_FILE` | Path to the YAML config file (same as `--config-file`) |
| `IROH_GATEWAY_RELAY_URLS` | Comma or space-separated list of iroh relay URLs to use |
| `IROH_SERVICES_API_KEY` | iroh-services API key — enables net diagnostics when set |
| `IROH_SERVICES_LABEL` | Label reported to iroh-services for this instance (default: `iroh-gateway`) |

`BUILD_IROH_GATEWAY_RELAY_URLS` can be set at compile time to bake a relay list into the binary as a fallback when the runtime variable is not set.

### Config file

Discovery settings can be provided via a YAML file instead of flags:

```yaml
discovery_mode: dns
dns_origin: iroh.example.com
dns_resolver: 127.0.0.1:53535
```

For a hosted CONNECT-IP gateway whose VPC interface address is assigned at
runtime, use a relay-only IPv6 wildcard bind. The gateway clears iroh's direct-IP
transports in CONNECT-IP mode, so peer traffic uses the configured relay rather
than advertising or routing through the TUN. Relay-only grants reject default
and near-default routes to avoid capturing relay traffic:

```yaml
ipv6_addr: "[::]:0"
discovery_mode: default
transport: masque
ip_config: /etc/connect/gateway/grants.json
```

Use `IROH_GATEWAY_RELAY_URLS` to pin a hosted gateway to Datum's staging relay
URLs. Set `discovery_mode: static` only when you configure direct peer addresses;
static discovery does not permit the wildcard underlay.

## Docker

```sh
docker run -p 8080:8080 \
  -v /path/to/data:/data \
  -e IROH_GATEWAY_KEY_FILE=/data/gateway_key \
  ghcr.io/datum-cloud/iroh-gateway
```

## Serve both client generations in one deployment

Use `--transport auto` to share one HTTP ingress listener, one iroh endpoint,
and one gateway identity between legacy desktop and MASQUE Connect traffic:

```sh
iroh-gateway --transport auto --port 10000 --metrics-port 9090 \
  --key-file /path/to/private/gateway_key --discovery hybrid --dns-origin datumconnect.net.
```

The TCP and optional Unix listeners accept HTTP/1.1 and HTTP/2 CONNECT.
Each request selects its upstream protocol from trusted ingress metadata:

| `x-datum-connect-transport` | Upstream protocol in auto mode |
|---|---|
| Absent | Legacy `iroh-http-proxy/1` |
| `legacy` | Legacy `iroh-http-proxy/1` |
| `masque-v1` | `datum-connect/masque-v1` |
| Empty, duplicate, or unknown | HTTP 400; no upstream connection |

Selection happens per request, including requests on a reused HTTP connection.
A failed MASQUE connection never retries legacy. In auto mode, HTTP origin
requests use a CONNECT stream for either profile; the legacy stream uses the
desktop's existing host/port authorization. MASQUE still selects only the
advertised destination port. HTTP and WebSocket forwarding share the ingress
implementation. Explicit `--transport legacy` and `--transport masque` retain
their existing absent-header behavior and reject a conflicting explicit profile.

The header is **not a public API or an authorization mechanism**. Restrict access
to this listener with network policy or socket permissions. NSO resolves the
Connector's `connect.datum.net/transport` annotation and adds `tunnel.transport`
to Envoy endpoint metadata. Missing annotations on resolved Connectors become
`legacy`; malformed profiles become offline routes. Connector lookup failures
do not become legacy destinations. Envoy generates a new upstream CONNECT and
sets the header from this metadata, not from public request headers.

The sibling `network-services-operator` and `infra` changes wire both NSO routing
implementations and the edge/base deployment templates. Transport annotation
changes also trigger Envoy retranslation without requiring a key or Ready change.
The templates retain their existing image tags; replace them with tested build
digests before applying. Those published tags do not include auto mode.
Roll out the gateway in auto mode first, then NSO, then the Envoy header template.
Verify generated routes contain the transport metadata before enabling MASQUE
Connectors. Do not point MASQUE routes at an old or legacy-only gateway.

Dispatch logs include request ID, protocol, endpoint key, destination port, setup
time, and failure stage. `iroh_gateway_dispatch_total{protocol=...}` counts
legacy, MASQUE, and invalid selections. `iroh_gateway_dispatch_failures_total`
counts upstream setup failures by protocol. Existing transport counters remain.

Run the mixed-profile test with:

```sh
cargo test one_listener_routes_legacy_and_masque_without_fallback
python3 scripts/connect-interop.py --transport-mode auto \
  --gateway target/debug/iroh-gateway \
  --daemon ../connect/connect-lib/target/debug/datum-connect-daemon
```

The Rust test uses a real legacy `UpstreamProxy` and real MASQUE endpoint, not
the packaged desktop. It checks HTTP keep-alive dispatch, HTTP/1 and HTTP/2
CONNECT, WebSocket bytes, shared gateway authorization, and wrong-profile denial.
The Python harness exercises auto-mode MASQUE against the real daemon with a
simulated control plane. Both need permission to bind loopback TCP/UDP sockets.
This session compiles these tests but cannot execute their network paths because
the sandbox denies loopback binds. Live Envoy header generation and the released
desktop remain rollout gates, alongside the existing key/socket migration and
standalone Docker dependency/toolchain issues described below.

## Forward local UDP traffic

Use `--udp-forward` to give a local UDP client a fixed destination on a Connect
device. The gateway forwards datagrams over HTTP/3 CONNECT-UDP using its stable
Connector identity. Each local source address and port gets its own association.
UDP ingress requires `--transport masque` or `--transport auto` and currently accepts loopback bind
addresses only; it does not expose an unauthenticated public UDP listener.

First, authorize the gateway explicitly on the device that runs your UDP service:

```sh
datumctl connect serve 127.0.0.1:5353 --protocol udp --allow GATEWAY_PUBLIC_KEY
```

Then start the gateway with a local forwarding port and the device's Connector key:

```sh
iroh-gateway --transport masque --key-file gateway_key \
  --udp-forward 127.0.0.1:15353=DEVICE_CONNECTOR_PUBLIC_KEY:5353
```

Your local client sends UDP packets to `127.0.0.1:15353`. Repeat `--udp-forward`
for additional fixed destinations. Use an explicit `--peer` mapping with
`--discovery static` when you want direct addressing without discovery or relays.

This is an operator-configured local listener, not a public HTTPProxy route.
`datumctl connect serve --public --protocol udp` remains unsupported. Approved
public gateways are excluded from default-private services; an explicit allowlist
is required for this path. Local processes can use the listener, so bind it only
on a machine whose local users you trust.

The forwarding path drops datagrams larger than 1,100 bytes. It also drops new
sources when the association limit is reached and drops packets when an
association's bounded queue is full. Idle associations release capacity.
Datagrams are not retried or made reliable by the gateway.

## Metrics

When `--metrics-port` is set, a Prometheus-compatible endpoint is available at `/metrics`. It exposes:

- Request counts by type (tunnel vs origin) and source (TCP vs UDS)
- Denied request counts by reason (missing header, invalid endpoint ID, etc.)
- HTTP error response counts by status code
- iroh connection counts (direct vs relay, current vs historical)
- Bytes sent and received through the iroh magicsock

## Validate local Connect interoperability

Use `scripts/connect-interop.py` to exercise the real gateway and Connect daemon
over MASQUE HTTP/3. Keep this checkout beside a compatible `connect` checkout;
the harness imports `connect/scripts/daemon-e2e.py` instead of duplicating its
simulated OAuth and control-plane server. The current local MASQUE build also
uses the transport crate from that sibling checkout.
This local path dependency is not a release dependency pin. Before publishing,
publish or pin the shared crate and update the standalone CI/Docker build context.
The existing published image does not contain this local MASQUE implementation.

```sh
cargo build
cd ../connect/connect-lib
cargo build -p datum-connect-daemon
cd ../../iroh-gateway
python3 scripts/connect-interop.py \
  --gateway target/debug/iroh-gateway \
  --daemon ../connect/connect-lib/target/debug/datum-connect-daemon
```

Use the Rust toolchain required by Connect. Python 3 and its standard library
are the only harness dependencies. If your checkout is elsewhere, pass
`--connect-repo /path/to/connect`.

Local verification on this machine uses Rust 1.94 with `--ignore-rust-version`
on Cargo commands because Connect declares Rust 1.98. This does not validate
the declared release toolchain.

The harness starts isolated processes and local TCP and UDP origins. It checks ordinary
HTTP, HTTP CONNECT, WebSocket upgrade and frame forwarding, public gateway
authorization, private allowlists, denial of
unpublished ports and unapproved gateways, routing-header removal, and service
removal. UDP checks cover empty datagrams, source isolation, association limits,
idle expiry, oversized-packet recovery, authorization denial, and revocation of
an existing association. It prints its private temporary artifact directory and retains logs for
diagnosis. It stops its processes automatically and never changes installed
services or creates deployed cloud resources.

Default-private services exclude gateway keys approved by the device's
ConnectorClass, including aliases of those keys. This is not a platform-wide
gateway-role or multi-class revocation guarantee. An explicit private
allowlist can authorize a gateway; that deliberately makes the service reachable
through that gateway's ingress. Only authorize a gateway when you intend to
trust its ingress access policy.

The MASQUE listener binds to loopback unless you explicitly override
`--bind-addr`. It trusts its ingress headers and does not authenticate incoming
HTTP clients. Place any non-loopback listener behind an authenticated ingress
or equivalent network isolation.

The harness sets `--discovery static` and supplies explicit peer addresses, so
gateway traffic does not depend on DNS discovery or a relay. New gateway key
files use private permissions. If an existing key is rejected for broad access,
set its permissions to mode 600 before starting the gateway.
Existing Unix socket paths are no longer unlinked automatically. Remove a stale
socket only after verifying that its previous owner has stopped.

Set `RUST_LOG=info,iroh_gateway=debug,connect_transport=debug` for diagnostics.
Responses include `x-request-id` for log correlation. MASQUE logs include the
peer, destination port, setup stage, status, selected direct/relay path, and RTT.
The metrics endpoint adds `iroh_gateway_masque_active_tcp`, payload byte counters,
and transport error counters. Logs do not include request bodies or credentials.
UDP counters use the `iroh_gateway_udp_` prefix and include active associations,
packets, bytes, connection failures, close reasons, and packet-drop reasons.

These checks validate direct local TCP and UDP interoperability. They do not certify
relay fallback, production controllers or HTTPProxy readiness, public UDP ingress,
CONNECT-IP, or deployed gateway access policy. The wire profile uses the shared
Datum-specific `datum-connect/masque-v1` ALPN and destination headers; these tests
do not establish generic MASQUE/RFC wire conformance or third-party interoperability.
MASQUE remains opt-in with
`--transport masque`; the default wire protocol remains legacy.

## Run the local CONNECT-IP prototype

You can test routed IPv4 or IPv6 traffic through the real Connect daemon and gateway.
The [Linux lab](scripts/connect-ip/README.md) runs `datumctl connect join`, creates
exclusive TUN interfaces inside disposable containers, and checks ping, TCP, UDP,
authorization, revocation, and route cleanup. Only OAuth and the Cloud API are
simulated. Your Mac routes and installed services stay unchanged.

The prototype uses static operator approvals, not production NetworkBinding
resources. It uses the Connector's existing iroh identity and a dedicated
`datum-connect/connect-ip-v1` ALPN. Extended CONNECT negotiates `connect-ip` and
exchanges address and route capsules over the reliable stream. IP packets travel
in HTTP Datagrams carried by QUIC DATAGRAM frames. Joins require measured datagram
capacity sufficient for the configured IP MTU; a capacity drop closes the session.
There is no silent reliable packet fallback.

Each static grant assigns one IPv4 `/32` or IPv6 `/128` address and routes of the
same address family. IPv6 grants support global and unique-local addresses with
TCP, UDP, and ICMPv6. The transport rejects IPv6 extension headers and fragments.
You must configure exactly one explicit `ipv4_addr` or `ipv6_addr` underlay socket.
The underlay family can differ from the grant family. Wildcard binds and underlay
addresses that overlap any grant's routes or assigned addresses are rejected to
prevent the tunnel from carrying its own transport traffic.

Dual-stack assignments in one grant, fragments, dynamic routes, native macOS
adapters, and generic third-party MASQUE interoperability remain unimplemented
or unverified. See the lab guide for verification commands and remaining restrictions.
