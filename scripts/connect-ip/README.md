# Test CONNECT-IP locally

This lab carries real IPv4 or IPv6 packets from an enrolled Connector through iroh and
HTTP/3 to a Linux gateway TUN, then into an isolated network. It uses the actual
`datumctl connect` plugin dispatch. Only OAuth and the Cloud API are simulated.
It does not create deployed resources or change your host routes or services.

## Build and test

Keep the `connect` and `iroh-gateway` checkouts next to each other. Install Python
3, Go, and Docker with a running Linux VM. The VM needs `/dev/net/tun` and support
for containers with `CAP_NET_ADMIN`. Use a Docker context explicitly; the script
does not change your default context. On this machine, use `colima-kata`.

From `iroh-gateway`, run:

```sh
python3 scripts/connect-ip-local.py --docker-context colima-kata \
  --build --datumctl-source /Users/scotwells/repos/datum-cloud/datumctl \
  --binaries target/connect-ip-datagram-linux-bin --keep
```

Replace the datumctl path on another machine. The build reads that checkout but
does not edit it. It cross-compiles both Go CLIs for the VM architecture and
builds the Rust binaries inside Docker using Connect's pinned toolchain. Cargo
and Rust toolchain caches remain in three `datum-connect-ip-*` Docker volumes.
The lab image is a development image, not a release artifact.
Rebuild the daemon and gateway together. The IPv6 prototype requests both address
families and explicitly declines the unassigned family; older IPv4-only prototype
binaries do not support this capsule exchange.

After the first build, omit `--build` and `--datumctl-source` to rerun the tests.
Keep the same `--binaries` argument. Rebuild whenever source changes.
Omit `--keep` to remove the test containers and networks automatically.

Add `--ipv6` to use IPv6-only underlay and VPC networks. The suite verifies that
every container has no non-loopback IPv4 address, before and after joining.
The daemon API, metrics, and simulated Cloud API still use IPv4 loopback inside
their containers; no IPv4 traffic crosses between containers. The origin binds
IPv6-only HTTP and UDP sockets. Docker must support `--ipv4=false` networks.
Build to a separate directory if you keep another lab running:

```sh
python3 scripts/connect-ip-local.py --docker-context colima-kata --ipv6 \
  --build --datumctl-source /Users/scotwells/repos/datum-cloud/datumctl \
  --binaries target/connect-ip-ipv6-linux-bin --keep
```

The suite checks:

- Real `datumctl connect up`, `join`, `status`, and `leave` without a project flag.
- ICMP echo, HTTP/TCP, and UDP, including empty datagrams and full 1,280-byte IP
  packets carried by QUIC DATAGRAM frames. Oversized local packets are rejected.
- Insufficient underlay MTU rejects setup without a TUN or reliable fallback.
- Underlay packet loss does not retransmit lost IP datagrams; subsequent traffic
  still works. A runtime MTU reduction closes the attachment with diagnostics.
- Source spoofing and destinations outside the approved route.
- IPv6 options and atomic fragments are rejected without breaking the session.
- Gateway readiness failure without adopting or deleting an existing interface.
- Unknown networks, revoked grants, idempotent join, and route removal on leave.
- Gateway shutdown and daemon restart cleanup, unchanged Connector identity,
  and explicit rejoin after restart.
- Packet counters, gateway metrics, and credential-redacted process logs.

## Explore the retained lab

The script prints an artifact directory containing `lab.json`. Use that path:

```sh
python3 scripts/connect-ip-local.py --shell target/CONNECT_IP_RUN/lab.json
```

The shell runs **inside the isolated Linux client**, with the local test token
and project configured. Run:

```sh
datumctl connect status
datumctl connect leave local-vpc
datumctl connect join local-vpc
datumctl connect status --output json
ip address show dcip0
ip route show dev dcip0
```

The join output shows the assigned address and approved subnet. The HTTP origin
is address `.3` in that subnet. For example, if the route is `10.201.78.0/24`:

```sh
ping -c 3 10.201.78.3
curl --noproxy '*' http://10.201.78.3:8080/
# real-connect-ip-tun-http
```

For IPv6, use the origin address printed by the harness. Bracket it in URLs:

```sh
ping -6 -c 3 fd12:3456:789a:2::3
curl --noproxy '*' 'http://[fd12:3456:789a:2::3]:8080/'
```

The example prefix is illustrative; each IPv6 lab uses its own random ULA prefix.

Use Linux `ping` for VPC addresses. `datumctl connect ping` still probes a
Connector identity. Join is ephemeral; restarting the daemon requires another
`join`. Normal Cloud enrollment remains separate from this static network grant.

Exit the shell and clean up only this lab's labeled resources:

```sh
python3 scripts/connect-ip-local.py --cleanup target/CONNECT_IP_RUN/lab.json
```

Cleanup removes the disposable containers and networks. It retains diagnostics
and build caches. Artifacts use a private directory and contain CLI output,
metrics, interface/route snapshots, and process logs. Credentials and private keys remain inside the lab
containers; do not publish a container filesystem snapshot.

## Understand the prototype boundary

The daemon accepts `--local-ip-config PATH`. See its
[configuration guide](../../../connect/connect-lib/daemon/README.md) in the
sibling Connect checkout. The gateway accepts `--ip-config PATH` with:

```json
{
  "grants": [{
    "network": "local-vpc",
    "peer": "CONNECTOR_PUBLIC_KEY",
    "client_address": "192.0.2.2/32",
    "gateway_address": "192.0.2.1/32",
    "routes": ["10.201.78.0/24"],
    "interface_name": "gip0",
    "mtu": 1280
  }]
}
```

Use actual keys and addresses. Keep approval files owner-only and operator-owned.
The daemon's local IP configuration requires `underlay_address`, the client's
explicit physical IPv4 or IPv6 address. The gateway must configure exactly one
of `ipv4_addr` or `ipv6_addr`, with its explicit underlay address, such as
`172.20.0.3:7777` or `[fd12:3456:789a:1::3]:7777`. Wildcard binds are rejected.
The daemon's gateway hints must match its underlay address family.
Local-IP mode clears implicit wildcard listeners. Bind addresses and transport
peer addresses must stay outside the overlay routes. This prevents iroh from
discovering its own TUN as a transport path and recursively tunneling itself.
The gateway accepts an empty grants list to deny all joins. Restart it after
changing grants; changes are not hot-reloaded. It installs only the client `/32` or `/128`
return route. The lab separately enables forwarding and configures the VPC
return route **inside containers**. The gateway never changes global forwarding
settings itself. A join succeeds only after gateway TUN setup completes.

`status --output json` reports attachment state, delivery mode, actual datagram IP
capacity, packet/drop counters, MTU failures, and the last error. Gateway `/metrics`
exports `iroh_gateway_ip_*` session, packet, byte, datagram, drop, protocol-error,
and MTU-error counters. Logs include peer, network,
interface, setup stage, selected direct/relay path, and handshake-time RTT.
Use `RUST_LOG=info,connect_transport=debug,iroh_gateway=debug`
for additional diagnostics. The harness retains process logs and metrics.

Each binding has one IPv4 `/32` or IPv6 `/128` address and 1–32 explicit,
canonical routes of the same family. IPv4 routes must be `/8` or narrower;
IPv6 routes must be global-unicast or ULA prefixes of `/16` or narrower.
The overlay address family is independent of the underlay family. The MTU is
1,280–1,500 bytes. The prototype rejects default routes, IP options, fragments,
and IPv6 extension headers. IPv6 packet delivery supports TCP, UDP, and ICMPv6.
It negotiates HTTP/3 Datagram support and carries IP
packets in QUIC DATAGRAM frames, with HTTP request-stream and Context ID framing.
Only address/route control capsules use the reliable HTTP/3 stream. It does not
silently fall back to reliable IP packet capsules, and rejects peers without
datagram support. Both directions need enough actual datagram capacity for the
entire configured IP MTU plus framing. Setup waits a bounded interval for QUIC
path MTU discovery; it does not force a larger initial outer MTU or assume a
1,500-byte inner packet fits on a 1,500-byte physical link. A detected capacity
reduction closes the attachment and removes its routes. After fixing the path,
run `join` again. Adaptive inner MTU changes are not implemented.

The capacity check is conservative: QUIC reports the minimum across available
paths, so probing a smaller path can also close the attachment. This prototype
does not provide transparent roaming. If the configured underlay address changes,
update the configuration and restart the endpoint. Sent-datagram counters count
packets accepted by QUIC, not confirmed delivery.

Gateway-generated ICMP
from an address outside the approved source routes is rejected; traceroute and
path-MTU discovery are not complete. Address/route assignment and the dedicated
ALPN are a Datum prototype contract, not a third-party interoperability claim.

Production work still includes NetworkBinding approval/IPAM and reconciliation,
gateway deployment and VPC routing, platform privilege separation, native macOS
and Windows adapters, dual-stack attachments, complete ICMP/MTU handling,
IPv6 extension-header support, relay/path-change validation,
and release packaging. The sibling crate paths and vendored h3 protocol patch
also need a release integration decision.
