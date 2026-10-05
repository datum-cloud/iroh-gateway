# Architecture

`iroh-gateway` is an HTTP/TCP proxy that sits at the edge of a network and
forwards traffic into [iroh](https://github.com/n0-computer/iroh)
peer-to-peer tunnels. Two request shapes arrive at the same listener:

```
client
  │  CONNECT api.example.com:443          ── or ──   GET /path
  │                                                    x-iroh-endpoint-id: 3xJ9…
  ▼                                                    x-datum-target-host: 10.0.4.2
iroh-gateway  ───────────────────  iroh tunnel (QUIC)  ───────────────────►  listen node
                                   direct, or relayed for NAT traversal          │
                                                                                  ▼
                                                                           local service
```

- **CONNECT (tunnel mode).** The client sends `CONNECT` and the gateway
  upgrades to a raw TCP tunnel. Used for HTTPS and arbitrary TCP traffic.
- **Origin (proxy mode).** The client sends a plain HTTP request with
  `x-iroh-endpoint-id`, `x-datum-target-host`, and `x-datum-target-port`
  headers. The gateway rewrites the request and forwards it upstream.

Both paths resolve to the same thing: the target's iroh `EndpointId`, dialed
over QUIC, either directly or via a relay when a direct path can't be
established.

## Diagrams

C4 model, one level per document:

- [System context](./context.md) — who talks to the gateway, and what it
  depends on to open a tunnel
- [Container view](./containers.md) — the gateway alongside the process(es)
  that front and depend on it
- [Component view](./components.md) — inside the single binary
- [Sequence diagrams](./sequences.md) — startup, both request modes, and the
  deny/error path

All diagrams are [Mermaid](https://mermaid.js.org/), rendered inline by
GitHub with no build step needed. Keep them next to the code they describe
and update them in the same PR as a behavioral change.

## Trust model

`iroh-gateway` performs no authentication of `x-iroh-endpoint-id`,
`x-datum-target-host`, or `x-datum-target-port` itself. It trusts whatever
sets them. That is only safe when the proxy listener (TCP and/or UDS) is not
reachable by untrusted callers; enforcing that is the deploying operator's
responsibility, not the binary's. See the [container view](./containers.md)
for where that boundary typically sits.
