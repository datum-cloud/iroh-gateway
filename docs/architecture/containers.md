# Container view

`iroh-gateway` is a single binary, but it's rarely deployed alone: something
has to terminate public TLS and hand it traffic, and something on the other
side has to be listening on the target `EndpointId`.

```mermaid
C4Container
    title iroh-gateway: Container view
    Person(client, "Client")
    Container_Ext(front_proxy, "Front proxy", "e.g. Envoy (Gateway API)", "Terminates public TLS and forwards CONNECT or origin requests to iroh-gateway")
    Container(gateway, "iroh-gateway", "Rust, axum, hyper", "Classifies, validates, and forwards proxy traffic over iroh QUIC")
    ContainerDb(keyfile, "gateway_key", "file on disk", "Persists the stable iroh EndpointId secret key across restarts")
    Container_Ext(listen_node, "Listen node", "iroh endpoint", "Runs on the target's network and terminates the tunnel")
    Container_Ext(local_service, "Local service", "any", "The private backend the client is actually trying to reach")
    System_Ext(relay, "iroh relay network")
    System_Ext(discovery, "iroh discovery")
    System_Ext(iroh_services, "iroh-services")
    Container_Ext(telemetry, "Metrics consumer", "Prometheus scraper", "Collects the gateway's metrics")

    Rel(client, front_proxy, "HTTPS", "TLS")
    Rel(front_proxy, gateway, "Forwards a CONNECT or origin request", "TCP or UDS")
    Rel(gateway, keyfile, "Loads, or creates on first run")
    Rel(gateway, listen_node, "Tunnels to", "iroh QUIC")
    Rel(listen_node, local_service, "Forwards to", "TCP")
    Rel(gateway, relay, "NAT-traversal fallback via")
    Rel(gateway, discovery, "Resolves EndpointId via")
    Rel(gateway, iroh_services, "Optionally reports diagnostics to")
    Rel(telemetry, gateway, "Scrapes", "HTTP /metrics")
```

## Deployment notes

- **Identity is disk-persisted.** `gateway_key` is generated once and read on
  every subsequent start; losing or rotating that file changes the gateway's
  iroh identity. Mount it on a path that survives restarts.
- **UDS is a common front-proxy transport.** Pairing `iroh-gateway` with a
  TLS-terminating front proxy over a Unix domain socket, rather than a pod- or
  host-network TCP hop, keeps the proxy hop off the network and out of scope
  for network-level ACLs. Datum Connect's own deployment does this.
- **The trust boundary is external.** `iroh-gateway` does not authenticate
  `x-iroh-endpoint-id`, `x-datum-target-host`, or `x-datum-target-port` itself
  (see [../README.md](./README.md#trust-model)). Whatever fronts it, and
  whatever network policy controls reachability of its listener(s), *is* the
  access-control layer.
- **`--discovery hybrid`** is useful when migrating between discovery
  backends (e.g. a custom DNS origin) without breaking clients that only
  publish to the default (n0des) discovery.
