# System context

Who talks to `iroh-gateway`, and what it depends on to get a tunnel open.

```mermaid
C4Context
    title iroh-gateway: System Context
    Person(client, "Client", "Browser, desktop app, or CLI making a proxied request")
    System(gateway, "iroh-gateway", "Edge proxy that classifies, validates, and forwards traffic over iroh QUIC")
    System_Ext(telemetry, "Metrics consumer", "Scrapes the gateway's Prometheus-compatible metrics endpoint")
    System_Ext(listen_node, "Listen node", "Runs on the target's own network, terminates the tunnel, and forwards to the local service")
    System_Ext(discovery, "iroh discovery", "n0des (pkarr) and/or DNS, resolving an EndpointId to a dialable address")
    System_Ext(relay, "iroh relay network", "DERP-like relays providing NAT-traversal fallback")
    System_Ext(iroh_services, "iroh-services", "n0's diagnostics platform, opt-in via API key")

    Rel(client, gateway, "Sends a CONNECT or origin request", "TCP or UDS")
    Rel(gateway, listen_node, "Opens an encrypted peer-to-peer tunnel", "iroh QUIC")
    Rel(gateway, discovery, "Resolves the target EndpointId via")
    Rel(gateway, relay, "NAT-traversal fallback via")
    Rel(gateway, iroh_services, "Optionally reports diagnostics to")
    Rel(telemetry, gateway, "Scrapes", "Prometheus")
```

Discovery and relay are consulted on every cold dial to a new `EndpointId`;
once a direct QUIC path is up, the gateway holds it and skips both.
