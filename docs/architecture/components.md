# Component view

Inside the single binary. Almost everything is wiring around two crates:
[`iroh`](https://docs.rs/iroh) (the endpoint, discovery, and relay machinery)
and [`iroh-proxy-utils`](https://docs.rs/iroh-proxy-utils) (the HTTP proxy
state machine). `iroh-gateway`'s own code is the config, key handling, header
policy, and metrics glue around them.

```mermaid
C4Component
    title iroh-gateway: Component view
    Container_Boundary(gw, "iroh-gateway process") {
        Component(cli, "Config Loader", "clap + serde_yml", "Parses flags / env / YAML; resolves discovery mode and relay settings")
        Component(keymgr, "Key Manager", "iroh::SecretKey", "Loads or generates the persistent EndpointId secret key")
        Component(relaysel, "Startup Relay Selector", "reqwest", "Probes candidate relay /ping latency, keeps the fastest 5")
        Component(epbuilder, "Endpoint Builder", "iroh::Endpoint::builder", "Builds the bound iroh Endpoint: relay mode, discovery, bind addrs")
        Component(proxy, "DownstreamProxy", "iroh-proxy-utils", "Owns the TCP / UDS accept loop and HTTP proxy state machine")
        Component(resolver, "HeaderResolver", "RequestHandler impl", "Classifies Tunnel vs Origin, validates Datum headers, resolves EndpointId")
        Component(errwriter, "ErrorResponseWriter", "askama template", "Renders the branded error page; records status-code metrics")
        Component(metrics, "GatewayMetrics", "atomics + iroh-metrics", "Counters: request kind/source, denials, status codes, QUIC bytes/paths")
        Component(metricshttp, "Metrics HTTP server", "axum", "Serves Prometheus text exposition on /metrics")
        Component(diag, "Diagnostics client", "iroh-services", "Optional: connects to iroh-services, grants NetDiagnosticsCap, hosts dial-back")
    }
    Rel(cli, epbuilder, "Configures")
    Rel(cli, relaysel, "Triggers at startup")
    Rel(relaysel, epbuilder, "Supplies the shortlisted RelayMap")
    Rel(keymgr, epbuilder, "Supplies the SecretKey")
    Rel(epbuilder, proxy, "Provides the bound Endpoint")
    Rel(epbuilder, diag, "Provides the Endpoint to")
    Rel(proxy, resolver, "Delegates request classification to")
    Rel(proxy, errwriter, "Delegates error rendering to")
    Rel(resolver, metrics, "Increments")
    Rel(errwriter, metrics, "Increments")
    Rel(epbuilder, metricshttp, "Supplies the Endpoint's own QUIC socket metrics to")
    Rel(proxy, metricshttp, "Supplies its DownstreamMetrics registry to")
    Rel(metricshttp, metrics, "Reads GatewayMetrics on scrape")
```

`HeaderResolver` and `ErrorResponseWriter` are the only two pieces of
routing-specific policy in the whole process. Everything on either side of
them is generic iroh/proxy plumbing, so most behavioral changes to *what*
gets proxied and *how it's validated* live in `src/gateway.rs`
(`HeaderResolver::handle_request`), not in `src/endpoint.rs`.

The relay probe (`select_best_relays_for_startup`) only runs when the
configured relay list exceeds five URLs, and only at startup. It is not
re-evaluated while the process is running, so a relay that degrades
mid-uptime isn't dropped from the shortlist until restart.

`/metrics` is an aggregation point, not just a counter dump: each scrape
merges `iroh-gateway`'s own `GatewayMetrics`, the iroh `Endpoint`'s built-in
QUIC/socket counters, and `DownstreamProxy`'s `DownstreamMetrics` registry
into one response.
