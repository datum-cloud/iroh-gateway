# Sequence diagrams

## Startup & endpoint bootstrap

Boot order matters: the endpoint identity and relay shortlist are settled
before either listener opens.

```mermaid
sequenceDiagram
    participant Main as main()
    participant Key as Key Manager
    participant Cfg as Config Loader
    participant EP as Endpoint Builder
    participant Relay as Relay Selector
    participant Diag as Diagnostics Client
    participant Listen as TCP / UDS listeners
    participant Metrics as Metrics HTTP server

    Main->>Key: load_or_create_key(key_file)
    alt key file exists
        Key-->>Main: SecretKey (from disk)
    else first run
        Key->>Key: generate + write to disk
        Key-->>Main: SecretKey (new)
    end
    Main->>Cfg: load flags / env / YAML
    Cfg-->>Main: GatewayConfig
    Main->>EP: build_endpoint(secret_key, config)
    opt IROH_GATEWAY_RELAY_URLS set, more than 5 relays
        EP->>Relay: GET /ping per candidate relay (800ms timeout)
        Relay-->>EP: top 5 by latency, backfilled from the rest if fewer than 5 succeed
    end
    EP-->>Main: bound iroh Endpoint
    Main->>Diag: maybe_start(endpoint)
    opt IROH_SERVICES_API_KEY set
        Diag->>Diag: connect to iroh-services
        Diag->>Diag: grant NetDiagnosticsCap::GetAny
        Diag->>Diag: host ClientHost (accepts dial-back probes)
    end
    Main->>Listen: bind TCP :port (+ UDS if --uds)
    Main->>Metrics: spawn /metrics server, if --metrics-port set
    Main->>Listen: serve loop, until SIGINT
```

## CONNECT tunnel mode

The dominant path: a `CONNECT`, upgraded to a raw byte tunnel. This is how
HTTPS and arbitrary TCP get through.

```mermaid
sequenceDiagram
    participant C as Client
    participant Front as Front proxy
    participant GW as iroh-gateway
    participant HR as HeaderResolver
    participant EP as iroh Endpoint
    participant Disc as iroh discovery
    participant Relay as iroh relay
    participant LN as Listen node
    participant Svc as Local service

    C->>Front: CONNECT api.example.com:443
    Front->>GW: CONNECT (x-iroh-endpoint-id attached)
    GW->>HR: classify(request)
    HR-->>GW: HttpRequestKind::Tunnel
    HR->>HR: extract + validate x-iroh-endpoint-id, strip Datum headers
    HR-->>GW: EndpointId
    GW->>EP: connect(endpoint_id)
    EP->>Disc: resolve dialable address
    Disc-->>EP: relay URL + direct candidates
    EP->>LN: QUIC handshake (direct attempt)
    alt direct path succeeds
        LN-->>EP: connection established, direct
    else NAT blocks the direct path
        EP->>Relay: relay-assisted holepunch
        Relay-->>LN: relayed handshake
        LN-->>EP: connection established, relay (may upgrade to direct)
    end
    GW-->>Front: 200 Connection Established
    Front-->>C: tunnel open
    loop bidirectional tunnel
        C->>GW: TLS bytes
        GW->>LN: forwarded over the iroh QUIC stream
        LN->>Svc: TCP
        Svc-->>LN: TCP response
        LN-->>GW: over the iroh QUIC stream
        GW-->>C: TLS bytes
    end
```

Once a stream to that `EndpointId` exists, later requests skip discovery and
the relay entirely. The metrics use `has_existing_peer_conn` to tell a fresh
dial from a reused one.

## Header-routed origin proxy

The header-routed path: a plain HTTP request naming its target explicitly,
rewritten and forwarded rather than tunneled raw.

```mermaid
sequenceDiagram
    participant C as Client
    participant GW as iroh-gateway
    participant HR as HeaderResolver
    participant EP as iroh Endpoint
    participant LN as Listen node
    participant Svc as Local service

    C->>GW: GET /path, x-iroh-endpoint-id, x-datum-target-host, x-datum-target-port
    GW->>HR: classify(request)
    HR-->>GW: HttpRequestKind::Origin
    HR->>HR: validate + extract EndpointId, host, port
    HR->>HR: set_absolute_http_authority(host, port)
    HR->>HR: strip Datum headers
    HR-->>GW: EndpointId
    GW->>EP: connect(endpoint_id)
    EP->>LN: QUIC stream, direct or relayed
    GW->>LN: rewritten HTTP request
    LN->>Svc: HTTP request
    Svc-->>LN: HTTP response
    LN-->>GW: HTTP response
    GW-->>C: HTTP response
```

All three Datum headers are stripped before the request leaves the gateway.
The listen node and the local service never see gateway-internal routing
details.

## Validation failure & error response

Every deny path funnels through the same templated error page, tagged with
why.

```mermaid
sequenceDiagram
    participant C as Client
    participant GW as iroh-gateway
    participant HR as HeaderResolver
    participant EW as ErrorResponseWriter
    participant M as GatewayMetrics

    C->>GW: proxy request
    GW->>HR: classify + resolve
    alt missing x-iroh-endpoint-id
        HR->>M: inc_denied_missing_header_name
        HR-->>GW: Deny::bad_request
    else invalid endpoint id
        HR->>M: inc_denied_invalid_endpoint
        HR-->>GW: Deny::bad_request
    else invalid x-datum-target-port
        HR->>M: inc_denied_invalid_target_port
        HR-->>GW: Deny::bad_request
    end
    GW->>EW: error_response(400)
    EW->>M: inc_status_code(400)
    EW->>EW: render gateway_error.html
    EW-->>C: 400 Bad Request, HTML
```

5xx responses are also tagged by whether a peer connection already existed,
via `iroh_gateway_upstream_failures_total{peer_conn_state=…}`, so a spike
right after a fresh dial reads differently from one on an established
tunnel.
