# iroh-gateway

An HTTP/TCP proxy gateway that forwards traffic through [iroh](https://github.com/n0-computer/iroh) peer-to-peer tunnels.

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
| `--bind-addr` | `0.0.0.0` | Proxy listener bind address |
| `--port` | `8080` | Proxy listener port |
| `--metrics-addr` | _(off)_ | Prometheus metrics bind address |
| `--metrics-port` | `9090` | Prometheus metrics port |
| `--uds` | _(off)_ | Unix domain socket path (Linux/macOS only) |
| `--key-file` | `gateway_key` | Path to the secret key file |
| `--config-file` | _(none)_ | Path to a YAML config file |
| `--discovery` | `default` | iroh discovery mode: `default`, `dns`, `hybrid` |
| `--dns-origin` | _(none)_ | DNS origin for `_iroh.<id>.<origin>` lookups |
| `--dns-resolver` | _(none)_ | Custom DNS resolver address (e.g. `127.0.0.1:53535`) |

### Environment variables

| Variable | Description |
|---|---|
| `IROH_GATEWAY_KEY_FILE` | Path to the secret key file (same as `--key-file`) |
| `IROH_GATEWAY_CONFIG_FILE` | Path to the YAML config file (same as `--config-file`) |
| `IROH_GATEWAY_RELAY_URLS` | Comma or space-separated list of iroh relay URLs to use |
| `IROH_SERVICES_API_KEY` | iroh-services API key — enables net diagnostics when set |

`BUILD_IROH_GATEWAY_RELAY_URLS` can be set at compile time to bake a relay list into the binary as a fallback when the runtime variable is not set.

### Config file

Discovery settings can be provided via a YAML file instead of flags:

```yaml
discovery_mode: dns
dns_origin: iroh.example.com
dns_resolver: 127.0.0.1:53535
```

## Docker

```sh
docker run -p 8080:8080 \
  -v /path/to/data:/data \
  -e IROH_GATEWAY_KEY_FILE=/data/gateway_key \
  ghcr.io/datum-cloud/iroh-gateway
```

## Metrics

When `--metrics-port` is set, a Prometheus-compatible endpoint is available at `/metrics`. It exposes:

- Request counts by type (tunnel vs origin) and source (TCP vs UDS)
- Denied request counts by reason (missing header, invalid endpoint ID, etc.)
- HTTP error response counts by status code
- iroh connection counts (direct vs relay, current vs historical)
- Bytes sent and received through the iroh magicsock
