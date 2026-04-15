FROM rust:1.89-bookworm AS builder

WORKDIR /app

COPY . .

ARG BUILD_IROH_SERVICES_API_KEY
ENV BUILD_IROH_SERVICES_API_KEY=${BUILD_IROH_SERVICES_API_KEY}

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd -u 65532 -r -s /usr/sbin/nologin iroh-gateway

COPY --from=builder /app/target/release/iroh-gateway /usr/local/bin/iroh-gateway

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/iroh-gateway"]
