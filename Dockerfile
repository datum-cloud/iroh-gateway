FROM rust:1.98-bookworm AS builder

ARG CONNECT_REV=736f6070ca2d6a54f4a4ad4bf1e8f35a534cb5ab

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir /connect \
  && git -C /connect init \
  && git -C /connect remote add origin https://github.com/datum-cloud/connect.git \
  && git -C /connect fetch --depth 1 origin "${CONNECT_REV}" \
  && git -C /connect checkout --detach FETCH_HEAD

WORKDIR /app

COPY . .

ARG BUILD_IROH_SERVICES_API_KEY
ENV BUILD_IROH_SERVICES_API_KEY=${BUILD_IROH_SERVICES_API_KEY}

RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd -u 65532 -r -s /usr/sbin/nologin iroh-gateway

COPY --from=builder /app/target/release/iroh-gateway /usr/local/bin/iroh-gateway

ENTRYPOINT ["/usr/local/bin/iroh-gateway"]
