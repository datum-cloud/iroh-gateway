# Local Linux-only CONNECT-IP lab. This is not a release image.
FROM rust:1.94-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping python3 curl ca-certificates pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
