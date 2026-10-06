# Release build environment (Client Design §9.1, OPS-02; M7). Debian 13 is the oldest
# supported platform, so a GUI linked here runs on Debian 13, Tails 7, Ubuntu 24.04+ and
# newer. The CLI and the relay are built static-pie and run anywhere.
#
#   docker build -t aska-release release/
#   docker run --rm -v "$PWD":/src -w /src aska-release scripts/release.sh v0.1.0-alpha
#
# Signing is done OUTSIDE the container by the release owner (scripts/release.sh --sign).
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git build-essential pkg-config \
      libgtk-4-dev libadwaita-1-dev \
      python3 minisign \
    && rm -rf /var/lib/apt/lists/*
# Pinned toolchain — must equal `channel` in rust-toolchain.toml (release.sh checks).
ARG RUST_VERSION=1.95.0
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION"
ENV PATH=/root/.cargo/bin:$PATH \
    CARGO_NET_RETRY=5 \
    CARGO_INCREMENTAL=0
WORKDIR /src
