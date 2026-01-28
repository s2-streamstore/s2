# Build stage
FROM rust:latest AS builder

WORKDIR /build

# Use Docker BuildKit cache mounts for faster builds
RUN --mount=type=bind,source=api,target=/build/api \
    --mount=type=bind,source=common,target=/build/common \
    --mount=type=bind,source=lite,target=/build/lite \
    --mount=type=bind,source=cli,target=/build/cli \
    --mount=type=bind,source=Cargo.toml,target=/build/Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=/build/Cargo.lock \
    --mount=type=cache,id=s2-rust,sharing=locked,target=/build/target \
    --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,target=/usr/local/cargo/git \
    cargo build --locked --release --package s2-cli --bin s2

# Copy the binary from the cache volume
RUN --mount=type=cache,id=s2-rust,sharing=locked,target=/build/target \
    mkdir -p /output && \
    cp /build/target/release/s2 /output/s2

# Debug runtime - ubuntu with shell access
# Build with: docker build --target debug .
FROM ubuntu:latest AS debug

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /output/s2 /app/s2

ENTRYPOINT ["./s2"]

# Production runtime (default) - minimal distroless image
FROM gcr.io/distroless/cc-debian13 AS runtime

WORKDIR /app

COPY --from=builder /output/s2 /app/s2

ENTRYPOINT ["./s2"]
