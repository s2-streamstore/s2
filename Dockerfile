FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig binutils

WORKDIR /build

# Copy source
COPY . .

# Build statically linked with optimizations
ENV OPENSSL_STATIC=1
ENV RUSTFLAGS="-C strip=symbols"
RUN cargo build --release --package s2-lite --bin server && \
    strip /build/target/release/server

# Minimal runtime
FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /build/target/release/server /app/s2-lite

EXPOSE 80

ENTRYPOINT ["/app/s2-lite", "--port", "80", "--local-path", "/data"]
