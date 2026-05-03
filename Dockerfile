# Multi-stage build for ebpf-socks.
#
# Stage 1: compile eBPF kernel programs (bpfel-unknown-none target)
# Stage 2: compile userspace binary (embeds eBPF object from stage 1)
# Stage 3: minimal runtime image

FROM rust:1.78-slim AS ebpf-builder
RUN rustup target add bpfel-unknown-none && \
    rustup component add rust-src
WORKDIR /build
COPY . .
RUN cargo build -p ebpf-socks-ebpf \
      --target bpfel-unknown-none \
      -Z build-std=core \
      --release

FROM rust:1.78-slim AS builder
WORKDIR /build
COPY . .
COPY --from=ebpf-builder \
  /build/target/bpfel-unknown-none/release/ebpf-socks-ebpf \
  /build/target/bpfel-unknown-none/release/ebpf-socks-ebpf
RUN cargo build -p ebpf-socks --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/ebpf-socks /usr/local/bin/ebpf-socks
ENTRYPOINT ["/usr/local/bin/ebpf-socks"]
