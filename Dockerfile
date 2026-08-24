# Multi-stage build for heimdall.
#
# Stage 1: compile userspace with the versioned, locally verified eBPF object.
# Stage 2: minimal runtime image.

FROM rust:1.95-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build -p heimdall-egress --locked --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/heimdall /usr/local/bin/heimdall
ENTRYPOINT ["/usr/local/bin/heimdall"]
