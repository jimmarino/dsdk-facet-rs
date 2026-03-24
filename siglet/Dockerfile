# Build stage
# NOTE: This Dockerfile should be built from the parent directory with both facet-rs and dataplane-sdk-rust:
# cd /Users/jim/workspace/rust && docker build --platform linux/amd64 -f facet-rs/siglet/Dockerfile -t siglet:local .

FROM --platform=linux/amd64 rust:bookworm AS builder

# Install cmake (required for facet-proxy/S3 functionality)
RUN apt-get update && \
    apt-get install -y cmake && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy dataplane-sdk-rust dependency
COPY dataplane-sdk-rust /build/dataplane-sdk-rust

# Copy facet-rs workspace (all members to satisfy workspace dependencies)
COPY facet-rs/Cargo.toml facet-rs/Cargo.lock ./
COPY facet-rs/crates ./crates
COPY facet-rs/siglet ./siglet
COPY facet-rs/e2e ./e2e

# Create symlink to make relative paths work (siglet references ../../dataplane-sdk-rust)
RUN ln -s /build/dataplane-sdk-rust /dataplane-sdk-rust

# Build the siglet binary in release mode
RUN cargo build --release --bin siglet

# Runtime stage
FROM --platform=linux/amd64 debian:bookworm-slim

# Install runtime dependencies (wget needed for health checks in e2e tests)
RUN apt-get update && \
    apt-get install -y ca-certificates curl wget && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 siglet

# Copy the binary from builder
COPY --from=builder /build/target/release/siglet /usr/local/bin/siglet

# Set ownership
RUN chown siglet:siglet /usr/local/bin/siglet

# Switch to non-root user
USER siglet

# Set environment variables
ENV RUST_LOG=info

# Expose Siglet API port (health/status)
EXPOSE 8080

# Expose Signaling API port (DataPlane protocol)
EXPOSE 8081

# Health check using the /health endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["siglet"]
