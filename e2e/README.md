# End-to-End Tests for Kubernetes Vault Integration

This directory contains E2E tests for Kubernetes-based JWT authentication with HashiCorp Vault using the sidecar pattern.

## Prerequisites

- **Docker**: Container runtime
- **Kind**: Kubernetes in Docker
- **kubectl**: Kubernetes CLI

## Quick Start

Setup cluster, deploy infrastructure, and run tests:

```bash
make all
```

## Development Workflow

```bash
cd e2e
make test-fast  # Rebuilds images and runs tests
```

### Initial Setup (one time)

```bash
cd e2e
make setup  # Sets up cluster, Vault, and builds all images
```

### Manual Builds

```bash
make build-siglet    # Full build (first time: 6+ min)
make rebuild-siglet  # Fast rebuild (~20-30s)
make build           # Build vault-test
```

## Build Performance

Builds use **cargo-chef** for dependency caching:
- **First build**: 5-6 minutes (builds all dependencies)
- **Rebuilds**: 20-30 seconds (only recompiles changed code)

No configuration needed - automatically enabled on macOS and Linux.

## Run Specific Tests

```bash
# Just Siglet tests
cargo test --package dsdk-facet-e2e-tests --features e2e siglet_e2e -- --ignored

# Single test
cargo test --package dsdk-facet-e2e-tests --features e2e test_signaling_operations -- --ignored --nocapture
```
 