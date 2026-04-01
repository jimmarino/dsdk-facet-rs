#!/bin/bash
set -e

# Build the test binary and load it into a Docker image for Kind

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${E2E_DIR}/.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
IMAGE_NAME="vault-test:local"

echo "======================================"
echo "Building and Loading Test Image"
echo "======================================"
echo ""

# Check if we're on macOS - if so, use full Docker build
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Detected macOS - using full Docker build for Linux compatibility..."
    cd "${WORKSPACE_ROOT}/.."

    # Use cargo-chef Dockerfile if available for faster rebuilds
    if [ -f "facet-rs/e2e/test-client/Dockerfile.chef" ]; then
        echo "Using cargo-chef for optimized build..."
        DOCKER_BUILDKIT=1 docker build --platform linux/amd64 -f facet-rs/e2e/test-client/Dockerfile.chef -t "${IMAGE_NAME}" .
    else
        docker build --platform linux/amd64 -f facet-rs/e2e/test-client/Dockerfile.full -t "${IMAGE_NAME}" .
    fi

    echo "Docker image built: ${IMAGE_NAME}"
    echo ""
else
    # Linux - use the normal binary build + lightweight Dockerfile
    # Step 1: Build the binary
    echo "Step 1: Building vault-test binary..."
    "${SCRIPT_DIR}/build-test-client.sh"
    echo ""

    # Step 2: Build Docker image
    echo "Step 2: Building Docker image..."
    cd "${E2E_DIR}/test-client"

    # Copy the binary to the Docker context
    cp "${E2E_DIR}/bin/vault-test" .

    # Build the image
    docker build -t "${IMAGE_NAME}" .

    # Clean up copied binary
    rm -f vault-test

    echo "Docker image built: ${IMAGE_NAME}"
    echo ""
fi

# Load image into Kind cluster
echo "Loading image into Kind cluster '${KIND_CLUSTER_NAME}'..."
kind load docker-image "${IMAGE_NAME}" --name "${KIND_CLUSTER_NAME}"
echo "Image loaded into Kind cluster"
echo ""

echo "======================================"
echo "Image ready in Kind cluster!"
echo "======================================"
