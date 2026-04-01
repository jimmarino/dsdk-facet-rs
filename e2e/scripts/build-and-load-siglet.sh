#!/bin/bash

#  Copyright (c) 2026 Metaform Systems, Inc
#
#  This program and the accompanying materials are made available under the
#  terms of the Apache License, Version 2.0 which is available at
#  https://www.apache.org/licenses/LICENSE-2.0
#
#  SPDX-License-Identifier: Apache-2.0
#
#  Contributors:
#       Metaform Systems, Inc. - initial API and implementation

set -e

# Build the Siglet binary and load it into a Docker image for Kind

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${E2E_DIR}/.." && pwd)"
FACET_RS_DIR="${WORKSPACE_ROOT}"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
IMAGE_NAME="siglet:local"

# Build mode: "full" or "iterative" (default: full)
BUILD_MODE="${SIGLET_BUILD_MODE:-full}"

echo "======================================"
echo "Building and Loading Siglet Image"
echo "Build mode: ${BUILD_MODE}"
echo "======================================"
echo ""

if [ "$BUILD_MODE" = "iterative" ]; then
    # Iterative build: cargo build + Dockerfile.local
    # Note: Only works on Linux. On macOS, falls back to full build.
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "WARNING: Iterative build mode not supported on macOS (wrong architecture)."
        echo "Falling back to full build mode..."
        echo ""
        BUILD_MODE="full"
    fi
fi

if [ "$BUILD_MODE" = "iterative" ]; then
    # Iterative build: cargo build + Dockerfile.local (Linux only)
    echo "Step 1: Building Siglet binary..."
    cd "$FACET_RS_DIR"
    cargo build --release --bin siglet
    echo ""

    echo "Step 2: Building Siglet Docker image (iterative mode)..."
    docker build -f siglet/Dockerfile.local -t "${IMAGE_NAME}" .
    echo "Docker image built: ${IMAGE_NAME}"
    echo ""
fi

if [ "$BUILD_MODE" = "full" ]; then
    # Full build: Dockerfile (multi-stage)
    cd "${WORKSPACE_ROOT}/.."

    # Use cargo-chef Dockerfile if available for faster rebuilds
    if [ -f "facet-rs/siglet/Dockerfile.chef" ]; then
        echo "Building Siglet Docker image (full build with cargo-chef)..."
        DOCKER_BUILDKIT=1 docker build --platform linux/amd64 -f facet-rs/siglet/Dockerfile.chef -t "${IMAGE_NAME}" .
    else
        echo "Building Siglet Docker image (full build)..."
        docker build --platform linux/amd64 -f facet-rs/siglet/Dockerfile -t "${IMAGE_NAME}" .
    fi

    echo "Docker image built: ${IMAGE_NAME}"
    echo ""
fi

# Load image into Kind cluster
echo "Loading image into Kind cluster '${KIND_CLUSTER_NAME}'..."
kind load docker-image "${IMAGE_NAME}" --name "${KIND_CLUSTER_NAME}"
echo "Image loaded into Kind cluster"
echo ""

echo "======================================"
echo "Siglet image ready in Kind cluster!"
echo "======================================"
