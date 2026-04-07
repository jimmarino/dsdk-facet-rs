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

set -euo pipefail

NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="$(cd "${SCRIPT_DIR}/../manifests" && pwd)"

echo "======================================"
echo "Setting up consumer DID server"
echo "======================================"
echo ""

# Resolve the public key multibase to use for the DID document.
# If the Secret already exists, reuse its public key so the private key stays stable.
# If not, generate a fresh Ed25519 keypair and store it in the Secret.
if kubectl get secret consumer-did-private-key -n "${NAMESPACE}" &>/dev/null; then
    echo "consumer-did-private-key secret already exists — reusing existing keypair"
    PUBLIC_KEY_MULTIBASE=$(kubectl get secret consumer-did-private-key \
        -n "${NAMESPACE}" \
        -o "jsonpath={.data.publicKeyMultibase}" \
        | base64 -d)
else
    echo "Generating Ed25519 keypair for did:web:consumer..."

    # Outputs: "<base64-pkcs8-private-key> <multibase-public-key>"
    KEYPAIR=$(cargo run -q --manifest-path "${SCRIPT_DIR}/../../Cargo.toml" \
        -p dsdk-facet-e2e-tests --bin consumer-did-setup)

    PRIVATE_KEY_B64=$(echo "${KEYPAIR}" | cut -d' ' -f1)
    PUBLIC_KEY_MULTIBASE=$(echo "${KEYPAIR}" | cut -d' ' -f2)

    # Write private key DER bytes to a temp file so kubectl stores raw bytes in the Secret
    # (using --from-file avoids double base64 encoding that --from-literal would cause)
    TEMP_KEY=$(mktemp)
    echo "${PRIVATE_KEY_B64}" | base64 -d > "${TEMP_KEY}"

    kubectl create secret generic consumer-did-private-key \
        --from-file="privateKeyDer=${TEMP_KEY}" \
        --from-literal="publicKeyMultibase=${PUBLIC_KEY_MULTIBASE}" \
        -n "${NAMESPACE}" \
        --dry-run=client -o yaml | kubectl apply -f - --server-side --force-conflicts

    rm -f "${TEMP_KEY}"
fi

# Always (re)build the ConfigMap from the current public key and restart the pod.
# This reconciles any drift — e.g. if the ConfigMap was overwritten by old test code
# while the Secret remained intact — and guarantees nginx serves the correct key.
echo "Reconciling consumer DID document (public key: ${PUBLIC_KEY_MULTIBASE:0:20}...)"

DID_JSON=$(cat <<EOF
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:web:consumer",
  "verificationMethod": [
    {
      "id": "did:web:consumer#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:consumer",
      "publicKeyMultibase": "${PUBLIC_KEY_MULTIBASE}"
    }
  ],
  "authentication": ["did:web:consumer#key-1"],
  "assertionMethod": ["did:web:consumer#key-1"]
}
EOF
)

TEMP_DID=$(mktemp)
echo "${DID_JSON}" > "${TEMP_DID}"

kubectl create configmap consumer-did \
    --from-file="did.json=${TEMP_DID}" \
    -n "${NAMESPACE}" \
    --dry-run=client -o yaml | kubectl apply -f - --server-side --force-conflicts

rm -f "${TEMP_DID}"

# Apply Deployment and Service
kubectl apply -f "${MANIFESTS_DIR}/consumer-did.yaml" --server-side --force-conflicts

# Always restart so nginx picks up the current ConfigMap immediately rather than
# waiting for the async volume mount sync (~2 min).
kubectl rollout restart deployment/consumer-did -n "${NAMESPACE}"
echo "Waiting for consumer DID server to be ready..."
kubectl rollout status deployment/consumer-did -n "${NAMESPACE}" --timeout=60s

echo ""
echo "Consumer DID server ready: http://consumer/.well-known/did.json"
