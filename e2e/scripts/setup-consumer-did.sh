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

VAULT_TOKEN="root"
VAULT_POD=$(kubectl get pod -n "${NAMESPACE}" -l app=vault -o jsonpath='{.items[0].metadata.name}')

vault_cmd() {
    kubectl exec -n "${NAMESPACE}" "${VAULT_POD}" -- env VAULT_TOKEN="${VAULT_TOKEN}" vault "$@"
}

echo "======================================"
echo "Setting up consumer DID server"
echo "======================================"
echo ""

# Provision (or reuse) the per-PC Vault transit signing key and its Kubernetes Secret.
# This is idempotent — if the secret already exists we reuse it; otherwise we create
# the transit key and export the public key. Running this here (rather than only in
# configure-vault.sh) makes `make test-fast` and `make setup-consumer-did` self-contained.

TRANSIT_KEY_NAME="client-signing-test-participant-context"
KEY_ID="client-signing-test-participant-context-1"

if kubectl get secret consumer-pc-signing-key -n "${NAMESPACE}" &>/dev/null; then
    echo "consumer-pc-signing-key secret already exists — reusing existing key"
    PUBLIC_KEY_MULTIBASE=$(kubectl get secret consumer-pc-signing-key \
        -n "${NAMESPACE}" \
        -o "jsonpath={.data.publicKeyMultibase}" \
        | base64 -d)
    KEY_ID=$(kubectl get secret consumer-pc-signing-key \
        -n "${NAMESPACE}" \
        -o "jsonpath={.data.keyId}" \
        | base64 -d)
else
    echo "Creating consumer PC transit signing key in Vault..."
    vault_cmd write -f "transit/keys/${TRANSIT_KEY_NAME}" type=ed25519 2>/dev/null && \
        echo "Transit key created" || echo "Transit key already exists"

    echo "Exporting public key..."
    CONSUMER_PC_PUBKEY_B64=$(kubectl exec -n "${NAMESPACE}" "${VAULT_POD}" -- \
        env VAULT_TOKEN="${VAULT_TOKEN}" vault read -format=json \
        "transit/keys/${TRANSIT_KEY_NAME}" | \
        python3 -c "
import sys, json
data = json.load(sys.stdin)
latest = str(data['data']['latest_version'])
print(data['data']['keys'][latest]['public_key'], end='')
")

    PUBLIC_KEY_MULTIBASE=$(echo "${CONSUMER_PC_PUBKEY_B64}" | python3 -c "
import sys, base64

BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(data):
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(BASE58[r])
    result.reverse()
    pad = len(data) - len(data.lstrip(b'\x00'))
    return '1' * pad + ''.join(result)

raw = base64.b64decode(sys.stdin.read().strip())
prefixed = bytes([0xed, 0x01]) + raw
print('z' + base58_encode(prefixed), end='')
")

    kubectl create secret generic consumer-pc-signing-key \
        --from-literal="publicKeyMultibase=${PUBLIC_KEY_MULTIBASE}" \
        --from-literal="keyId=${KEY_ID}" \
        -n "${NAMESPACE}" \
        --dry-run=client -o yaml | kubectl apply -f - --server-side --force-conflicts

    echo "consumer-pc-signing-key secret created"
fi

echo "Consumer PC signing key: id=${KEY_ID}, multibase=${PUBLIC_KEY_MULTIBASE:0:20}..."

# Build the DID document. The verification method id uses the kid as the fragment,
# matching how VaultJwtGenerator sets kid and DidWebVerificationKeyResolver resolves it:
#   kid = "client-signing-test-participant-context-1"
#   → looks for vm.id ending in "#client-signing-test-participant-context-1"
DID_JSON=$(cat <<EOF
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:web:consumer",
  "verificationMethod": [
    {
      "id": "did:web:consumer#${KEY_ID}",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:consumer",
      "publicKeyMultibase": "${PUBLIC_KEY_MULTIBASE}"
    }
  ],
  "authentication": ["did:web:consumer#${KEY_ID}"],
  "assertionMethod": ["did:web:consumer#${KEY_ID}"]
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
echo "  Verification method: did:web:consumer#${KEY_ID}"
