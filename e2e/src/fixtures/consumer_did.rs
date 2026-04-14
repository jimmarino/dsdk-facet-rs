//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

use crate::utils::*;
use anyhow::{Context, Result};
use tokio::sync::OnceCell;

static CONSUMER_DID: OnceCell<ConsumerDidDeployment> = OnceCell::const_new();

/// Key material for the consumer DID, provisioned by `setup.sh` and stored in the cluster.
pub struct ConsumerDidDeployment {
    /// The JWT `kid` that identifies the consumer's per-PC Vault transit signing key.
    /// Matches the verification method fragment in the consumer DID document.
    pub pc_signing_key_id: String,

    /// The multibase-encoded public key of the consumer's per-PC Vault transit signing key.
    /// Used for pre-flight DID document verification.
    pub pc_signing_key_multibase: String,
}

/// Returns the consumer DID deployment info provisioned by `setup.sh`.
///
/// Reads the per-PC signing key metadata from the `consumer-pc-signing-key` Secret,
/// which is populated by `configure-vault.sh` when it creates the transit key
/// `client-signing-test-participant-context` in Vault.
///
/// The corresponding public key is published in the consumer DID document
/// (served at `http://consumer/.well-known/did.json`) — both were written by
/// `setup.sh` and are stable for the lifetime of the cluster.
///
/// This function is idempotent and thread-safe.
pub async fn ensure_consumer_did() -> Result<&'static ConsumerDidDeployment> {
    CONSUMER_DID
        .get_or_try_init(|| async {
            verify_e2e_setup().await?;

            let key_id_bytes = read_secret_bytes(E2E_NAMESPACE, "consumer-pc-signing-key", "keyId").context(
                "Failed to read consumer PC signing key ID. \
                     Run 'cd e2e && ./scripts/setup.sh' to provision the consumer DID server.",
            )?;
            let pc_signing_key_id = String::from_utf8(key_id_bytes).context("Non-UTF8 key ID in secret")?;

            let multibase_bytes = read_secret_bytes(E2E_NAMESPACE, "consumer-pc-signing-key", "publicKeyMultibase")
                .context(
                    "Failed to read consumer PC signing key public key. \
                     Run 'cd e2e && ./scripts/setup.sh' to provision the consumer DID server.",
                )?;
            let pc_signing_key_multibase =
                String::from_utf8(multibase_bytes).context("Non-UTF8 public key multibase in secret")?;

            Ok(ConsumerDidDeployment {
                pc_signing_key_id,
                pc_signing_key_multibase,
            })
        })
        .await
}
