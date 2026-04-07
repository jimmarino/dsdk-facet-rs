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
    /// PKCS#8 DER-encoded private key for `did:web:consumer#key-1`.
    /// Use with `LocalJwtGenerator` to sign tokens as the consumer.
    pub private_key_der: Vec<u8>,
}

/// Returns the consumer DID doc provisioned by `setup.sh`.
///
/// Reads the PKCS#8 DER private key from the `consumer-did-private-key` Secret.
/// The corresponding public key is already published in the consumer-did ConfigMap
/// (served by nginx at `http://consumer/.well-known/did.json`) — both were written
/// by `setup.sh` and are stable for the lifetime of the cluster.
///
/// This function is idempotent and thread-safe.
pub async fn ensure_consumer_did() -> Result<&'static ConsumerDidDeployment> {
    CONSUMER_DID
        .get_or_try_init(|| async {
            crate::utils::verify_e2e_setup().await?;

            let private_key_der = read_secret_bytes(E2E_NAMESPACE, "consumer-did-private-key", "privateKeyDer")
                .context(
                    "Failed to read consumer DID private key. \
                     Run 'cd e2e && ./scripts/setup.sh' to provision the consumer DID server.",
                )?;

            Ok(ConsumerDidDeployment { private_key_der })
        })
        .await
}
