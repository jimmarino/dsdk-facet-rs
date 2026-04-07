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

use crate::context::ParticipantContext;
use crate::jwt::{
    JwtGenerationError, JwtVerificationError, KeyFormat, KeyMaterial, SigningKeyResolver, VerificationKeyResolver,
};
use crate::vault::{PublicKeyFormat, VaultClient, VaultSigningClient};
use async_trait::async_trait;
use base64::Engine;
use bon::Builder;
use std::sync::Arc;

#[derive(Builder)]
pub struct StaticVerificationKeyResolver {
    pub key: Vec<u8>,
    #[builder(default = KeyFormat::PEM)]
    key_format: KeyFormat,
}

#[async_trait]
impl VerificationKeyResolver for StaticVerificationKeyResolver {
    async fn resolve_key(&self, iss: &str, kid: &str) -> Result<KeyMaterial, JwtVerificationError> {
        Ok(KeyMaterial::builder()
            .key(self.key.clone())
            .key_format(self.key_format)
            .iss(iss)
            .kid(kid)
            .build())
    }
}

#[derive(Builder)]
pub struct StaticSigningKeyResolver {
    pub key: Vec<u8>,

    #[builder(into)]
    pub iss: String,

    #[builder(into)]
    pub kid: String,

    #[builder(default = KeyFormat::PEM)]
    key_format: KeyFormat,
}

#[async_trait]
impl SigningKeyResolver for StaticSigningKeyResolver {
    async fn resolve_key(&self, _: &ParticipantContext) -> Result<KeyMaterial, JwtGenerationError> {
        Ok(KeyMaterial::builder()
            .key_format(self.key_format)
            .key(self.key.clone())
            .iss(self.iss.clone())
            .kid(self.kid.clone())
            .build())
    }
}

/// A signing key resolver that retrieves keys from a VaultClient.
///
/// This resolver delegates to a VaultClient to fetch signing keys at runtime.
/// The vault stores a JSON-serialized `SigningKeyRecord` containing the
/// private key, its identifier (kid), and key format.
/// The issuer (iss) is derived from the participant context's identifier field.
#[derive(Builder)]
pub struct VaultSigningKeyResolver {
    /// The vault client to use for resolving keys
    vault_client: Arc<dyn VaultClient>,

    /// Base path in the vault where keys are stored
    #[builder(into)]
    base_path: String,
}

#[async_trait]
impl SigningKeyResolver for VaultSigningKeyResolver {
    async fn resolve_key(&self, participant_context: &ParticipantContext) -> Result<KeyMaterial, JwtGenerationError> {
        let json_str = self
            .vault_client
            .resolve_secret(participant_context, &self.base_path)
            .await
            .map_err(|e| {
                JwtGenerationError::GenerationError(format!("Failed to resolve signing key from vault: {}", e))
            })?;

        let record: SigningKeyRecord = serde_json::from_str(&json_str).map_err(|e| {
            JwtGenerationError::GenerationError(format!("Failed to deserialize SigningKeyRecord: {}", e))
        })?;

        Ok(KeyMaterial::builder()
            .key_format(record.key_format)
            .key(record.private_key.into_bytes())
            .iss(participant_context.identifier.clone())
            .kid(record.kid)
            .build())
    }
}

/// A record containing a private signing key and its identifier.
///
/// This structure is stored in the vault as JSON.
#[derive(Debug, Clone, Builder, serde::Serialize, serde::Deserialize)]
pub struct SigningKeyRecord {
    /// The private key in the configured format (PEM or DER)
    #[builder(into)]
    pub private_key: String,

    /// The key identifier (kid)
    #[builder(into)]
    pub kid: String,

    /// The format of the private key (PEM or DER)
    #[builder(default = KeyFormat::PEM)]
    pub key_format: KeyFormat,
}

#[derive(Builder)]
pub struct VaultVerificationKeyResolver {
    /// The vault client to use for resolving keys
    vault_client: Arc<dyn VaultSigningClient>,
}

#[async_trait]
impl VerificationKeyResolver for VaultVerificationKeyResolver {
    async fn resolve_key(&self, iss: &str, kid: &str) -> Result<KeyMaterial, JwtVerificationError> {
        let metadata = self
            .vault_client
            .get_key_metadata(PublicKeyFormat::Base64Url)
            .await
            .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to get key metadata: {}", e)))?;

        // kid is formatted as "{key_name}-{version}" by VaultJwtGenerator
        let version: usize = kid
            .rsplit_once('-')
            .and_then(|(_, v)| v.parse().ok())
            .ok_or_else(|| JwtVerificationError::VerificationFailed(format!("Invalid kid format: {}", kid)))?;

        let key_b64 = metadata.keys.get(version.saturating_sub(1)).ok_or_else(|| {
            JwtVerificationError::VerificationFailed(format!("Key version {} not found", version))
        })?;

        let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key_b64)
            .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to decode public key: {}", e)))?;

        Ok(KeyMaterial::builder()
            .key(key_bytes)
            .key_format(KeyFormat::DER)
            .iss(iss)
            .kid(kid)
            .build())
    }
}
