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
use crate::util::task::TaskHandle;
use crate::vault::{PublicKeyFormat, VaultClient, VaultSigningClient};
use async_trait::async_trait;
use base64::Engine;
use bon::Builder;
use log::error;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

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

/// Inner state shared between the resolver and the background refresh task.
/// Holds only the vault client and cached keys; all scheduling and resolution
/// logic lives on `VaultVerificationKeyResolver`.
struct VaultKeyResolverState {
    pub(super) vault_client: Arc<dyn VaultSigningClient>,
    public_keys: std::sync::RwLock<HashMap<String, CachedPublicKey>>,
}

impl VaultKeyResolverState {
    fn new(vault_client: Arc<dyn VaultSigningClient>) -> Self {
        Self {
            vault_client,
            public_keys: std::sync::RwLock::new(HashMap::new()),
        }
    }

    async fn load_keys(&self) -> Result<(), JwtVerificationError> {
        let metadata = self
            .vault_client
            .get_key_metadata(PublicKeyFormat::Base64Url)
            .await
            .map_err(|e| JwtVerificationError::GeneralError(format!("Failed to get key metadata: {}", e)))?;

        let cached_keys = metadata
            .keys
            .iter()
            .enumerate()
            .map(|(i, key_b64)| {
                let kid = format!("{}-{}", metadata.key_name, i + 1);
                let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(key_b64)
                    .map_err(|e| JwtVerificationError::GeneralError(format!("Failed to decode public key: {}", e)))?;
                Ok(CachedPublicKey::builder()
                    .key(key_bytes)
                    .key_format(KeyFormat::DER)
                    .kid(kid)
                    .build())
            })
            .collect::<Result<Vec<_>, JwtVerificationError>>()?;

        self.public_keys
            .write()
            .map_err(|e| JwtVerificationError::GeneralError(format!("Failed to acquire write lock: {}", e)))?
            .extend(cached_keys.into_iter().map(Into::into));
        Ok(())
    }
}

pub struct VaultVerificationKeyResolver {
    state: Arc<VaultKeyResolverState>,
    refresh_interval: Duration,
    refresh_handle: std::sync::Mutex<Option<TaskHandle>>,
}

#[bon::bon]
impl VaultVerificationKeyResolver {
    #[builder(finish_fn = build)]
    pub fn new(
        vault_client: Arc<dyn VaultSigningClient>,
        #[builder(default = Duration::from_secs(300))] refresh_interval: Duration,
    ) -> Self {
        Self {
            state: Arc::new(VaultKeyResolverState::new(vault_client)),
            refresh_interval,
            refresh_handle: std::sync::Mutex::new(None),
        }
    }

    pub async fn initialize(&self) -> Result<(), JwtVerificationError> {
        self.state.load_keys().await?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let state = Arc::clone(&self.state);
        let interval = self.refresh_interval;
        let task_handle = tokio::spawn(async move {
            Self::refresh_loop(state, shutdown_rx, interval).await;
        });
        let mut handle_lock = self
            .refresh_handle
            .lock()
            .map_err(|e| JwtVerificationError::GeneralError(format!("Failed to acquire lock: {}", e)))?;
        *handle_lock = Some(TaskHandle::new(shutdown_tx, task_handle));

        Ok(())
    }

    async fn refresh_loop(
        state: Arc<VaultKeyResolverState>,
        mut shutdown_rx: watch::Receiver<bool>,
        interval: Duration,
    ) {
        let mut interval_timer = tokio::time::interval(interval);
        // Skip the first tick since keys were loaded during initialization
        interval_timer.tick().await;

        loop {
            tokio::select! {
                _ = interval_timer.tick() => {
                    if let Err(e) = state.load_keys().await {
                        error!("Failed to refresh Vault verification keys: {}", e);
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

#[async_trait]
impl VerificationKeyResolver for VaultVerificationKeyResolver {
    async fn resolve_key(&self, iss: &str, kid: &str) -> Result<KeyMaterial, JwtVerificationError> {
        let metadata = self
            .state
            .vault_client
            .get_key_metadata(PublicKeyFormat::Base64Url)
            .await
            .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to get key metadata: {}", e)))?;

        // kid is formatted as "{key_name}-{version}" by VaultJwtGenerator
        let version: usize = kid
            .rsplit_once('-')
            .and_then(|(_, v)| v.parse().ok())
            .ok_or_else(|| JwtVerificationError::VerificationFailed(format!("Invalid kid format: {}", kid)))?;

        let key_b64 = metadata
            .keys
            .get(version.saturating_sub(1))
            .ok_or_else(|| JwtVerificationError::VerificationFailed(format!("Key version {} not found", version)))?;

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

#[derive(Builder)]
pub struct CachedPublicKey {
    #[builder(default = KeyFormat::DER)]
    pub key_format: KeyFormat,

    pub key: Vec<u8>,

    #[builder(into)]
    pub kid: String,
}

impl From<CachedPublicKey> for (String, CachedPublicKey) {
    fn from(key: CachedPublicKey) -> Self {
        (key.kid.clone(), key)
    }
}
