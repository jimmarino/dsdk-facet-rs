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

use super::{RenewableTokenEntry, RenewableTokenStore};
use crate::context::ParticipantContext;
use crate::token::TokenError;
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// In-memory renewable token store for testing and development.
///
/// Tokens are isolated by the participant context. Not suitable for production use.
pub struct MemoryRenewableTokenStore {
    // Primary storage indexed by (participant_id, hashed_refresh_token)
    entries_by_hash: RwLock<HashMap<(String, String), RenewableTokenEntry>>,
    // Secondary index by (participant_id, id) for id-based lookups
    entries_by_id: RwLock<HashMap<(String, String), RenewableTokenEntry>>,
}

impl MemoryRenewableTokenStore {
    pub fn new() -> Self {
        Self {
            entries_by_hash: RwLock::new(HashMap::new()),
            entries_by_id: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryRenewableTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RenewableTokenStore for MemoryRenewableTokenStore {
    async fn save(
        &self,
        participant_context: &ParticipantContext,
        entry: RenewableTokenEntry,
    ) -> Result<(), TokenError> {
        let hash_key = (participant_context.id.clone(), entry.hashed_refresh_token.clone());
        let id_key = (participant_context.id.clone(), entry.id.clone());

        self.entries_by_hash.write().await.insert(hash_key, entry.clone());
        self.entries_by_id.write().await.insert(id_key, entry);
        Ok(())
    }

    async fn find_by_renewal(
        &self,
        participant_context: &ParticipantContext,
        hash: &str,
    ) -> Result<RenewableTokenEntry, TokenError> {
        let tokens = self.entries_by_hash.read().await;
        let key = (participant_context.id.clone(), hash.to_string());

        let entry = tokens.get(&key).ok_or_else(|| TokenError::token_not_found(hash))?;

        Ok(entry.clone())
    }

    async fn find_by_id(
        &self,
        participant_context: &ParticipantContext,
        id: &str,
    ) -> Result<RenewableTokenEntry, TokenError> {
        let tokens = self.entries_by_id.read().await;
        let key = (participant_context.id.clone(), id.to_string());

        let entry = tokens.get(&key).ok_or_else(|| TokenError::token_not_found(id))?;

        Ok(entry.clone())
    }

    async fn update(
        &self,
        participant_context: &ParticipantContext,
        old_hash: &str,
        new_entry: RenewableTokenEntry,
    ) -> Result<(), TokenError> {
        let mut tokens_by_hash = self.entries_by_hash.write().await;
        let mut tokens_by_id = self.entries_by_id.write().await;

        let old_hash_key = (participant_context.id.clone(), old_hash.to_string());

        // Remove the old entry from both indices
        let old_entry = tokens_by_hash
            .remove(&old_hash_key)
            .ok_or_else(|| TokenError::token_not_found(old_hash))?;

        let old_id_key = (participant_context.id.clone(), old_entry.id.clone());
        tokens_by_id.remove(&old_id_key);

        // Insert the new entry in both indices
        let new_hash_key = (participant_context.id.clone(), new_entry.hashed_refresh_token.clone());
        let new_id_key = (participant_context.id.clone(), new_entry.id.clone());

        tokens_by_hash.insert(new_hash_key, new_entry.clone());
        tokens_by_id.insert(new_id_key, new_entry);

        Ok(())
    }
}
