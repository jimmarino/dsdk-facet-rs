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

/// Inner storage structure holding all token indices.
struct InnerStore {
    /// Primary storage indexed by (participant_id, hashed_refresh_token)
    entries_by_hash: HashMap<(String, String), RenewableTokenEntry>,
    /// Secondary index by (participant_id, id) for id-based lookups
    entries_by_id: HashMap<(String, String), RenewableTokenEntry>,
    /// Secondary index by (participant_id, flow_id) for flow_id-based lookups
    entries_by_flow_id: HashMap<(String, String), RenewableTokenEntry>,
}

/// In-memory renewable token store for testing and development.
///
/// Tokens are isolated by the participant context. Not suitable for production use.
/// Uses a single lock to protect all indices, ensuring atomic updates and simplicity.
pub struct MemoryRenewableTokenStore {
    store: RwLock<InnerStore>,
}

impl MemoryRenewableTokenStore {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(InnerStore {
                entries_by_hash: HashMap::new(),
                entries_by_id: HashMap::new(),
                entries_by_flow_id: HashMap::new(),
            }),
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
        let flow_id_key = (participant_context.id.clone(), entry.flow_id.clone());

        let mut store = self.store.write().await;
        store.entries_by_hash.insert(hash_key, entry.clone());
        store.entries_by_id.insert(id_key, entry.clone());
        store.entries_by_flow_id.insert(flow_id_key, entry);
        Ok(())
    }

    async fn find_by_renewal(
        &self,
        participant_context: &ParticipantContext,
        hash: &str,
    ) -> Result<RenewableTokenEntry, TokenError> {
        let store = self.store.read().await;
        let key = (participant_context.id.clone(), hash.to_string());

        let entry = store
            .entries_by_hash
            .get(&key)
            .ok_or_else(|| TokenError::token_not_found(hash))?;

        Ok(entry.clone())
    }

    async fn find_by_id(
        &self,
        participant_context: &ParticipantContext,
        id: &str,
    ) -> Result<RenewableTokenEntry, TokenError> {
        let store = self.store.read().await;
        let key = (participant_context.id.clone(), id.to_string());

        let entry = store
            .entries_by_id
            .get(&key)
            .ok_or_else(|| TokenError::token_not_found(id))?;

        Ok(entry.clone())
    }

    async fn find_by_flow_id(
        &self,
        participant_context: &ParticipantContext,
        flow_id: &str,
    ) -> Result<RenewableTokenEntry, TokenError> {
        let store = self.store.read().await;
        let key = (participant_context.id.clone(), flow_id.to_string());

        let entry = store
            .entries_by_flow_id
            .get(&key)
            .ok_or_else(|| TokenError::token_not_found(flow_id))?;

        Ok(entry.clone())
    }

    async fn remove_by_flow_id(
        &self,
        participant_context: &ParticipantContext,
        flow_id: &str,
    ) -> Result<(), TokenError> {
        let mut store = self.store.write().await;
        let flow_id_key = (participant_context.id.clone(), flow_id.to_string());

        // Remove the entry from the flow_id index
        let entry = store
            .entries_by_flow_id
            .remove(&flow_id_key)
            .ok_or_else(|| TokenError::token_not_found(flow_id))?;

        // Remove from other indices
        let hash_key = (participant_context.id.clone(), entry.hashed_refresh_token.clone());
        let id_key = (participant_context.id.clone(), entry.id.clone());
        store.entries_by_hash.remove(&hash_key);
        store.entries_by_id.remove(&id_key);

        Ok(())
    }

    async fn update(
        &self,
        participant_context: &ParticipantContext,
        old_hash: &str,
        new_entry: RenewableTokenEntry,
    ) -> Result<(), TokenError> {
        let mut store = self.store.write().await;
        let old_hash_key = (participant_context.id.clone(), old_hash.to_string());

        // Remove the old entry from all indices
        let old_entry = store
            .entries_by_hash
            .remove(&old_hash_key)
            .ok_or_else(|| TokenError::token_not_found(old_hash))?;

        let old_id_key = (participant_context.id.clone(), old_entry.id.clone());
        let old_flow_id_key = (participant_context.id.clone(), old_entry.flow_id.clone());
        store.entries_by_id.remove(&old_id_key);
        store.entries_by_flow_id.remove(&old_flow_id_key);

        // Insert the new entry in all indices
        let new_hash_key = (participant_context.id.clone(), new_entry.hashed_refresh_token.clone());
        let new_id_key = (participant_context.id.clone(), new_entry.id.clone());
        let new_flow_id_key = (participant_context.id.clone(), new_entry.flow_id.clone());

        store.entries_by_hash.insert(new_hash_key, new_entry.clone());
        store.entries_by_id.insert(new_id_key, new_entry.clone());
        store.entries_by_flow_id.insert(new_flow_id_key, new_entry);

        Ok(())
    }
}
