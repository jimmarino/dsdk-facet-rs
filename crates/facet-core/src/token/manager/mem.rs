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
use crate::token::TokenError;
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Inner storage structure holding all token indices.
struct InnerStore {
    /// Primary storage indexed by hashed_refresh_token
    entries_by_hash: HashMap<String, RenewableTokenEntry>,
    /// Secondary index by id for id-based lookups
    entries_by_id: HashMap<String, RenewableTokenEntry>,
    /// Secondary index by flow_id for flow_id-based lookups
    entries_by_flow_id: HashMap<String, RenewableTokenEntry>,
}

/// In-memory renewable token store for testing and development.
///
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
    async fn save(&self, entry: RenewableTokenEntry) -> Result<(), TokenError> {
        let mut store = self.store.write().await;
        store
            .entries_by_hash
            .insert(entry.hashed_refresh_token.clone(), entry.clone());
        store.entries_by_id.insert(entry.id.clone(), entry.clone());
        store.entries_by_flow_id.insert(entry.flow_id.clone(), entry);
        Ok(())
    }

    async fn find_by_renewal(&self, hash: &str) -> Result<RenewableTokenEntry, TokenError> {
        let store = self.store.read().await;
        store
            .entries_by_hash
            .get(hash)
            .cloned()
            .ok_or_else(|| TokenError::token_not_found(hash))
    }

    async fn find_by_id(&self, id: &str) -> Result<RenewableTokenEntry, TokenError> {
        let store = self.store.read().await;
        store
            .entries_by_id
            .get(id)
            .cloned()
            .ok_or_else(|| TokenError::token_not_found(id))
    }

    async fn find_by_flow_id(&self, flow_id: &str) -> Result<RenewableTokenEntry, TokenError> {
        let store = self.store.read().await;
        store
            .entries_by_flow_id
            .get(flow_id)
            .cloned()
            .ok_or_else(|| TokenError::token_not_found(flow_id))
    }

    async fn remove_by_flow_id(&self, flow_id: &str) -> Result<(), TokenError> {
        let mut store = self.store.write().await;
        let entry = store
            .entries_by_flow_id
            .remove(flow_id)
            .ok_or_else(|| TokenError::token_not_found(flow_id))?;

        store.entries_by_hash.remove(&entry.hashed_refresh_token);
        store.entries_by_id.remove(&entry.id);
        Ok(())
    }

    async fn update(&self, old_hash: &str, new_entry: RenewableTokenEntry) -> Result<(), TokenError> {
        let mut store = self.store.write().await;

        let old_entry = store
            .entries_by_hash
            .remove(old_hash)
            .ok_or_else(|| TokenError::token_not_found(old_hash))?;

        store.entries_by_id.remove(&old_entry.id);
        store.entries_by_flow_id.remove(&old_entry.flow_id);

        store
            .entries_by_hash
            .insert(new_entry.hashed_refresh_token.clone(), new_entry.clone());
        store.entries_by_id.insert(new_entry.id.clone(), new_entry.clone());
        store.entries_by_flow_id.insert(new_entry.flow_id.clone(), new_entry);
        Ok(())
    }
}
