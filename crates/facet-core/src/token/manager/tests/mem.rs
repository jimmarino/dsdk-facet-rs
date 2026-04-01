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

use super::super::{MemoryRenewableTokenStore, RenewableTokenEntry, RenewableTokenStore};
use crate::context::ParticipantContext;
use crate::token::TokenError;
use chrono::{TimeDelta, Utc};
use std::collections::HashMap;

#[tokio::test]
async fn test_save_success() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let entry = RenewableTokenEntry {
        id: "id_123".to_string(),
        token: "access_token_123".to_string(),
        hashed_refresh_token: "hash_abc".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let result = store.save(pc, entry.clone()).await;
    assert!(result.is_ok(), "save should succeed");

    // Verify we can retrieve it
    let retrieved = store
        .find_by_renewal(pc, "hash_abc")
        .await
        .expect("Failed to find saved entry");
    assert_eq!(retrieved.id, "id_123");
    assert_eq!(retrieved.token, "access_token_123");
    assert_eq!(retrieved.hashed_refresh_token, "hash_abc");
    assert_eq!(retrieved.expires_at, expiration);
}

#[tokio::test]
async fn test_save_multiple_entries() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let entry1 = RenewableTokenEntry {
        id: "id1".to_string(),
        token: "token1".to_string(),
        hashed_refresh_token: "hash1".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry2 = RenewableTokenEntry {
        id: "id2".to_string(),
        token: "token2".to_string(),
        hashed_refresh_token: "hash2".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry3 = RenewableTokenEntry {
        id: "id3".to_string(),
        token: "token3".to_string(),
        hashed_refresh_token: "hash3".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc, entry1).await.unwrap();
    store.save(pc, entry2).await.unwrap();
    store.save(pc, entry3).await.unwrap();

    assert_eq!(store.find_by_renewal(pc, "hash1").await.unwrap().token, "token1");
    assert_eq!(store.find_by_renewal(pc, "hash2").await.unwrap().token, "token2");
    assert_eq!(store.find_by_renewal(pc, "hash3").await.unwrap().token, "token3");
}

#[tokio::test]
async fn test_save_overwrites_same_hash() {
    let store = MemoryRenewableTokenStore::new();
    let expiration1 = Utc::now() + TimeDelta::seconds(1000);
    let expiration2 = Utc::now() + TimeDelta::seconds(2000);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let entry1 = RenewableTokenEntry {
        id: "id_old".to_string(),
        token: "old_token".to_string(),
        hashed_refresh_token: "hash_same".to_string(),
        expires_at: expiration1,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry2 = RenewableTokenEntry {
        id: "id_new".to_string(),
        token: "new_token".to_string(),
        hashed_refresh_token: "hash_same".to_string(),
        expires_at: expiration2,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc, entry1).await.unwrap();
    store.save(pc, entry2).await.unwrap();

    // Should retrieve the new entry
    let retrieved = store.find_by_renewal(pc, "hash_same").await.unwrap();
    assert_eq!(retrieved.id, "id_new");
    assert_eq!(retrieved.token, "new_token");
    assert_eq!(retrieved.expires_at, expiration2);
}

#[tokio::test]
async fn test_find_not_found() {
    let store = MemoryRenewableTokenStore::new();
    let pc = &ParticipantContext::builder().id("participant1").build();

    let result = store.find_by_renewal(pc, "nonexistent").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_update_success() {
    let store = MemoryRenewableTokenStore::new();
    let expiration1 = Utc::now() + TimeDelta::seconds(1000);
    let expiration2 = Utc::now() + TimeDelta::seconds(2000);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let initial_entry = RenewableTokenEntry {
        id: "id_initial".to_string(),
        token: "initial_token".to_string(),
        hashed_refresh_token: "old_hash".to_string(),
        expires_at: expiration1,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc, initial_entry).await.unwrap();

    // Update with new hash and new id
    let updated_entry = RenewableTokenEntry {
        id: "id_updated".to_string(),
        token: "updated_token".to_string(),
        hashed_refresh_token: "new_hash".to_string(),
        expires_at: expiration2,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let result = store.update(pc, "old_hash", updated_entry).await;
    assert!(result.is_ok(), "update should succeed");

    // Old hash should not be findable
    let old_result = store.find_by_renewal(pc, "old_hash").await;
    assert!(old_result.is_err());

    // Old id should not be findable
    let old_id_result = store.find_by_id(pc, "id_initial").await;
    assert!(old_id_result.is_err());

    // New hash should be findable with updated data
    let new_result = store.find_by_renewal(pc, "new_hash").await.unwrap();
    assert_eq!(new_result.id, "id_updated");
    assert_eq!(new_result.token, "updated_token");
    assert_eq!(new_result.hashed_refresh_token, "new_hash");
    assert_eq!(new_result.expires_at, expiration2);

    // New id should also be findable
    let new_id_result = store.find_by_id(pc, "id_updated").await.unwrap();
    assert_eq!(new_id_result.token, "updated_token");
}

#[tokio::test]
async fn test_update_not_found() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let entry = RenewableTokenEntry {
        id: "id_new".to_string(),
        token: "token".to_string(),
        hashed_refresh_token: "new_hash".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let result = store.update(pc, "nonexistent_hash", entry).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_context_isolation_save() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let pc1 = &ParticipantContext::builder().id("participant1").build();
    let pc2 = &ParticipantContext::builder().id("participant2").build();

    let entry_p1 = RenewableTokenEntry {
        id: "id_p1".to_string(),
        token: "token_p1".to_string(),
        hashed_refresh_token: "hash_shared".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry_p2 = RenewableTokenEntry {
        id: "id_p2".to_string(),
        token: "token_p2".to_string(),
        hashed_refresh_token: "hash_shared".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc1, entry_p1).await.unwrap();
    store.save(pc2, entry_p2).await.unwrap();

    // Each participant should only see their own token
    let retrieved_p1 = store.find_by_renewal(pc1, "hash_shared").await.unwrap();
    let retrieved_p2 = store.find_by_renewal(pc2, "hash_shared").await.unwrap();

    assert_eq!(retrieved_p1.token, "token_p1");
    assert_eq!(retrieved_p2.token, "token_p2");
}

#[tokio::test]
async fn test_context_isolation_find() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let pc1 = &ParticipantContext::builder().id("participant1").build();
    let pc2 = &ParticipantContext::builder().id("participant2").build();
    let pc3 = &ParticipantContext::builder().id("participant3").build();

    let entry_p1 = RenewableTokenEntry {
        id: "id_p1".to_string(),
        token: "token_p1".to_string(),
        hashed_refresh_token: "hash_p1".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc1, entry_p1).await.unwrap();

    // Participant 1 can find their token
    let result_p1 = store.find_by_renewal(pc1, "hash_p1").await;
    assert!(result_p1.is_ok());
    assert_eq!(result_p1.unwrap().token, "token_p1");

    // Participant 2 cannot find participant 1's token
    let result_p2 = store.find_by_renewal(pc2, "hash_p1").await;
    assert!(result_p2.is_err());
    assert!(matches!(result_p2.unwrap_err(), TokenError::TokenNotFound { .. }));

    // Participant 3 cannot find participant 1's token
    let result_p3 = store.find_by_renewal(pc3, "hash_p1").await;
    assert!(result_p3.is_err());
    assert!(matches!(result_p3.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_context_isolation_update() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let pc1 = &ParticipantContext::builder().id("participant1").build();
    let pc2 = &ParticipantContext::builder().id("participant2").build();

    // Save initial entries for both participants
    let entry_p1 = RenewableTokenEntry {
        id: "id_p1".to_string(),
        token: "token_p1".to_string(),
        hashed_refresh_token: "hash_p1".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry_p2 = RenewableTokenEntry {
        id: "id_p2".to_string(),
        token: "token_p2".to_string(),
        hashed_refresh_token: "hash_p2".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc1, entry_p1).await.unwrap();
    store.save(pc2, entry_p2).await.unwrap();

    // Participant 2 cannot update participant 1's token
    let updated_entry = RenewableTokenEntry {
        id: "id_new".to_string(),
        token: "token_p2_trying_to_update_p1".to_string(),
        hashed_refresh_token: "new_hash".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let result = store.update(pc2, "hash_p1", updated_entry).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));

    // Participant 1's token should remain unchanged
    let retrieved_p1 = store.find_by_renewal(pc1, "hash_p1").await.unwrap();
    assert_eq!(retrieved_p1.token, "token_p1");

    // Participant 1 can update their own token
    let updated_p1_entry = RenewableTokenEntry {
        id: "id_p1_updated".to_string(),
        token: "token_p1_updated".to_string(),
        hashed_refresh_token: "new_hash_p1".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let result = store.update(pc1, "hash_p1", updated_p1_entry).await;
    assert!(result.is_ok());

    // Verify the update
    let retrieved_p1_new = store.find_by_renewal(pc1, "new_hash_p1").await.unwrap();
    assert_eq!(retrieved_p1_new.token, "token_p1_updated");

    // Old hash should not be findable
    let old_result = store.find_by_renewal(pc1, "hash_p1").await;
    assert!(old_result.is_err());

    // Participant 2's token should remain unchanged
    let retrieved_p2 = store.find_by_renewal(pc2, "hash_p2").await.unwrap();
    assert_eq!(retrieved_p2.token, "token_p2");
}

#[tokio::test]
async fn test_cloned_entry_independence() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let entry = RenewableTokenEntry {
        id: "id123".to_string(),
        token: "original_token".to_string(),
        hashed_refresh_token: "hash123".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc, entry).await.unwrap();

    // Get the entry
    let mut retrieved1 = store.find_by_renewal(pc, "hash123").await.unwrap();

    // Modify the clone
    retrieved1.token = "modified_token".to_string();

    // Get the entry again - should still have original value
    let retrieved2 = store.find_by_renewal(pc, "hash123").await.unwrap();
    assert_eq!(retrieved2.token, "original_token");
    assert_ne!(retrieved2.token, retrieved1.token);
}

#[tokio::test]
async fn test_concurrent_save_operations() {
    use std::sync::Arc;

    let store = Arc::new(MemoryRenewableTokenStore::new());
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let mut handles = vec![];

    // Spawn 10 concurrent save operations
    for i in 0..10 {
        let store_clone = store.clone();
        let handle = tokio::spawn(async move {
            let pc = ParticipantContext::builder().id(format!("participant{}", i)).build();

            let entry = RenewableTokenEntry {
                id: format!("id{}", i),
                token: format!("token{}", i),
                hashed_refresh_token: format!("hash{}", i),
                expires_at: expiration,
                subject: "test_subject".to_string(),
                claims: HashMap::new(),
                flow_id: "test_flow".to_string(),
            };

            store_clone.save(&pc, entry).await.unwrap();
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all entries were saved correctly
    for i in 0..10 {
        let pc = ParticipantContext::builder().id(format!("participant{}", i)).build();

        let retrieved = store.find_by_renewal(&pc, &format!("hash{}", i)).await.unwrap();
        assert_eq!(retrieved.token, format!("token{}", i));
    }
}

#[tokio::test]
async fn test_concurrent_update_operations() {
    use std::sync::Arc;

    let store = Arc::new(MemoryRenewableTokenStore::new());
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let pc = ParticipantContext::builder().id("participant1").build();

    // Save initial entry
    let initial_entry = RenewableTokenEntry {
        id: "id0".to_string(),
        token: "initial_token".to_string(),
        hashed_refresh_token: "hash0".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };
    store.save(&pc, initial_entry).await.unwrap();

    let mut handles = vec![];

    // Spawn 5 sequential update operations (each depends on the previous)
    for i in 1..6 {
        let store_clone = store.clone();
        let pc_clone = pc.clone();
        let old_hash = format!("hash{}", i - 1);

        let handle = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(i as u64 * 10)).await;

            let entry = RenewableTokenEntry {
                id: format!("id{}", i),
                token: format!("token{}", i),
                hashed_refresh_token: format!("hash{}", i),
                expires_at: expiration,
                subject: "test_subject".to_string(),
                claims: HashMap::new(),
                flow_id: "test_flow".to_string(),
            };

            store_clone.update(&pc_clone, &old_hash, entry).await
        });
        handles.push(handle);
    }

    // Collect results
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // At least one update should succeed (the first one)
    assert!(results.iter().any(|r| r.is_ok()));
}

#[tokio::test]
async fn test_find_by_id_success() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let entry = RenewableTokenEntry {
        id: "unique_id_123".to_string(),
        token: "access_token_123".to_string(),
        hashed_refresh_token: "hash_abc".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc, entry.clone()).await.unwrap();

    // Find by id
    let retrieved = store.find_by_id(pc, "unique_id_123").await.unwrap();
    assert_eq!(retrieved.id, "unique_id_123");
    assert_eq!(retrieved.token, "access_token_123");
    assert_eq!(retrieved.hashed_refresh_token, "hash_abc");
    assert_eq!(retrieved.expires_at, expiration);
}

#[tokio::test]
async fn test_find_by_id_not_found() {
    let store = MemoryRenewableTokenStore::new();
    let pc = &ParticipantContext::builder().id("participant1").build();

    let result = store.find_by_id(pc, "nonexistent_id").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_find_by_id_multiple_entries() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let entry1 = RenewableTokenEntry {
        id: "id_alpha".to_string(),
        token: "token_alpha".to_string(),
        hashed_refresh_token: "hash_alpha".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry2 = RenewableTokenEntry {
        id: "id_beta".to_string(),
        token: "token_beta".to_string(),
        hashed_refresh_token: "hash_beta".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry3 = RenewableTokenEntry {
        id: "id_gamma".to_string(),
        token: "token_gamma".to_string(),
        hashed_refresh_token: "hash_gamma".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc, entry1).await.unwrap();
    store.save(pc, entry2).await.unwrap();
    store.save(pc, entry3).await.unwrap();

    // Verify each can be found by id
    assert_eq!(store.find_by_id(pc, "id_alpha").await.unwrap().token, "token_alpha");
    assert_eq!(store.find_by_id(pc, "id_beta").await.unwrap().token, "token_beta");
    assert_eq!(store.find_by_id(pc, "id_gamma").await.unwrap().token, "token_gamma");
}

#[tokio::test]
async fn test_find_by_id_context_isolation() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let pc1 = &ParticipantContext::builder().id("participant1").build();
    let pc2 = &ParticipantContext::builder().id("participant2").build();
    let pc3 = &ParticipantContext::builder().id("participant3").build();

    let entry_p1 = RenewableTokenEntry {
        id: "shared_id".to_string(),
        token: "token_p1".to_string(),
        hashed_refresh_token: "hash_p1".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry_p2 = RenewableTokenEntry {
        id: "shared_id".to_string(),
        token: "token_p2".to_string(),
        hashed_refresh_token: "hash_p2".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc1, entry_p1).await.unwrap();
    store.save(pc2, entry_p2).await.unwrap();

    // Each participant should only see their own token by id
    let retrieved_p1 = store.find_by_id(pc1, "shared_id").await.unwrap();
    let retrieved_p2 = store.find_by_id(pc2, "shared_id").await.unwrap();

    assert_eq!(retrieved_p1.token, "token_p1");
    assert_eq!(retrieved_p2.token, "token_p2");

    // Participant 3 should not find anything
    let result_p3 = store.find_by_id(pc3, "shared_id").await;
    assert!(result_p3.is_err());
    assert!(matches!(result_p3.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_find_by_id_after_update() {
    let store = MemoryRenewableTokenStore::new();
    let expiration1 = Utc::now() + TimeDelta::seconds(1000);
    let expiration2 = Utc::now() + TimeDelta::seconds(2000);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let initial_entry = RenewableTokenEntry {
        id: "id_original".to_string(),
        token: "token_original".to_string(),
        hashed_refresh_token: "hash_original".to_string(),
        expires_at: expiration1,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc, initial_entry).await.unwrap();

    // Verify we can find by original id
    let found = store.find_by_id(pc, "id_original").await.unwrap();
    assert_eq!(found.token, "token_original");

    // Update with new id
    let updated_entry = RenewableTokenEntry {
        id: "id_updated".to_string(),
        token: "token_updated".to_string(),
        hashed_refresh_token: "hash_updated".to_string(),
        expires_at: expiration2,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.update(pc, "hash_original", updated_entry).await.unwrap();

    // Old id should not be findable
    let old_result = store.find_by_id(pc, "id_original").await;
    assert!(old_result.is_err());

    // New id should be findable
    let new_result = store.find_by_id(pc, "id_updated").await.unwrap();
    assert_eq!(new_result.token, "token_updated");
    assert_eq!(new_result.expires_at, expiration2);
}

#[tokio::test]
async fn test_dual_index_consistency() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let entry = RenewableTokenEntry {
        id: "test_id_456".to_string(),
        token: "test_token_456".to_string(),
        hashed_refresh_token: "test_hash_456".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.save(pc, entry).await.unwrap();

    // Both indices should return the same data
    let by_hash = store.find_by_renewal(pc, "test_hash_456").await.unwrap();
    let by_id = store.find_by_id(pc, "test_id_456").await.unwrap();

    assert_eq!(by_hash.id, by_id.id);
    assert_eq!(by_hash.token, by_id.token);
    assert_eq!(by_hash.hashed_refresh_token, by_id.hashed_refresh_token);
    assert_eq!(by_hash.expires_at, by_id.expires_at);
}

#[tokio::test]
async fn test_find_by_flow_id_success() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let entry = RenewableTokenEntry {
        id: "test_id".to_string(),
        token: "test_token".to_string(),
        hashed_refresh_token: "test_hash".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "flow_123".to_string(),
    };

    store.save(pc, entry.clone()).await.unwrap();

    let retrieved = store.find_by_flow_id(pc, "flow_123").await.unwrap();
    assert_eq!(retrieved.id, "test_id");
    assert_eq!(retrieved.token, "test_token");
    assert_eq!(retrieved.flow_id, "flow_123");
}

#[tokio::test]
async fn test_find_by_flow_id_not_found() {
    let store = MemoryRenewableTokenStore::new();
    let pc = &ParticipantContext::builder().id("participant1").build();

    let result = store.find_by_flow_id(pc, "nonexistent_flow").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_find_by_flow_id_context_isolation() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let pc1 = &ParticipantContext::builder().id("participant1").build();
    let pc2 = &ParticipantContext::builder().id("participant2").build();

    let entry_p1 = RenewableTokenEntry {
        id: "id_p1".to_string(),
        token: "token_p1".to_string(),
        hashed_refresh_token: "hash_p1".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "shared_flow_id".to_string(),
    };

    let entry_p2 = RenewableTokenEntry {
        id: "id_p2".to_string(),
        token: "token_p2".to_string(),
        hashed_refresh_token: "hash_p2".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "shared_flow_id".to_string(),
    };

    store.save(pc1, entry_p1).await.unwrap();
    store.save(pc2, entry_p2).await.unwrap();

    // Each participant should only see their own token
    let retrieved_p1 = store.find_by_flow_id(pc1, "shared_flow_id").await.unwrap();
    let retrieved_p2 = store.find_by_flow_id(pc2, "shared_flow_id").await.unwrap();

    assert_eq!(retrieved_p1.token, "token_p1");
    assert_eq!(retrieved_p2.token, "token_p2");
}

#[tokio::test]
async fn test_remove_by_flow_id_success() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let pc = &ParticipantContext::builder().id("participant1").build();

    let entry = RenewableTokenEntry {
        id: "test_id".to_string(),
        token: "test_token".to_string(),
        hashed_refresh_token: "test_hash".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "flow_to_remove".to_string(),
    };

    store.save(pc, entry.clone()).await.unwrap();

    // Verify entry exists
    let found = store.find_by_flow_id(pc, "flow_to_remove").await.unwrap();
    assert_eq!(found.id, "test_id");

    // Delete by flow_id
    let result = store.remove_by_flow_id(pc, "flow_to_remove").await;
    assert!(result.is_ok());

    // Verify entry no longer exists (all indices should be cleared)
    let not_found_by_flow = store.find_by_flow_id(pc, "flow_to_remove").await;
    assert!(not_found_by_flow.is_err());

    let not_found_by_hash = store.find_by_renewal(pc, "test_hash").await;
    assert!(not_found_by_hash.is_err());

    let not_found_by_id = store.find_by_id(pc, "test_id").await;
    assert!(not_found_by_id.is_err());
}

#[tokio::test]
async fn test_delete_by_flow_id_not_found() {
    let store = MemoryRenewableTokenStore::new();
    let pc = &ParticipantContext::builder().id("participant1").build();

    let result = store.remove_by_flow_id(pc, "nonexistent_flow").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_delete_by_flow_id_context_isolation() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let pc1 = &ParticipantContext::builder().id("participant1").build();
    let pc2 = &ParticipantContext::builder().id("participant2").build();

    let entry_p1 = RenewableTokenEntry {
        id: "id_p1".to_string(),
        token: "token_p1".to_string(),
        hashed_refresh_token: "hash_p1".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "flow_delete".to_string(),
    };

    let entry_p2 = RenewableTokenEntry {
        id: "id_p2".to_string(),
        token: "token_p2".to_string(),
        hashed_refresh_token: "hash_p2".to_string(),
        expires_at: expiration,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "flow_delete".to_string(),
    };

    store.save(pc1, entry_p1).await.unwrap();
    store.save(pc2, entry_p2).await.unwrap();

    // Delete p1's token
    let result = store.remove_by_flow_id(pc1, "flow_delete").await;
    assert!(result.is_ok());

    // P1's token should be gone
    let not_found_p1 = store.find_by_flow_id(pc1, "flow_delete").await;
    assert!(not_found_p1.is_err());

    // P2's token should still exist
    let found_p2 = store.find_by_flow_id(pc2, "flow_delete").await.unwrap();
    assert_eq!(found_p2.token, "token_p2");
}
