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

#![allow(clippy::unwrap_used)]
use chrono::{TimeDelta, Utc};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::manager::{RenewableTokenEntry, RenewableTokenStore};
use dsdk_facet_postgres::renewable_token_store::PostgresRenewableTokenStore;
use dsdk_facet_testcontainers::postgres::{setup_postgres_container, truncate_to_micros};
use std::collections::HashMap;

#[tokio::test]
async fn test_postgres_renewable_token_store_initialization_idempotent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);

    // Initialize multiple times - should not fail
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
}

#[tokio::test]
async fn test_postgres_save_and_find_by_renewal() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let mut claims = HashMap::new();
    claims.insert("custom_claim".to_string(), "custom_value".to_string());

    let entry = RenewableTokenEntry {
        id: "token-id-123".to_string(),
        token: "access_token_abc".to_string(),
        hashed_refresh_token: "hashed_refresh_abc".to_string(),
        expires_at,
        subject: "user@example.com".to_string(),
        claims: claims.clone(),
        flow_id: "test_flow".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save(pc, entry.clone()).await.unwrap();
    let retrieved = store.find_by_renewal(pc, "hashed_refresh_abc").await.unwrap();

    assert_eq!(retrieved.id, "token-id-123");
    assert_eq!(retrieved.token, "access_token_abc");
    assert_eq!(retrieved.hashed_refresh_token, "hashed_refresh_abc");
    assert_eq!(retrieved.expires_at, truncate_to_micros(expires_at));
    assert_eq!(retrieved.subject, "user@example.com");
    assert_eq!(retrieved.claims, claims);
}

#[tokio::test]
async fn test_postgres_save_and_find_by_id() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let mut claims = HashMap::new();
    claims.insert("role".to_string(), "admin".to_string());

    let entry = RenewableTokenEntry {
        id: "token-id-456".to_string(),
        token: "access_token_xyz".to_string(),
        hashed_refresh_token: "hashed_refresh_xyz".to_string(),
        expires_at,
        subject: "admin@example.com".to_string(),
        claims,
        flow_id: "test_flow".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save(pc, entry.clone()).await.unwrap();
    let retrieved = store.find_by_id(pc, "token-id-456").await.unwrap();

    assert_eq!(retrieved.id, "token-id-456");
    assert_eq!(retrieved.token, "access_token_xyz");
    assert_eq!(retrieved.hashed_refresh_token, "hashed_refresh_xyz");
    assert_eq!(retrieved.subject, "admin@example.com");
}

#[tokio::test]
async fn test_postgres_find_by_renewal_nonexistent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let pc = &ParticipantContext::builder().id("participant1").build();

    let result = store.find_by_renewal(pc, "nonexistent_hash").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_postgres_find_by_id_nonexistent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let pc = &ParticipantContext::builder().id("participant1").build();

    let result = store.find_by_id(pc, "nonexistent_id").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_postgres_save_upserts_on_duplicate() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at_1 = initial_time + TimeDelta::seconds(1000);
    let expires_at_2 = initial_time + TimeDelta::seconds(2000);

    let mut claims1 = HashMap::new();
    claims1.insert("version".to_string(), "1".to_string());

    let mut claims2 = HashMap::new();
    claims2.insert("version".to_string(), "2".to_string());

    let entry1 = RenewableTokenEntry {
        id: "same-id".to_string(),
        token: "old_token".to_string(),
        hashed_refresh_token: "old_hash".to_string(),
        expires_at: expires_at_1,
        subject: "user@example.com".to_string(),
        claims: claims1,
        flow_id: "test_flow".to_string(),
    };

    let entry2 = RenewableTokenEntry {
        id: "same-id".to_string(),
        token: "new_token".to_string(),
        hashed_refresh_token: "new_hash".to_string(),
        expires_at: expires_at_2,
        subject: "user@example.com".to_string(),
        claims: claims2.clone(),
        flow_id: "test_flow".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save(pc, entry1).await.unwrap();
    store.save(pc, entry2).await.unwrap();

    let retrieved = store.find_by_id(pc, "same-id").await.unwrap();
    assert_eq!(retrieved.token, "new_token");
    assert_eq!(retrieved.hashed_refresh_token, "new_hash");
    assert_eq!(retrieved.expires_at, truncate_to_micros(expires_at_2));
    assert_eq!(retrieved.claims, claims2);
}

#[tokio::test]
async fn test_postgres_update_success() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(1000);

    let mut claims = HashMap::new();
    claims.insert("claim1".to_string(), "value1".to_string());

    let entry = RenewableTokenEntry {
        id: "token-id-1".to_string(),
        token: "token1".to_string(),
        hashed_refresh_token: "old_hash".to_string(),
        expires_at,
        subject: "user@example.com".to_string(),
        claims: claims.clone(),
        flow_id: "test_flow".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save(pc, entry).await.unwrap();

    let new_expires_at = initial_time + TimeDelta::seconds(2000);
    let new_entry = RenewableTokenEntry {
        id: "token-id-2".to_string(),
        token: "token2".to_string(),
        hashed_refresh_token: "new_hash".to_string(),
        expires_at: new_expires_at,
        subject: "user@example.com".to_string(),
        claims,
        flow_id: "test_flow".to_string(),
    };

    store.update(pc, "old_hash", new_entry).await.unwrap();

    // Old hash should not exist anymore
    let old_result = store.find_by_renewal(pc, "old_hash").await;
    assert!(old_result.is_err());

    // New hash should exist
    let retrieved = store.find_by_renewal(pc, "new_hash").await.unwrap();
    assert_eq!(retrieved.id, "token-id-2");
    assert_eq!(retrieved.token, "token2");
    assert_eq!(retrieved.expires_at, truncate_to_micros(new_expires_at));
}

#[tokio::test]
async fn test_postgres_update_nonexistent_token() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(1000);

    let entry = RenewableTokenEntry {
        id: "new-id".to_string(),
        token: "new_token".to_string(),
        hashed_refresh_token: "new_hash".to_string(),
        expires_at,
        subject: "user@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    let result = store.update(pc, "nonexistent_hash", entry).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_postgres_multiple_tokens() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry1 = RenewableTokenEntry {
        id: "id-1".to_string(),
        token: "token1".to_string(),
        hashed_refresh_token: "hash1".to_string(),
        expires_at,
        subject: "user1@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry2 = RenewableTokenEntry {
        id: "id-2".to_string(),
        token: "token2".to_string(),
        hashed_refresh_token: "hash2".to_string(),
        expires_at,
        subject: "user2@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save(pc, entry1).await.unwrap();
    store.save(pc, entry2).await.unwrap();

    let retrieved1 = store.find_by_id(pc, "id-1").await.unwrap();
    let retrieved2 = store.find_by_id(pc, "id-2").await.unwrap();

    assert_eq!(retrieved1.token, "token1");
    assert_eq!(retrieved2.token, "token2");
}

#[tokio::test]
async fn test_postgres_token_with_special_characters() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let mut claims = HashMap::new();
    claims.insert("special!@#$%".to_string(), "value!@#$%".to_string());

    let entry = RenewableTokenEntry {
        id: "id-with-dashes-123".to_string(),
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0".to_string(),
        hashed_refresh_token: "hash!@#$%^&*()".to_string(),
        expires_at,
        subject: "user+tag@example.com".to_string(),
        claims,
        flow_id: "test_flow".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save(pc, entry.clone()).await.unwrap();
    let retrieved = store.find_by_renewal(pc, "hash!@#$%^&*()").await.unwrap();

    assert_eq!(retrieved.id, "id-with-dashes-123");
    assert!(retrieved.token.contains("eyJ"));
    assert_eq!(retrieved.subject, "user+tag@example.com");
}

#[tokio::test]
async fn test_postgres_token_with_long_values() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let mut claims = HashMap::new();
    for i in 0..50 {
        claims.insert(format!("claim_{}", i), format!("value_{}", i));
    }

    let entry = RenewableTokenEntry {
        id: "i".repeat(250),
        token: "t".repeat(5000),
        hashed_refresh_token: "h".repeat(250),
        expires_at,
        subject: "s".repeat(250),
        claims: claims.clone(),
        flow_id: "test_flow".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save(pc, entry).await.unwrap();

    let retrieved = store.find_by_renewal(pc, &"h".repeat(250)).await.unwrap();
    assert_eq!(retrieved.token.len(), 5000);
    assert_eq!(retrieved.subject.len(), 250);
    assert_eq!(retrieved.claims.len(), 50);
}

#[tokio::test]
async fn test_postgres_save_find_update_flow() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at_1 = initial_time + TimeDelta::seconds(1000);

    let mut claims = HashMap::new();
    claims.insert("session".to_string(), "abc123".to_string());

    let entry = RenewableTokenEntry {
        id: "id-1".to_string(),
        token: "token1".to_string(),
        hashed_refresh_token: "hash1".to_string(),
        expires_at: expires_at_1,
        subject: "user@example.com".to_string(),
        claims: claims.clone(),
        flow_id: "test_flow".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    // Save
    store.save(pc, entry).await.unwrap();

    // Find by renewal
    let found = store.find_by_renewal(pc, "hash1").await.unwrap();
    assert_eq!(found.token, "token1");

    // Update
    let expires_at_2 = initial_time + TimeDelta::seconds(2000);
    let new_entry = RenewableTokenEntry {
        id: "id-2".to_string(),
        token: "token2".to_string(),
        hashed_refresh_token: "hash2".to_string(),
        expires_at: expires_at_2,
        subject: "user@example.com".to_string(),
        claims,
        flow_id: "test_flow".to_string(),
    };

    store.update(pc, "hash1", new_entry).await.unwrap();

    // Find by new hash
    let updated = store.find_by_renewal(pc, "hash2").await.unwrap();
    assert_eq!(updated.token, "token2");
    assert_eq!(updated.id, "id-2");

    // Old hash should not work
    let old_result = store.find_by_renewal(pc, "hash1").await;
    assert!(old_result.is_err());
}

#[tokio::test]
async fn test_context_isolation_save() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry_p1 = RenewableTokenEntry {
        id: "id-same".to_string(),
        token: "token_p1".to_string(),
        hashed_refresh_token: "hash_p1".to_string(),
        expires_at,
        subject: "user1@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry_p2 = RenewableTokenEntry {
        id: "id-same".to_string(),
        token: "token_p2".to_string(),
        hashed_refresh_token: "hash_p2".to_string(),
        expires_at,
        subject: "user2@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let pc1 = &ParticipantContext::builder().id("participant1").build();
    let pc2 = &ParticipantContext::builder().id("participant2").build();

    store.save(pc1, entry_p1).await.unwrap();
    store.save(pc2, entry_p2).await.unwrap();

    let retrieved_p1 = store.find_by_id(pc1, "id-same").await.unwrap();
    let retrieved_p2 = store.find_by_id(pc2, "id-same").await.unwrap();

    assert_eq!(retrieved_p1.token, "token_p1");
    assert_eq!(retrieved_p2.token, "token_p2");

    // Participant 3 should not see either token
    let pc3 = &ParticipantContext::builder().id("participant3").build();
    let result_p3 = store.find_by_id(pc3, "id-same").await;
    assert!(result_p3.is_err());
}

#[tokio::test]
async fn test_context_isolation_find_by_renewal() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry_p1 = RenewableTokenEntry {
        id: "id-1".to_string(),
        token: "token_p1".to_string(),
        hashed_refresh_token: "hash-same".to_string(),
        expires_at,
        subject: "user1@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry_p2 = RenewableTokenEntry {
        id: "id-2".to_string(),
        token: "token_p2".to_string(),
        hashed_refresh_token: "hash-same".to_string(),
        expires_at,
        subject: "user2@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let pc1 = &ParticipantContext::builder().id("participant1").build();
    let pc2 = &ParticipantContext::builder().id("participant2").build();

    store.save(pc1, entry_p1).await.unwrap();
    store.save(pc2, entry_p2).await.unwrap();

    let p1_result = store.find_by_renewal(pc1, "hash-same").await.unwrap();
    let p2_result = store.find_by_renewal(pc2, "hash-same").await.unwrap();

    assert_eq!(p1_result.token, "token_p1");
    assert_eq!(p2_result.token, "token_p2");

    // Participant 3 should not find the token
    let pc3 = &ParticipantContext::builder().id("participant3").build();
    let result_p3 = store.find_by_renewal(pc3, "hash-same").await;
    assert!(result_p3.is_err());
    assert!(result_p3.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_context_isolation_find_by_id() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry_p1 = RenewableTokenEntry {
        id: "shared-id".to_string(),
        token: "token_p1".to_string(),
        hashed_refresh_token: "hash1".to_string(),
        expires_at,
        subject: "user1@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry_p2 = RenewableTokenEntry {
        id: "shared-id".to_string(),
        token: "token_p2".to_string(),
        hashed_refresh_token: "hash2".to_string(),
        expires_at,
        subject: "user2@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let pc1 = &ParticipantContext::builder().id("participant1").build();
    let pc2 = &ParticipantContext::builder().id("participant2").build();

    store.save(pc1, entry_p1).await.unwrap();
    store.save(pc2, entry_p2).await.unwrap();

    let p1_result = store.find_by_id(pc1, "shared-id").await.unwrap();
    let p2_result = store.find_by_id(pc2, "shared-id").await.unwrap();

    assert_eq!(p1_result.token, "token_p1");
    assert_eq!(p2_result.token, "token_p2");
}

#[tokio::test]
async fn test_context_isolation_update() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry_p1 = RenewableTokenEntry {
        id: "id-1".to_string(),
        token: "token_p1".to_string(),
        hashed_refresh_token: "hash1".to_string(),
        expires_at,
        subject: "user1@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let entry_p2 = RenewableTokenEntry {
        id: "id-2".to_string(),
        token: "token_p2".to_string(),
        hashed_refresh_token: "hash2".to_string(),
        expires_at,
        subject: "user2@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let pc1 = &ParticipantContext::builder().id("participant1").build();
    let pc2 = &ParticipantContext::builder().id("participant2").build();

    store.save(pc1, entry_p1).await.unwrap();
    store.save(pc2, entry_p2).await.unwrap();

    // Update p1's token
    let updated_p1 = RenewableTokenEntry {
        id: "id-1-updated".to_string(),
        token: "token_p1_updated".to_string(),
        hashed_refresh_token: "hash1_updated".to_string(),
        expires_at,
        subject: "user1@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    store.update(pc1, "hash1", updated_p1).await.unwrap();

    let p1_result = store.find_by_renewal(pc1, "hash1_updated").await.unwrap();
    let p2_result = store.find_by_renewal(pc2, "hash2").await.unwrap();

    assert_eq!(p1_result.token, "token_p1_updated");
    assert_eq!(p2_result.token, "token_p2");

    // Participant 3 cannot update a non-existent token
    let pc3 = &ParticipantContext::builder().id("participant3").build();
    let update_p3 = RenewableTokenEntry {
        id: "id-3".to_string(),
        token: "token_p3".to_string(),
        hashed_refresh_token: "hash3".to_string(),
        expires_at,
        subject: "user3@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let result_p3 = store.update(pc3, "nonexistent_hash", update_p3).await;
    assert!(result_p3.is_err());
    assert!(matches!(result_p3.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_postgres_claims_serialization() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool.clone());
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let mut claims = HashMap::new();
    claims.insert("claim1".to_string(), "value1".to_string());
    claims.insert("claim2".to_string(), "value2".to_string());
    claims.insert("claim3".to_string(), "value3".to_string());

    let entry = RenewableTokenEntry {
        id: "id-1".to_string(),
        token: "token1".to_string(),
        hashed_refresh_token: "hash1".to_string(),
        expires_at,
        subject: "user@example.com".to_string(),
        claims: claims.clone(),
        flow_id: "test_flow".to_string(),
    };

    let pc = ParticipantContext::builder().id("participant1").build();

    store.save(&pc, entry).await.unwrap();

    // Query database directly to verify JSONB storage
    let row: (serde_json::Value,) =
        sqlx::query_as("SELECT claims FROM renewable_tokens WHERE participant_context = $1 AND id = $2")
            .bind("participant1")
            .bind("id-1")
            .fetch_one(&pool)
            .await
            .unwrap();

    // Verify it's valid JSON
    assert!(row.0.is_object());

    // Verify retrieval correctly deserializes the JSONB
    let retrieved = store.find_by_id(&pc, "id-1").await.unwrap();
    assert_eq!(retrieved.claims.len(), 3);
    assert_eq!(retrieved.claims.get("claim1").unwrap(), "value1");
    assert_eq!(retrieved.claims.get("claim2").unwrap(), "value2");
    assert_eq!(retrieved.claims.get("claim3").unwrap(), "value3");
}

#[tokio::test]
async fn test_postgres_empty_claims() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry = RenewableTokenEntry {
        id: "id-1".to_string(),
        token: "token1".to_string(),
        hashed_refresh_token: "hash1".to_string(),
        expires_at,
        subject: "user@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let pc = ParticipantContext::builder().id("participant1").build();

    store.save(&pc, entry).await.unwrap();

    let retrieved = store.find_by_id(&pc, "id-1").await.unwrap();
    assert_eq!(retrieved.claims.len(), 0);
}

#[tokio::test]
async fn test_postgres_timestamp_precision() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry = RenewableTokenEntry {
        id: "id-1".to_string(),
        token: "token1".to_string(),
        hashed_refresh_token: "hash1".to_string(),
        expires_at,
        subject: "user@example.com".to_string(),
        claims: HashMap::new(),
        flow_id: "test_flow".to_string(),
    };

    let pc = ParticipantContext::builder().id("participant1").build();

    store.save(&pc, entry).await.unwrap();

    let retrieved = store.find_by_id(&pc, "id-1").await.unwrap();

    // PostgreSQL truncates to microseconds, so we verify it's within acceptable range
    assert_eq!(retrieved.expires_at, truncate_to_micros(expires_at));
}

#[tokio::test]
async fn test_postgres_find_by_flow_id_success() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry = RenewableTokenEntry {
        id: "test_id".to_string(),
        token: "test_token".to_string(),
        hashed_refresh_token: "test_hash".to_string(),
        expires_at,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "flow_123".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save(pc, entry.clone()).await.unwrap();

    let retrieved = store.find_by_flow_id(pc, "flow_123").await.unwrap();
    assert_eq!(retrieved.id, "test_id");
    assert_eq!(retrieved.token, "test_token");
    assert_eq!(retrieved.flow_id, "flow_123");
}

#[tokio::test]
async fn test_postgres_find_by_flow_id_not_found() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let pc = &ParticipantContext::builder().id("participant1").build();

    let result = store.find_by_flow_id(pc, "nonexistent_flow").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_postgres_delete_by_flow_id_success() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry = RenewableTokenEntry {
        id: "test_id".to_string(),
        token: "test_token".to_string(),
        hashed_refresh_token: "test_hash".to_string(),
        expires_at,
        subject: "test_subject".to_string(),
        claims: HashMap::new(),
        flow_id: "flow_to_delete".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save(pc, entry.clone()).await.unwrap();

    // Verify entry exists
    let found = store.find_by_flow_id(pc, "flow_to_delete").await.unwrap();
    assert_eq!(found.id, "test_id");

    // Delete by flow_id
    let result = store.delete_by_flow_id(pc, "flow_to_delete").await;
    assert!(result.is_ok());

    // Verify entry no longer exists
    let not_found_by_flow = store.find_by_flow_id(pc, "flow_to_delete").await;
    assert!(not_found_by_flow.is_err());
}
