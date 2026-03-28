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

use super::{JwtTokenManager, MemoryRenewableTokenStore, TokenManager};
use crate::context::ParticipantContext;
use crate::jwt::jwtutils::{StaticSigningKeyResolver, StaticVerificationKeyResolver, generate_ed25519_keypair_pem};
use crate::jwt::{
    JwtGenerator, JwtVerifier, KeyFormat, LocalJwtGenerator, LocalJwtVerifier, SigningAlgorithm, TokenClaims,
};
use crate::token::manager::RenewableTokenStore;
use crate::util::clock::{Clock, MockClock};
use chrono::{DateTime, TimeDelta};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Test fixture containing all the components needed for testing
struct TestFixture {
    manager: JwtTokenManager,
    store: Arc<MemoryRenewableTokenStore>,
    generator: Arc<LocalJwtGenerator>,
    verifier: Arc<LocalJwtVerifier>,
}

/// Helper function to create a JwtTokenManager with real JWT generator/verifier for testing
fn create_jwt_token_manager(clock: Arc<dyn Clock>) -> TestFixture {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate test keypair");

    let signing_resolver = Arc::new(
        StaticSigningKeyResolver::builder()
            .key(keypair.private_key.clone())
            .iss("did:web:issuer.com")
            .kid("test_kid_1")
            .key_format(KeyFormat::PEM)
            .build(),
    );

    let verification_resolver = Arc::new(
        StaticVerificationKeyResolver::builder()
            .key(keypair.public_key.clone())
            .key_format(KeyFormat::PEM)
            .build(),
    );

    let generator = Arc::new(
        LocalJwtGenerator::builder()
            .signing_key_resolver(signing_resolver)
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .clock(clock.clone())
            .build(),
    );

    let verifier = Arc::new(
        LocalJwtVerifier::builder()
            .verification_key_resolver(verification_resolver)
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .leeway_seconds(86400 * 365 * 30) // 30-years leeway for testing with mock times
            .build(),
    );

    let store = Arc::new(MemoryRenewableTokenStore::new());

    let manager = JwtTokenManager::builder()
        .issuer("did:web:issuer.com")
        .refresh_endpoint("http://localhost:8080/refresh")
        .server_secret(b"this_is_exactly_32bytes_long!!!!".to_vec())
        .token_duration(3600) // 1 hour
        .renewal_token_duration(86400) // 24 hours
        .clock(clock)
        .token_store(store.clone())
        .token_generator(generator.clone())
        .token_verifier(verifier.clone())
        .build();

    TestFixture {
        manager,
        store,
        generator,
        verifier,
    }
}

/// Helper to create a bound token (JWT containing the access token)
async fn create_bound_token(
    fixture: &TestFixture,
    participant_context: &ParticipantContext,
    subject: &str,
    access_token: &str,
    clock: Arc<dyn Clock>,
) -> String {
    let mut custom = serde_json::Map::new();
    custom.insert("token".to_string(), Value::String(access_token.to_string()));

    let claims = TokenClaims::builder()
        .iss("did:web:issuer.com")
        .sub(subject)
        .aud(participant_context.identifier.clone())
        .exp(clock.now().timestamp() + 300) // 5 minutes
        .custom(custom)
        .build();

    fixture
        .generator
        .generate_token(participant_context, claims)
        .await
        .expect("Failed to generate bound token")
}

// =============================================================================
// Generate Pair Tests
// =============================================================================

#[tokio::test]
async fn test_generate_pair_success() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    let result = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await;

    assert!(
        result.is_ok(),
        "generate_pair should succeed: {:?}",
        result.as_ref().err()
    );
    let pair = result.unwrap();

    assert!(!pair.token.is_empty(), "Token should not be empty");
    assert!(!pair.refresh_token.is_empty(), "Refresh token should not be empty");
    assert_eq!(pair.refresh_endpoint, "http://localhost:8080/refresh");
    assert_eq!(
        pair.expires_at.timestamp(),
        fixed_time.timestamp() + 86400,
        "Expires at should be 24 hours from now"
    );
}

#[tokio::test]
async fn test_generate_pair_token_is_valid_jwt() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    let mut custom_claims = HashMap::new();
    custom_claims.insert("role".to_string(), "admin".to_string());
    custom_claims.insert("department".to_string(), "engineering".to_string());

    let pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", custom_claims)
        .await
        .expect("generate_pair should succeed");

    // Verify the token using the fixture's verifier
    let claims = fixture
        .verifier
        .verify_token(&pc, &pair.token)
        .expect("Token should be valid");

    assert_eq!(claims.sub, "did:web:consumer.com");
    assert_eq!(claims.iss, "did:web:issuer.com");
    assert_eq!(claims.aud, "did:web:provider.com");
    assert_eq!(claims.exp, fixed_time.timestamp() + 3600);

    // Verify custom claims
    assert_eq!(claims.custom.get("role").and_then(|v| v.as_str()), Some("admin"));
    assert_eq!(
        claims.custom.get("department").and_then(|v| v.as_str()),
        Some("engineering")
    );

    // Verify jti is present
    assert!(claims.custom.contains_key("jti"));
}

#[tokio::test]
async fn test_generate_pair_stores_token_entry() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    let mut custom_claims = HashMap::new();
    custom_claims.insert("custom_field".to_string(), "custom_value".to_string());

    let pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", custom_claims.clone())
        .await
        .expect("generate_pair should succeed");

    // Verify the entry is stored by attempting to retrieve it using the hashed refresh token
    let hash = fixture.manager.hash(&pair.refresh_token).expect("Hash should succeed");
    let entry = fixture
        .store
        .find_by_renewal(&pc, &hash)
        .await
        .expect("Entry should be found");

    assert_eq!(entry.token, pair.token);
    assert_eq!(entry.subject, "did:web:consumer.com");
    assert_eq!(entry.expires_at, pair.expires_at);
    assert_eq!(entry.claims, custom_claims);
}

#[tokio::test]
async fn test_generate_pair_refresh_token_is_unique() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    let pair1 = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    let pair2 = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    let pair3 = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    assert_ne!(
        pair1.refresh_token, pair2.refresh_token,
        "Refresh tokens should be unique"
    );
    assert_ne!(
        pair2.refresh_token, pair3.refresh_token,
        "Refresh tokens should be unique"
    );
    assert_ne!(
        pair1.refresh_token, pair3.refresh_token,
        "Refresh tokens should be unique"
    );
}

#[tokio::test]
async fn test_generate_pair_with_empty_custom_claims() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    let result = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await;

    assert!(result.is_ok(), "Should accept empty custom claims");
}

// =============================================================================
// Renew Tests
// =============================================================================

#[tokio::test]
async fn test_renew_success() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    // First generate a token pair
    let original_pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    // Create bound token
    let bound_token = create_bound_token(
        &fixture,
        &pc,
        "did:web:consumer.com",
        &original_pair.token,
        clock.clone(),
    )
    .await;

    // Now renew the token
    let renewed_pair = fixture
        .manager
        .renew(&pc, &bound_token, &original_pair.refresh_token)
        .await
        .expect("renew should succeed");

    assert!(!renewed_pair.token.is_empty(), "Renewed token should not be empty");
    assert_ne!(
        renewed_pair.token, original_pair.token,
        "Renewed token should be different from original"
    );
    assert_ne!(
        renewed_pair.refresh_token, original_pair.refresh_token,
        "Renewed refresh token should be different"
    );
    assert_eq!(renewed_pair.refresh_endpoint, "http://localhost:8080/refresh");
}

#[tokio::test]
async fn test_renew_preserves_subject_and_claims() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    let mut custom_claims = HashMap::new();
    custom_claims.insert("role".to_string(), "admin".to_string());
    custom_claims.insert("scope".to_string(), "read:write".to_string());

    // Generate original pair
    let original_pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", custom_claims)
        .await
        .expect("generate_pair should succeed");

    // Create bound token
    let bound_token = create_bound_token(
        &fixture,
        &pc,
        "did:web:consumer.com",
        &original_pair.token,
        clock.clone(),
    )
    .await;

    // Renew
    let renewed_pair = fixture
        .manager
        .renew(&pc, &bound_token, &original_pair.refresh_token)
        .await
        .expect("renew should succeed");

    // Verify the renewed token
    let claims = fixture
        .verifier
        .verify_token(&pc, &renewed_pair.token)
        .expect("Renewed token should be valid");

    assert_eq!(claims.sub, "did:web:consumer.com", "Subject should be preserved");
    assert_eq!(
        claims.custom.get("role").and_then(|v| v.as_str()),
        Some("admin"),
        "Custom claims should be preserved"
    );
    assert_eq!(
        claims.custom.get("scope").and_then(|v| v.as_str()),
        Some("read:write"),
        "Custom claims should be preserved"
    );
}

#[tokio::test]
async fn test_renew_invalid_refresh_token() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    // Generate a token pair
    let original_pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    // Create bound token
    let bound_token = create_bound_token(
        &fixture,
        &pc,
        "did:web:consumer.com",
        &original_pair.token,
        clock.clone(),
    )
    .await;

    // Try to renew with invalid refresh token
    let result = fixture.manager.renew(&pc, &bound_token, "invalid_refresh_token").await;

    assert!(result.is_err(), "Should reject invalid refresh token");
    match result.unwrap_err() {
        crate::token::TokenError::NotAuthorized(msg) => {
            assert_eq!(msg, "Invalid refresh token");
        }
        other => panic!("Expected NotAuthorized error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_renew_subject_mismatch() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    // Generate a token pair for user123
    let original_pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    // Create bound token with DIFFERENT subject
    let bound_token = create_bound_token(
        &fixture,
        &pc,
        "did:web:different-consumer.com", // Different subject!
        &original_pair.token,
        clock.clone(),
    )
    .await;

    // Try to renew - should fail due to subject mismatch
    let result = fixture
        .manager
        .renew(&pc, &bound_token, &original_pair.refresh_token)
        .await;

    assert!(result.is_err(), "Should reject subject mismatch");
    match result.unwrap_err() {
        crate::token::TokenError::NotAuthorized(msg) => {
            assert_eq!(msg, "Subject mismatch");
        }
        other => panic!("Expected NotAuthorized error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_renew_missing_token_claim() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    // Generate a token pair
    let original_pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    // Create bound token without "token" claim
    let claims = TokenClaims::builder()
        .iss("did:web:issuer.com")
        .sub("did:web:consumer.com")
        .aud(pc.identifier.clone())
        .exp(clock.now().timestamp() + 300)
        .build();

    let bound_token = fixture
        .generator
        .generate_token(&pc, claims)
        .await
        .expect("Should generate token");

    // Try to renew - should fail due to missing token claim
    let result = fixture
        .manager
        .renew(&pc, &bound_token, &original_pair.refresh_token)
        .await;

    assert!(result.is_err(), "Should reject missing token claim");
    match result.unwrap_err() {
        crate::token::TokenError::NotAuthorized(msg) => {
            assert_eq!(msg, "Missing token claim");
        }
        other => panic!("Expected NotAuthorized error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_renew_token_mismatch() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    // Generate a token pair
    let original_pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    // Create bound token with WRONG token value
    let bound_token = create_bound_token(
        &fixture,
        &pc,
        "did:web:consumer.com",
        "wrong_token_value", // Wrong token!
        clock.clone(),
    )
    .await;

    // Try to renew - should fail due to token mismatch
    let result = fixture
        .manager
        .renew(&pc, &bound_token, &original_pair.refresh_token)
        .await;

    assert!(result.is_err(), "Should reject token mismatch");
    match result.unwrap_err() {
        crate::token::TokenError::NotAuthorized(msg) => {
            assert_eq!(msg, "Invalid token");
        }
        other => panic!("Expected NotAuthorized error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_renew_uses_consistent_expiration_time() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    // Generate original pair
    let original_pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    let original_expiration = original_pair.expires_at;

    // Create bound token
    let bound_token = create_bound_token(
        &fixture,
        &pc,
        "did:web:consumer.com",
        &original_pair.token,
        clock.clone(),
    )
    .await;

    // Renew - with the same clock, expiration should be the same as original
    let renewed_pair = fixture
        .manager
        .renew(&pc, &bound_token, &original_pair.refresh_token)
        .await
        .expect("renew should succeed");

    // Renewed token should have the same expiration time (since clock hasn't advanced)
    let expected_expiration = (fixed_time + TimeDelta::hours(24)).timestamp();
    assert_eq!(
        renewed_pair.expires_at.timestamp(),
        expected_expiration,
        "Expiration should be based on clock time"
    );
    assert_eq!(
        renewed_pair.expires_at, original_expiration,
        "With same clock time, expiration should be consistent"
    );
}

// =============================================================================
// Round-trip Tests (generate + renew)
// =============================================================================

#[tokio::test]
async fn test_round_trip_generate_and_renew() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    let mut custom_claims = HashMap::new();
    custom_claims.insert("org_id".to_string(), "org123".to_string());

    // Step 1: Generate token pair
    let original_pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", custom_claims)
        .await
        .expect("generate_pair should succeed");

    // Step 2: Create bound token
    let bound_token = create_bound_token(
        &fixture,
        &pc,
        "did:web:consumer.com",
        &original_pair.token,
        clock.clone(),
    )
    .await;

    // Step 3: Renew the token
    let renewed_pair = fixture
        .manager
        .renew(&pc, &bound_token, &original_pair.refresh_token)
        .await
        .expect("renew should succeed");

    // Step 4: Verify the renewed token
    let claims = fixture
        .verifier
        .verify_token(&pc, &renewed_pair.token)
        .expect("Renewed token should be valid");

    assert_eq!(claims.sub, "did:web:consumer.com");
    assert_eq!(
        claims.custom.get("org_id").and_then(|v| v.as_str()),
        Some("org123"),
        "Custom claims should survive round-trip"
    );
}

#[tokio::test]
async fn test_round_trip_multiple_renewals() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    // Generate initial pair
    let mut current_pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    // Perform 3 sequential renewals
    for i in 1..=3 {
        let bound_token = create_bound_token(
            &fixture,
            &pc,
            "did:web:consumer.com",
            &current_pair.token,
            clock.clone(),
        )
        .await;

        let renewed_pair = fixture
            .manager
            .renew(&pc, &bound_token, &current_pair.refresh_token)
            .await
            .unwrap_or_else(|_| panic!("Renewal {} should succeed", i));

        // Verify each renewal produces different tokens
        assert_ne!(
            renewed_pair.token, current_pair.token,
            "Renewal {} should produce new token",
            i
        );
        assert_ne!(
            renewed_pair.refresh_token, current_pair.refresh_token,
            "Renewal {} should produce new refresh token",
            i
        );

        current_pair = renewed_pair;
    }
}

#[tokio::test]
async fn test_round_trip_old_refresh_token_invalid_after_renewal() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    // Generate initial pair
    let original_pair = fixture
        .manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    let bound_token1 = create_bound_token(
        &fixture,
        &pc,
        "did:web:consumer.com",
        &original_pair.token,
        clock.clone(),
    )
    .await;

    // First renewal
    let renewed_pair = fixture
        .manager
        .renew(&pc, &bound_token1, &original_pair.refresh_token)
        .await
        .expect("First renewal should succeed");

    // Try to use the old refresh token again - should fail
    let bound_token2 = create_bound_token(
        &fixture,
        &pc,
        "did:web:consumer.com",
        &original_pair.token,
        clock.clone(),
    )
    .await;

    let result = fixture
        .manager
        .renew(&pc, &bound_token2, &original_pair.refresh_token)
        .await;

    assert!(result.is_err(), "Old refresh token should not work after renewal");

    // But the new refresh token should work
    let bound_token3 = create_bound_token(
        &fixture,
        &pc,
        "did:web:consumer.com",
        &renewed_pair.token,
        clock.clone(),
    )
    .await;

    let result = fixture
        .manager
        .renew(&pc, &bound_token3, &renewed_pair.refresh_token)
        .await;

    assert!(result.is_ok(), "New refresh token should work");
}

#[tokio::test]
async fn test_security_different_participants_isolated() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;
    let fixture = create_jwt_token_manager(clock.clone());

    let pc1 = ParticipantContext::builder()
        .id("12345")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();

    let pc2 = ParticipantContext::builder()
        .id("did:web:provider2.com")
        .identifier("did:web:provider2.com")
        .audience("did:web:provider2.com")
        .build();

    // Generate token for participant1
    let pair1 = fixture
        .manager
        .generate_pair(&pc1, "did:web:consumer.com", HashMap::new())
        .await
        .expect("generate_pair should succeed");

    // Try to use participant1's refresh token with participant2 context
    let bound_token = create_bound_token(&fixture, &pc2, "did:web:consumer.com", &pair1.token, clock.clone()).await;

    let result = fixture.manager.renew(&pc2, &bound_token, &pair1.refresh_token).await;

    assert!(
        result.is_err(),
        "Should not be able to use participant1's token with participant2 context"
    );
}
