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

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeDelta, Utc};
use dataplane_sdk::core::db::memory::MemoryContext;
use dataplane_sdk::core::db::tx::TransactionalContext;
use dataplane_sdk::core::handler::DataFlowHandler;
use dataplane_sdk::core::model::data_address::{DataAddress, EndpointProperty};
use dataplane_sdk::core::model::data_flow::DataFlow;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::jwtutils::{
    StaticSigningKeyResolver, StaticVerificationKeyResolver, generate_ed25519_keypair_pem,
};
use dsdk_facet_core::jwt::{KeyFormat, LocalJwtGenerator, LocalJwtVerifier, SigningAlgorithm};
use dsdk_facet_core::token::client::{MemoryTokenStore, TokenStore};
use dsdk_facet_core::token::manager::{JwtTokenManager, MemoryRenewableTokenStore};
use dsdk_facet_core::util::clock::{Clock, MockClock};
use serde_json::Value;
use siglet::handler::{
    SigletDataFlowHandler, CLAIM_AGREEMENT_ID, CLAIM_COUNTER_PARTY_ID, CLAIM_DATASET_ID, CLAIM_PARTICIPANT_ID,
};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn test_on_start_token_created() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_start(&mut tx, &flow).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Extract the JWT token from the data address
    let data_address = response.data_address.expect("Data address should be present");
    let token = data_address
        .get_property("authorization")
        .expect("Authorization token should be present");

    // Parse the JWT structure
    let token_parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        token_parts.len(),
        3,
        "JWT should have 3 parts (header.payload.signature)"
    );

    // Decode the payload (second part) from base64
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(token_parts[1])
        .expect("Failed to decode JWT payload");
    let payload_str = String::from_utf8(payload_bytes).expect("Failed to convert payload to string");
    let jwt_payload: serde_json::Value =
        serde_json::from_str(&payload_str).expect("Failed to parse JWT payload as JSON");

    // Verify the metadata claims are present in the JWT
    assert_eq!(
        jwt_payload.get("key1").and_then(|v| v.as_str()),
        Some("value1"),
        "key1 should be present in JWT with correct value"
    );
    assert_eq!(
        jwt_payload.get("key2").and_then(|v| v.as_str()),
        Some("value2"),
        "key2 should be present in JWT with correct value"
    );

    // Verify additional flow-based claims are present in the JWT
    assert_eq!(
        jwt_payload.get(CLAIM_AGREEMENT_ID).and_then(|v| v.as_str()),
        Some("agreement-1"),
        "agreementId should be present in JWT with correct value"
    );
    assert_eq!(
        jwt_payload.get(CLAIM_PARTICIPANT_ID).and_then(|v| v.as_str()),
        Some("participant-1"),
        "participantId should be present in JWT with correct value"
    );
    assert_eq!(
        jwt_payload.get(CLAIM_COUNTER_PARTY_ID).and_then(|v| v.as_str()),
        Some("counter-party-1"),
        "counterPartyId should be present in JWT with correct value"
    );
    assert_eq!(
        jwt_payload.get(CLAIM_DATASET_ID).and_then(|v| v.as_str()),
        Some("dataset-1"),
        "datasetId should be present in JWT with correct value"
    );

    let result = handler.on_suspend(&mut tx, &flow).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_on_suspend_succeeds() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_start(&mut tx, &flow).await;

    assert!(result.is_ok());
    let result = handler.on_suspend(&mut tx, &flow).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_on_started_saves_token_to_store() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store.clone())
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .build();
    let expires_at = Utc::now() + TimeDelta::hours(1);
    let expires_at_str = expires_at.to_rfc3339();

    let data_address = DataAddress::builder()
        .endpoint_type("HttpData")
        .endpoint_properties(vec![
            create_endpoint_property("endpoint", "https://example.com/data"),
            create_endpoint_property("access_token", "token-id-123"),
            create_endpoint_property("token", "access-token-value"),
            create_endpoint_property("refresh_token", "refresh-token-value"),
            create_endpoint_property("refresh_endpoint", "https://example.com/refresh"),
            create_endpoint_property("expires_at", &expires_at_str),
        ])
        .build();

    let flow = create_test_flow_with_data_address("flow-1", "participant-1", "http-pull", data_address);

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_ok());

    // Verify token was saved to the store
    let participant_ctx = ParticipantContext::builder().id("participant-1").build();
    let saved_token = token_store.get_token(&participant_ctx, "flow-1").await;
    assert!(saved_token.is_ok());

    let token_data = saved_token.unwrap();
    assert_eq!(token_data.identifier, "flow-1");
    assert_eq!(token_data.participant_context, "participant-1");
    assert_eq!(token_data.token, "access-token-value");
    assert_eq!(token_data.refresh_token, "refresh-token-value");
    assert_eq!(token_data.refresh_endpoint, "https://example.com/refresh");
}

#[tokio::test]
async fn test_on_started_without_data_address_succeeds() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_on_started_with_missing_endpoint_fails() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .build();

    let data_address = DataAddress::builder()
        .endpoint_type("HttpData")
        .endpoint_properties(vec![create_endpoint_property("access_token", "token-id-123")])
        .build();

    let flow = create_test_flow_with_data_address("flow-1", "participant-1", "http-pull", data_address);

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("endpoint"));
}

#[tokio::test]
async fn test_on_started_with_missing_access_token_fails() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .build();

    let data_address = DataAddress::builder()
        .endpoint_type("HttpData")
        .endpoint_properties(vec![create_endpoint_property("endpoint", "https://example.com/data")])
        .build();

    let flow = create_test_flow_with_data_address("flow-1", "participant-1", "http-pull", data_address);

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("access_token"));
}

#[tokio::test]
async fn test_on_started_with_missing_token_fails() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .build();

    let data_address = DataAddress::builder()
        .endpoint_type("HttpData")
        .endpoint_properties(vec![
            create_endpoint_property("endpoint", "https://example.com/data"),
            create_endpoint_property("access_token", "token-id-123"),
        ])
        .build();

    let flow = create_test_flow_with_data_address("flow-1", "participant-1", "http-pull", data_address);

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("token"));
}

/// Helper to create a JwtTokenManager with real JWT generator/verifier for testing
fn create_jwt_token_manager() -> Arc<JwtTokenManager> {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;

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

    let token_store = Arc::new(MemoryRenewableTokenStore::new());

    Arc::new(
        JwtTokenManager::builder()
            .issuer("did:web:issuer.com")
            .refresh_endpoint("http://localhost:8080/refresh")
            .server_secret(b"this_is_exactly_32bytes_long!!!!".to_vec())
            .token_duration(3600) // 1 hour
            .renewal_token_duration(86400) // 24 hours
            .clock(clock)
            .token_store(token_store)
            .token_generator(generator)
            .token_verifier(verifier)
            .build(),
    )
}

/// Helper to create endpoint properties for DataAddress
fn create_endpoint_property(name: &str, value: &str) -> EndpointProperty {
    EndpointProperty::builder().name(name).value(value).build()
}

/// Helper function to create a test DataFlow with required fields
fn create_test_flow(id: &str, participant_id: &str, transfer_type: &str) -> DataFlow {
    let mut metadata = HashMap::new();
    metadata.insert("key1".to_string(), Value::String("value1".to_string()));
    metadata.insert("key2".to_string(), Value::String("value2".to_string()));
    DataFlow::builder()
        .id(id)
        .participant_id(participant_id)
        .transfer_type(transfer_type)
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
        .participant_context_id("context-1")
        .metadata(metadata)
        .build()
}

/// Helper function to create a test DataFlow with data address
fn create_test_flow_with_data_address(
    id: &str,
    participant_id: &str,
    transfer_type: &str,
    data_address: DataAddress,
) -> DataFlow {
    DataFlow::builder()
        .id(id)
        .participant_id(participant_id)
        .transfer_type(transfer_type)
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
        .participant_context_id("context-1")
        .data_address(data_address)
        .build()
}
