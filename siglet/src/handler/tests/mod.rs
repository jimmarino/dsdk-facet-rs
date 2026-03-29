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

use crate::config::{TokenSource, TransferTypes};
use crate::handler::SigletDataFlowHandler;
use dataplane_sdk::core::handler::DataFlowHandler;
use dataplane_sdk::core::model::data_flow::DataFlow;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::token::client::MemoryTokenStore;
use dsdk_facet_core::token::manager::{RenewableTokenPair, TokenManager};
use dsdk_facet_core::token::TokenError;
use std::collections::HashMap;
use std::sync::Arc;

/// Mock TokenManager for testing
struct MockTokenManager;

#[async_trait::async_trait]
impl TokenManager for MockTokenManager {
    async fn generate_pair(
        &self,
        _participant_context: &ParticipantContext,
        _subject: &str,
        _claims: HashMap<String, String>,
        _flow_id: String,
    ) -> Result<RenewableTokenPair, TokenError> {
        Ok(RenewableTokenPair::builder()
            .token("mock_token".to_string())
            .refresh_token("mock_refresh_token".to_string())
            .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
            .refresh_endpoint("https://mock.endpoint/refresh".to_string())
            .build())
    }

    async fn renew(
        &self,
        _participant_context: &ParticipantContext,
        _bound_token: &str,
        _refresh_token: &str,
    ) -> Result<RenewableTokenPair, TokenError> {
        Ok(RenewableTokenPair::builder()
            .token("mock_renewed_token".to_string())
            .refresh_token("mock_new_refresh_token".to_string())
            .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
            .refresh_endpoint("https://mock.endpoint/refresh".to_string())
            .build())
    }

    async fn revoke_token(
        &self,
        _participant_context: &ParticipantContext,
        _flow_id: &str,
    ) -> Result<(), TokenError> {
        Ok(())
    }
}

/// Helper function to create a test DataFlow with required fields
fn create_test_flow(id: &str, participant_id: &str, transfer_type: &str) -> DataFlow {
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
        .build()
}

/// Helper function to create a TransferTypes configuration
fn create_transfer_type(transfer_type: &str, endpoint_type: &str, token_source: TokenSource) -> TransferTypes {
    TransferTypes::builder()
        .transfer_type(transfer_type.to_string())
        .endpoint_type(endpoint_type.to_string())
        .token_source(token_source)
        .build()
}

#[tokio::test]
async fn test_can_handle_with_default_accepts_http_pull() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let handler = SigletDataFlowHandler::builder()
        .dataplane_id("dataplane-1")
        .token_store(token_store)
        .token_manager(token_manager)
        .build();

    // Default includes http-pull
    let flow = create_test_flow("flow-1", "participant-1", "http-pull");
    let result = handler.can_handle(&flow).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Default does not include other transfer types
    let flow2 = create_test_flow("flow-2", "participant-1", "http-push");
    let result2 = handler.can_handle(&flow2).await;
    assert!(result2.is_ok());
    assert!(!result2.unwrap());
}

#[tokio::test]
async fn test_can_handle_with_matching_transfer_type_accepts() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", TokenSource::Provider),
    );
    mappings.insert(
        "http-push".to_string(),
        create_transfer_type("http-push", "HTTP", TokenSource::Client),
    );

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("dataplane-1")
        .transfer_type_mappings(mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let result = handler.can_handle(&flow).await;
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[tokio::test]
async fn test_can_handle_with_non_matching_transfer_type_rejects() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", TokenSource::Provider),
    );
    mappings.insert(
        "http-push".to_string(),
        create_transfer_type("http-push", "HTTP", TokenSource::Client),
    );

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "UnknownData");

    let result = handler.can_handle(&flow).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_can_handle_with_single_transfer_type() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", TokenSource::Provider),
    );

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    // Should accept http-pull
    let flow1 = create_test_flow("flow-1", "participant-1", "http-pull");

    let result = handler.can_handle(&flow1).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Should reject http-push
    let flow2 = create_test_flow("flow-2", "participant-1", "http-push");

    let result = handler.can_handle(&flow2).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_on_start_generates_token_for_provider_token_source() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", TokenSource::Provider),
    );

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_start(&mut tx, &flow).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    let data_address = response.data_address.unwrap();

    // Verify token properties are present
    assert!(data_address.get_property("authorization").is_some());
    assert!(data_address.get_property("authType").is_some());
    assert!(data_address.get_property("refreshToken").is_some());
    assert!(data_address.get_property("expiresIn").is_some());
    assert!(data_address.get_property("refreshEndpoint").is_some());
}

#[tokio::test]
async fn test_on_start_skips_token_for_client_token_source() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-push".to_string(),
        create_transfer_type("http-push", "HTTP", TokenSource::Client),
    );

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-push");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_start(&mut tx, &flow).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    let data_address = response.data_address.unwrap();

    // Verify no token properties are present
    assert!(data_address.get_property("authorization").is_none());
    assert!(data_address.get_property("authType").is_none());
    assert!(data_address.get_property("refreshToken").is_none());
    assert!(data_address.get_property("expiresIn").is_none());
    assert!(data_address.get_property("refreshEndpoint").is_none());
}

#[tokio::test]
async fn test_on_start_skips_token_for_none_token_source() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "s3-pull".to_string(),
        create_transfer_type("s3-pull", "S3", TokenSource::None),
    );

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "s3-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_start(&mut tx, &flow).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    let data_address = response.data_address.unwrap();

    // Verify no token properties are present
    assert!(data_address.get_property("authorization").is_none());
    assert!(data_address.get_property("authType").is_none());
    assert!(data_address.get_property("refreshToken").is_none());
    assert!(data_address.get_property("expiresIn").is_none());
    assert!(data_address.get_property("refreshEndpoint").is_none());
}

#[tokio::test]
async fn test_on_prepare_generates_token_for_client_token_source() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-push".to_string(),
        create_transfer_type("http-push", "HTTP", TokenSource::Client),
    );

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-push");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_prepare(&mut tx, &flow).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    let data_address = response.data_address.unwrap();

    // Verify token properties are present
    assert!(data_address.get_property("authorization").is_some());
    assert!(data_address.get_property("authType").is_some());
    assert!(data_address.get_property("refreshToken").is_some());
    assert!(data_address.get_property("expiresIn").is_some());
    assert!(data_address.get_property("refreshEndpoint").is_some());
}

#[tokio::test]
async fn test_on_prepare_skips_token_for_provider_token_source() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", TokenSource::Provider),
    );

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_prepare(&mut tx, &flow).await;
    assert!(result.is_ok());

    let response = result.unwrap();

    // Verify no data address is present
    assert!(response.data_address.is_none());
}

#[tokio::test]
async fn test_on_prepare_skips_token_for_none_token_source() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "s3-pull".to_string(),
        create_transfer_type("s3-pull", "S3", TokenSource::None),
    );

    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "s3-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_prepare(&mut tx, &flow).await;
    assert!(result.is_ok());

    let response = result.unwrap();

    // Verify no data address is present
    assert!(response.data_address.is_none());
}
