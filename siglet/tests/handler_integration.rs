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
use dataplane_sdk::core::db::memory::MemoryContext;
use dataplane_sdk::core::db::tx::TransactionalContext;
use dataplane_sdk::core::handler::DataFlowHandler;
use dataplane_sdk::core::model::data_address::{DataAddress, EndpointProperty};
use dataplane_sdk::core::model::data_flow::DataFlow;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::client::{MemoryTokenStore, TokenStore};
use dsdk_facet_core::token::manager::{RenewableTokenPair, TokenManager};
use siglet::handler::SigletDataFlowHandler;
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
            .expires_at(Utc::now() + chrono::Duration::hours(1))
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
            .expires_at(Utc::now() + chrono::Duration::hours(1))
            .refresh_endpoint("https://mock.endpoint/refresh".to_string())
            .build())
    }
}

/// Helper to create endpoint properties for DataAddress
fn create_endpoint_property(name: &str, value: &str) -> EndpointProperty {
    EndpointProperty::builder().name(name).value(value).build()
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

#[tokio::test]
async fn test_on_suspend_succeeds() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
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
    let token_manager = Arc::new(MockTokenManager);
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
    let token_manager = Arc::new(MockTokenManager);
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
    let token_manager = Arc::new(MockTokenManager);
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
    let token_manager = Arc::new(MockTokenManager);
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
    let token_manager = Arc::new(MockTokenManager);
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
