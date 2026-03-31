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
use crate::config::{TokenSource, TransferTypes};
use bon::Builder;
use chrono::Utc;
use dataplane_sdk::core::error::HandlerError;
use dataplane_sdk::core::model::data_address::{DataAddress, EndpointProperty};
use dataplane_sdk::core::{
    db::memory::MemoryContext,
    db::tx::TransactionalContext,
    error::HandlerResult,
    handler::DataFlowHandler,
    model::{
        data_flow::{DataFlow, DataFlowState},
        messages::DataFlowResponseMessage,
    },
};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::client::{TokenData, TokenStore};
use dsdk_facet_core::token::manager::{RenewableTokenPair, TokenManager};
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// DataFlowHandler implementation for Siglet
#[derive(Clone, Builder)]
pub struct SigletDataFlowHandler {
    #[builder(into)]
    dataplane_id: String,

    token_store: Arc<dyn TokenStore>,

    token_manager: Arc<dyn TokenManager>,

    #[builder(default = default_transfer_type_mappings())]
    transfer_type_mappings: HashMap<String, TransferTypes>,
}

fn default_transfer_type_mappings() -> HashMap<String, TransferTypes> {
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        TransferTypes::builder()
            .transfer_type("http-pull".to_string())
            .endpoint_type("HTTP".to_string())
            .token_source(TokenSource::Provider)
            .build(),
    );
    mappings
}

impl SigletDataFlowHandler {
    /// Generates authentication properties from a token pair
    fn create_auth_properties(pair: &RenewableTokenPair) -> Vec<EndpointProperty> {
        vec![
            EndpointProperty::builder()
                .name("authorization")
                .value(&pair.token)
                .build(),
            EndpointProperty::builder().name("authType").value("bearer").build(),
            EndpointProperty::builder()
                .name("refreshToken")
                .value(&pair.refresh_token)
                .build(),
            EndpointProperty::builder()
                .name("expiresIn")
                .value((pair.expires_at.timestamp() - Utc::now().timestamp()).to_string())
                .build(),
            EndpointProperty::builder()
                .name("refreshEndpoint")
                .value(&pair.refresh_endpoint)
                .build(),
        ]
    }

    /// Generates a token pair if the token source is Provider
    async fn generate_token_if_needed(
        &self,
        participant_context: &ParticipantContext,
        transfer_type_config: &TransferTypes,
        flow: &DataFlow,
    ) -> HandlerResult<Option<RenewableTokenPair>> {
        if !matches!(transfer_type_config.token_source, TokenSource::Provider) {
            return Ok(None);
        }

        let claims: HashMap<String, String> = flow.metadata.iter().map(|(k, v)| (k.clone(), v.to_string())).collect();

        let pair = self
            .token_manager
            .generate_pair(participant_context, &flow.counter_party_id, claims, flow.id.clone())
            .await
            .map_err(|e| HandlerError::Generic(format!("Failed to generate token pair: {}", e).into()))?;

        Ok(Some(pair))
    }

    /// Generates a token pair if the token source is Client (consumer side)
    async fn generate_client_token_if_needed(
        &self,
        participant_context: &ParticipantContext,
        transfer_type_config: &TransferTypes,
        flow: &DataFlow,
    ) -> HandlerResult<Option<RenewableTokenPair>> {
        if !matches!(transfer_type_config.token_source, TokenSource::Client) {
            return Ok(None);
        }

        let claims: HashMap<String, String> = flow.metadata.iter().map(|(k, v)| (k.clone(), v.to_string())).collect();

        let pair = self
            .token_manager
            .generate_pair(participant_context, &flow.counter_party_id, claims, flow.id.clone())
            .await
            .map_err(|e| HandlerError::Generic(format!("Failed to generate token pair: {}", e).into()))?;

        Ok(Some(pair))
    }

    async fn cleanup_tokens(
        &self,
        flow: &DataFlow,
        participant_context: &ParticipantContext,
    ) -> Result<HandlerResult<()>, HandlerError> {
        // TODO only revoke if this data plane is the token source, otherwise remove from the cache
        Ok(
            match self.token_manager.revoke_token(participant_context, &flow.id).await {
                Ok(_) => Ok(()),
                Err(TokenError::TokenNotFound { .. }) => {
                    // Ignore NotFound errors
                    self.token_store
                        .remove_token(participant_context.id.as_str(), flow.id.as_str())
                        .await
                        .map_err(|e| HandlerError::Generic(format!("Failed to remove token: {}", e).into()))?;
                    Ok(())
                }
                Err(e) => Err(HandlerError::Generic(format!("Failed to revoke token: {}", e).into())),
            },
        )
    }

    /// Extracts a ParticipantContext from a DataFlow
    ///
    /// This helper reduces duplication across handler methods that need
    /// to create participant context from flow data.
    fn build_participant_context(flow: &DataFlow) -> ParticipantContext {
        ParticipantContext::builder()
            .id(flow.participant_context_id.clone())
            .identifier(flow.participant_id.clone())
            .build()
    }
}

#[async_trait::async_trait]
impl DataFlowHandler for SigletDataFlowHandler {
    type Transaction = <MemoryContext as TransactionalContext>::Transaction;

    async fn can_handle(&self, flow: &DataFlow) -> HandlerResult<bool> {
        Ok(self.transfer_type_mappings.contains_key(&flow.transfer_type))
    }

    async fn on_start(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<DataFlowResponseMessage> {
        let participant_context = Self::build_participant_context(flow);

        let transfer_type_config = self.transfer_type_mappings.get(&flow.transfer_type).ok_or_else(|| {
            HandlerError::Generic(format!("Unsupported transfer type: {}", flow.transfer_type).into())
        })?;

        let endpoint_properties = self
            .generate_token_if_needed(&participant_context, transfer_type_config, flow)
            .await?
            .map(|pair| Self::create_auth_properties(&pair))
            .unwrap_or_default();

        let data_address = DataAddress::builder()
            .endpoint_type(&transfer_type_config.endpoint_type)
            .endpoint_properties(endpoint_properties)
            .build();

        Ok(DataFlowResponseMessage::builder()
            .dataplane_id(self.dataplane_id.clone())
            .state(DataFlowState::Started)
            .data_address(data_address)
            .build())
    }

    async fn on_prepare(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<DataFlowResponseMessage> {
        let participant_context = Self::build_participant_context(flow);

        let transfer_type_config = self.transfer_type_mappings.get(&flow.transfer_type).ok_or_else(|| {
            HandlerError::Generic(format!("Unsupported transfer type: {}", flow.transfer_type).into())
        })?;

        // On consumer side, generate token if token source is Client
        let maybe_token_pair = self
            .generate_client_token_if_needed(&participant_context, transfer_type_config, flow)
            .await?;

        // Transform token pair into data address if present
        let data_address = maybe_token_pair.map(|pair| {
            let endpoint_properties = Self::create_auth_properties(&pair);
            DataAddress::builder()
                .endpoint_type(&transfer_type_config.endpoint_type)
                .endpoint_properties(endpoint_properties)
                .build()
        });

        // Build response, using map_or to handle both cases without duplication
        let response = data_address.map_or_else(
            || {
                // No data address - build without it
                DataFlowResponseMessage::builder()
                    .dataplane_id(self.dataplane_id.clone())
                    .state(DataFlowState::Prepared)
                    .build()
            },
            |addr| {
                // With data address - include it
                DataFlowResponseMessage::builder()
                    .dataplane_id(self.dataplane_id.clone())
                    .state(DataFlowState::Prepared)
                    .data_address(addr)
                    .build()
            },
        );

        Ok(response)
    }

    async fn on_terminate(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<()> {
        let participant_context = Self::build_participant_context(flow);
        self.cleanup_tokens(flow, &participant_context).await?
    }

    async fn on_started(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<()> {
        if let Some(data_address) = flow.data_address.as_ref() {
            let _endpoint = data_address
                .get_property("endpoint")
                .ok_or_else(|| HandlerError::Generic("Data address must contain an endpoint property".into()))?;

            let _token_id = data_address
                .get_property("access_token")
                .ok_or_else(|| HandlerError::Generic("Data address must contain an access_token property".into()))?;

            let token = data_address.get_property("token");
            let refresh_endpoint = data_address.get_property("refresh_endpoint");
            let refresh_token = data_address.get_property("refresh_token");
            let expires_at = data_address.get_property("expires_at");

            let token_data = TokenData {
                identifier: flow.id.clone(),
                participant_context: flow.participant_id.clone(),
                token: token
                    .ok_or_else(|| HandlerError::Generic("Data address must contain a token property".into()))?
                    .to_string(),
                refresh_token: refresh_token
                    .ok_or_else(|| HandlerError::Generic("Data address must contain a refresh_token property".into()))?
                    .to_string(),
                expires_at: expires_at
                    .ok_or_else(|| HandlerError::Generic("Data address must contain an expires_at property".into()))
                    .and_then(|s| {
                        s.parse()
                            .map_err(|_| HandlerError::Generic("Invalid expires_at format".into()))
                    })?,
                refresh_endpoint: refresh_endpoint
                    .ok_or_else(|| {
                        HandlerError::Generic("Data address must contain a refresh_endpoint property".into())
                    })?
                    .to_string(),
            };

            self.token_store
                .save_token(token_data)
                .await
                .map_err(|e| HandlerError::Generic(format!("Failed to save token: {}", e).into()))?;
        }

        Ok(())
    }

    async fn on_suspend(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<()> {
        // TODO only revoke if this data plane is the token source, otherwise remove from the cache
        let participant_context = Self::build_participant_context(flow);
        self.cleanup_tokens(flow, &participant_context).await?
    }
}
