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
use bon::Builder;
use dataplane_sdk::core::error::HandlerError;
use dataplane_sdk::core::model::data_address::DataAddress;
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
use dsdk_facet_core::token::client::{TokenData, TokenStore};
use std::collections::HashMap;
use std::sync::Arc;

/// DataFlowHandler implementation for Siglet
#[derive(Clone, Builder)]
pub struct SigletDataFlowHandler {
    token_store: Arc<dyn TokenStore>,
    // jwt_generator: Arc<dyn JwtGenerator>,
    // #[builder(into)]
    // issuer: String,
    // #[builder(into)]
    // subject: String,
    // #[builder(into)]
    // audience: String,
    #[builder(into)]
    dataplane_id: String,
    //
    // #[builder(into)]
    // refresh_endpoint: String,
    //
    // token_duration: i64,
    // renewal_token_duration: i64,
    //
    // #[builder(default = default_clock())]
    // clock: Arc<dyn Clock>,
    /// Transfer types to endpoint types that this handler can process
    #[builder(default)]
    endpoint_type_mappings: HashMap<String, String>,
}

impl SigletDataFlowHandler {}

#[async_trait::async_trait]
impl DataFlowHandler for SigletDataFlowHandler {
    type Transaction = <MemoryContext as TransactionalContext>::Transaction;

    async fn can_handle(&self, flow: &DataFlow) -> HandlerResult<bool> {
        // If no transfer types are configured, accept all flows
        if self.endpoint_type_mappings.is_empty() {
            return Ok(true);
        }

        Ok(self.endpoint_type_mappings.contains_key(&flow.transfer_type))
    }

    async fn on_start(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<DataFlowResponseMessage> {
        let data_address = DataAddress::builder()
            .endpoint_type(
                self.endpoint_type_mappings
                    .get(&flow.transfer_type)
                    .unwrap_or(&"HTTP".to_string()),
            )
            .build();

        Ok(DataFlowResponseMessage::builder()
            .dataplane_id(self.dataplane_id.clone())
            .state(DataFlowState::Started)
            .data_address(data_address)
            .build())
    }

    async fn on_prepare(
        &self,
        _tx: &mut Self::Transaction,
        _flow: &DataFlow,
    ) -> HandlerResult<DataFlowResponseMessage> {
        // TODO: Create token if configured (consumer side)

        Ok(DataFlowResponseMessage::builder()
            .dataplane_id("siglet")
            .state(DataFlowState::Prepared)
            .build())
    }

    async fn on_terminate(&self, _tx: &mut Self::Transaction, _flow: &DataFlow) -> HandlerResult<()> {
        // TODO: Revoke tokens
        Ok(())
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

    async fn on_suspend(&self, _tx: &mut Self::Transaction, _flow: &DataFlow) -> HandlerResult<()> {
        // TODO: Handle suspend event
        // TODO on consumer, revoke token
        Ok(())
    }
}

#[cfg(test)]
mod tests;
