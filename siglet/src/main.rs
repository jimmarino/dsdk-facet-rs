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

use std::sync::Arc;
use std::collections::HashMap;

use dataplane_sdk::{
    core::{db::data_flow::memory::MemoryDataFlowRepo, db::memory::MemoryContext},
    sdk::DataPlaneSdk,
};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::token::client::MemoryTokenStore;
use dsdk_facet_core::token::manager::{TokenManager, RenewableTokenPair};
use dsdk_facet_core::token::TokenError;
use siglet::{
    config::{SigletConfig, StorageBackend, load_config},
    error::SigletError,
    handler::SigletDataFlowHandler,
    server::run_server,
};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

// TODO: Replace with proper TokenManager implementation
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
}

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber with info level default
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let cfg = load_config().unwrap_or_else(|e| {
        error!("Failed to load configuration: {}", e);
        SigletConfig::default()
    });

    match run(cfg).await {
        Ok(_) => info!("Shutdown"),
        Err(e) => {
            error!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn run(cfg: SigletConfig) -> Result<(), SigletError> {
    match cfg.storage_backend {
        StorageBackend::Memory => {
            let ctx = MemoryContext;
            let flow_repo = MemoryDataFlowRepo::default();
            let token_store = Arc::new(MemoryTokenStore::default());
            let token_manager = Arc::new(MockTokenManager);
            let handler = SigletDataFlowHandler::builder()
                .token_store(token_store)
                .token_manager(token_manager)
                .dataplane_id("dataplane-1")
                .build();

            let sdk = DataPlaneSdk::builder(ctx)
                .with_repo(flow_repo)
                .with_handler(handler)
                .build()
                .map_err(|e| SigletError::DataPlane(e.to_string()))?;

            run_server(cfg.bind, cfg.signaling_port, cfg.siglet_api_port, sdk).await
        }
        StorageBackend::Postgres => {
            todo!("Postgres storage backend not yet implemented")
        }
    }
}
