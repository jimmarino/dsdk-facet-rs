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
mod config;
mod handler;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    Extension, Router,
    response::{IntoResponse, Json},
    routing::get,
};
use config::{SigletConfig, StorageBackend, load_config};
use dataplane_sdk::{
    core::{
        db::data_flow::memory::MemoryDataFlowRepo, db::memory::MemoryContext, model::participant::ParticipantContext,
    },
    sdk::DataPlaneSdk,
};
use dataplane_sdk_axum::router::router as signaling_router;
use dsdk_facet_core::token::MemoryTokenStore;
use handler::SigletDataFlowHandler;
use serde_json::json;
use thiserror::Error;
use tokio::{signal, sync::Barrier};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Error, Debug)]
pub enum SigletError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DataPlane SDK error: {0}")]
    DataPlane(String),
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
            let handler = SigletDataFlowHandler::new(token_store);

            let sdk = DataPlaneSdk::builder(ctx)
                .with_repo(flow_repo)
                .with_handler(handler)
                .build()
                .map_err(|e| SigletError::DataPlane(e.to_string()))?;

            run_server(cfg, sdk).await
        }
        StorageBackend::Postgres => {
            todo!("Postgres storage backend not yet implemented")
        }
    }
}

async fn run_server(cfg: SigletConfig, sdk: DataPlaneSdk<MemoryContext>) -> Result<(), SigletError> {
    let barrier = Arc::new(Barrier::new(3));
    start_signaling_api(cfg.bind, cfg.signaling_port, sdk.clone(), barrier.clone()).await?;
    start_siglet_api(cfg.bind, cfg.siglet_api_port, barrier.clone()).await?;

    info!("Ready");

    barrier.wait().await;

    Ok(())
}

async fn start_signaling_api(
    bind: IpAddr,
    port: u16,
    sdk: DataPlaneSdk<MemoryContext>,
    barrier: Arc<Barrier>,
) -> Result<(), SigletError> {
    let addr: SocketAddr = format!("{}:{}", bind, port)
        .parse()
        .map_err(|e: std::net::AddrParseError| {
            SigletError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

    let p_context = ParticipantContext::builder().id("siglet-participant").build();

    let router = signaling_router().layer(Extension(p_context));

    info!("Signaling API {}", addr);

    tokio::task::spawn(async move {
        let app = router.layer(TraceLayer::new_for_http()).with_state(sdk);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("Failed to bind signaling API");

        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_shutdown())
            .await;

        barrier.wait().await;
    });

    Ok(())
}

async fn start_siglet_api(bind: IpAddr, port: u16, barrier: Arc<Barrier>) -> Result<(), SigletError> {
    let addr: SocketAddr = format!("{}:{}", bind, port)
        .parse()
        .map_err(|e: std::net::AddrParseError| {
            SigletError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

    let app = create_router();

    info!("Siglet API {}", addr);

    tokio::task::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("Failed to bind Siglet API");

        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_shutdown())
            .await;

        barrier.wait().await;
    });

    Ok(())
}

fn create_router() -> Router {
    Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
}

async fn root() -> impl IntoResponse {
    Json(json!({
        "name": "Siglet",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running"
    }))
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "healthy"
    }))
}

async fn wait_for_shutdown() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
