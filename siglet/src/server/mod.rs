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

use std::net::{IpAddr, SocketAddr};

use axum::{
    Extension, Router,
    response::{IntoResponse, Json},
    routing::get,
};
use dataplane_sdk::{
    core::{db::memory::MemoryContext, model::participant::ParticipantContext},
    sdk::DataPlaneSdk,
};
use dataplane_sdk_axum::router::router as signaling_router;
use serde_json::json;
use tokio::{signal, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use crate::assembly::DEFAULT_PARTICIPANT_ID;
use crate::error::SigletError;

#[cfg(test)]
mod tests;

// ============================================================================
// API Endpoint Constants
// ============================================================================

/// Root API endpoint path
const ENDPOINT_ROOT: &str = "/";

/// Health check endpoint path
const ENDPOINT_HEALTH: &str = "/health";

/// Application name for API responses
const APP_NAME: &str = "Siglet";

/// Status value for running state
const STATUS_RUNNING: &str = "running";

/// Status value for healthy state
const STATUS_HEALTHY: &str = "healthy";

// ============================================================================
// Server Functions
// ============================================================================

/// Run both signaling and siglet APIs with structured concurrency
///
/// This function uses JoinSet to manage multiple server tasks and provides:
/// - Proper error propagation from spawned tasks
/// - Graceful shutdown coordination via CancellationToken
/// - Fail-fast behavior: if one server fails, all are cancelled
pub async fn run_server(
    bind: IpAddr,
    signaling_port: u16,
    siglet_api_port: u16,
    sdk: DataPlaneSdk<MemoryContext>,
) -> Result<(), SigletError> {
    let mut join_set = JoinSet::new();
    let cancel_token = CancellationToken::new();

    // Spawn both server tasks
    join_set.spawn(run_signaling_api(
        bind,
        signaling_port,
        sdk.clone(),
        cancel_token.clone(),
    ));

    join_set.spawn(run_siglet_api(bind, siglet_api_port, cancel_token.clone()));

    info!("Ready");

    // Wait for shutdown signal OR first task to complete/fail
    tokio::select! {
        // Shutdown signal received (Ctrl+C or SIGTERM)
        _ = wait_for_shutdown() => {
            cancel_token.cancel();
        }

        // A server task completed (either successfully or with error)
        Some(result) = join_set.join_next() => {
            handle_task_result(result, &cancel_token, &mut join_set)?
        }
    }

    // Wait for all remaining tasks to complete
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(())) => {
                // Task completed successfully during cleanup
            }
            Ok(Err(e)) => {
                error!("Server task failed during cleanup: {}", e);
            }
            Err(e) => {
                error!("Server task panicked during cleanup: {}", e);
            }
        }
    }

    info!("Shutdown complete");
    Ok(())
}

/// Handles the result of a completed task
///
/// Returns Err if the task failed or panicked, which will cause
/// immediate shutdown of all other tasks.
fn handle_task_result(
    result: Result<Result<(), SigletError>, tokio::task::JoinError>,
    cancel_token: &CancellationToken,
    join_set: &mut JoinSet<Result<(), SigletError>>,
) -> Result<(), SigletError> {
    match result {
        // Task completed successfully
        Ok(Ok(())) => Ok(()),

        // Task returned an error
        Ok(Err(e)) => {
            error!("Server task failed: {}", e);
            cancel_token.cancel();
            join_set.abort_all();
            Err(e)
        }

        // Task panicked
        Err(e) => {
            error!("Server task panicked: {}", e);
            cancel_token.cancel();
            join_set.abort_all();
            Err(SigletError::TaskPanic(Box::new(e)))
        }
    }
}

/// Run the DataPlane SDK signaling API
///
/// This function binds to the specified address and runs until either:
/// - The cancellation token is triggered
/// - An error occurs
async fn run_signaling_api(
    bind: IpAddr,
    port: u16,
    sdk: DataPlaneSdk<MemoryContext>,
    cancel_token: CancellationToken,
) -> Result<(), SigletError> {
    let addr: SocketAddr = format!("{}:{}", bind, port)
        .parse()
        .map_err(|e: std::net::AddrParseError| SigletError::Network(Box::new(e)))?;

    let p_context = ParticipantContext::builder().id(DEFAULT_PARTICIPANT_ID).build();
    let router = signaling_router().layer(Extension(p_context));
    let app = router.layer(TraceLayer::new_for_http()).with_state(sdk);

    info!("Signaling API listening on {}", addr);

    // Bind to address - returns error if fails (e.g., port already in use)
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel_token.cancelled().await;
        })
        .await
        .map_err(|e| SigletError::Io(std::io::Error::other(e)))?;

    Ok(())
}

/// Run the Siglet management API
///
/// This function binds to the specified address and runs until either:
/// - The cancellation token is triggered
/// - An error occurs
async fn run_siglet_api(bind: IpAddr, port: u16, cancel_token: CancellationToken) -> Result<(), SigletError> {
    let addr: SocketAddr = format!("{}:{}", bind, port)
        .parse()
        .map_err(|e: std::net::AddrParseError| SigletError::Network(Box::new(e)))?;

    let app = create_router();

    info!("Siglet API listening on {}", addr);

    // Bind to address - returns error if fails (e.g., port already in use)
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel_token.cancelled().await;
        })
        .await
        .map_err(|e| SigletError::Io(std::io::Error::other(e)))?;

    Ok(())
}

/// Create the Siglet management API router
fn create_router() -> Router {
    Router::new()
        .route(ENDPOINT_ROOT, get(root))
        .route(ENDPOINT_HEALTH, get(health))
        .layer(TraceLayer::new_for_http())
}

/// Root endpoint handler
async fn root() -> impl IntoResponse {
    Json(json!({
        "name": APP_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "status": STATUS_RUNNING
    }))
}

/// Health check endpoint handler
async fn health() -> impl IntoResponse {
    Json(json!({
        "status": STATUS_HEALTHY
    }))
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
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
