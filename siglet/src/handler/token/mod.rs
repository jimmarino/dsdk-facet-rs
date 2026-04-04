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
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use bon::Builder;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::client::TokenClientApi;
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
}

/// Handler for token retrieval operations
#[derive(Clone, Builder)]
pub struct TokenApiHandler {
    token_client_api: Arc<TokenClientApi>,
}

impl TokenApiHandler {
    pub fn router(self) -> Router {
        Router::new()
            .route(
                "/tokens/{participant_context_id}/{id}",
                get(get_token).delete(delete_token),
            )
            .with_state(self)
    }
}

async fn get_token(
    State(handler): State<TokenApiHandler>,
    Path((participant_context_id, id)): Path<(String, String)>,
) -> Response {
    let participant_context = ParticipantContext::builder().id(participant_context_id).build();

    match handler.token_client_api.get_token(&participant_context, &id, &id).await {
        Ok(result) => (StatusCode::OK, Json(TokenResponse { token: result.token })).into_response(),
        Err(TokenError::TokenNotFound { .. }) => (StatusCode::NOT_FOUND, "Token not found").into_response(),
        Err(TokenError::NotAuthorized(msg)) => (StatusCode::UNAUTHORIZED, msg).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_token(
    State(handler): State<TokenApiHandler>,
    Path((participant_context_id, id)): Path<(String, String)>,
) -> Response {
    match handler
        .token_client_api
        .delete_token(&participant_context_id, &id, &id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(TokenError::TokenNotFound { .. }) => (StatusCode::NOT_FOUND, "Token not found").into_response(),
        Err(TokenError::NotAuthorized(msg)) => (StatusCode::UNAUTHORIZED, msg).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
