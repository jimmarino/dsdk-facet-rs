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

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::manager::{RenewableTokenEntry, RenewableTokenStore};
use sqlx::PgPool;
use std::collections::HashMap;

/// Postgres-backed renewable token store using SQLx connection pooling.
///
/// `PostgresRenewableTokenStore` provides persistent, distributed token storage backed by a Postgres database.
/// It enables multiple services or instances to share and coordinate renewable token management with
/// automatic expiration tracking.
///
/// # Features
///
/// - **Distributed Token Storage**: Tokens are persisted in Postgres, enabling coordination across
///   multiple services or instances.
/// - **Multitenancy Support**: Tokens are isolated by participant context, ensuring tenant data separation.
/// - **Efficient Lookups**: Supports lookups by both token ID and hashed refresh token via indexes.
/// - **Concurrent Access**: Thread-safe operations via connection pooling.
///
/// # Examples
///
/// ```ignore
/// use sqlx::PgPool;
/// use dsdk_facet_postgres::token_manager::PostgresRenewableTokenStore;
///
/// // Create a connection pool
/// let pool = PgPool::connect("postgres://user:pass@localhost/db").await?;
///
/// // Initialize the renewable token store
/// let store = PostgresRenewableTokenStore::new(pool);
/// store.initialize().await?;
/// ```
pub struct PostgresRenewableTokenStore {
    pool: PgPool,
}

impl PostgresRenewableTokenStore {
    /// Creates a new PostgresRenewableTokenStore with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Initializes the renewable_tokens table and indexes.
    ///
    /// Creates the `renewable_tokens` table if it does not already exist, along with
    /// indexes to optimize token operations:
    /// - Primary key on (participant_context, id)
    /// - `idx_renewable_tokens_hash`: For efficient hash-based lookups during token renewal
    /// - `idx_renewable_tokens_participant`: For efficient participant-scoped queries
    /// - `idx_renewable_tokens_expires_at`: For efficient expiration-based cleanup
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn initialize(&self) -> Result<(), TokenError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to begin transaction: {}", e)))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS renewable_tokens (
                participant_context VARCHAR(255) NOT NULL,
                id VARCHAR(255) NOT NULL,
                token TEXT NOT NULL,
                hashed_refresh_token VARCHAR(255) NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                subject VARCHAR(255) NOT NULL,
                claims JSONB NOT NULL,
                flow_id VARCHAR(255) NOT NULL,
                PRIMARY KEY (participant_context, id)
            )",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to create renewable_tokens table: {}", e)))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_renewable_tokens_hash
             ON renewable_tokens(participant_context, hashed_refresh_token)",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to create hash index: {}", e)))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_renewable_tokens_participant
             ON renewable_tokens(participant_context)",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to create participant index: {}", e)))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_renewable_tokens_expires_at
             ON renewable_tokens(expires_at)",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to create expires_at index: {}", e)))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_renewable_tokens_flow_id
             ON renewable_tokens(participant_context, flow_id)",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to create flow_id index: {}", e)))?;

        tx.commit()
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to commit transaction: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl RenewableTokenStore for PostgresRenewableTokenStore {
    async fn save(
        &self,
        participant_context: &ParticipantContext,
        entry: RenewableTokenEntry,
    ) -> Result<(), TokenError> {
        let claims_json = serde_json::to_value(&entry.claims)
            .map_err(|e| TokenError::database_error(format!("Failed to serialize claims: {}", e)))?;

        sqlx::query(
            "INSERT INTO renewable_tokens (participant_context, id, token, hashed_refresh_token, expires_at, subject, claims, flow_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (participant_context, id)
             DO UPDATE SET
                token = EXCLUDED.token,
                hashed_refresh_token = EXCLUDED.hashed_refresh_token,
                expires_at = EXCLUDED.expires_at,
                subject = EXCLUDED.subject,
                claims = EXCLUDED.claims,
                flow_id = EXCLUDED.flow_id",
        )
        .bind(&participant_context.id)
        .bind(&entry.id)
        .bind(&entry.token)
        .bind(&entry.hashed_refresh_token)
        .bind(entry.expires_at)
        .bind(&entry.subject)
        .bind(claims_json)
        .bind(&entry.flow_id)
        .execute(&self.pool)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to save renewable token: {}", e)))?;

        Ok(())
    }

    async fn find_by_renewal(
        &self,
        participant_context: &ParticipantContext,
        hash: &str,
    ) -> Result<RenewableTokenEntry, TokenError> {
        let record: RenewableTokenRecord = sqlx::query_as(
            "SELECT participant_context, id, token, hashed_refresh_token, expires_at, subject, claims, flow_id
             FROM renewable_tokens
             WHERE participant_context = $1 AND hashed_refresh_token = $2",
        )
        .bind(&participant_context.id)
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to fetch token by hash: {}", e)))?
        .ok_or_else(|| TokenError::token_not_found(hash))?;

        // Verify the participant context matches (defense in depth)
        if record.participant_context != participant_context.id {
            return Err(TokenError::token_not_found(hash));
        }

        let claims: HashMap<String, String> = serde_json::from_value(record.claims)
            .map_err(|e| TokenError::database_error(format!("Failed to deserialize claims: {}", e)))?;

        Ok(RenewableTokenEntry {
            id: record.id,
            token: record.token,
            hashed_refresh_token: record.hashed_refresh_token,
            expires_at: record.expires_at,
            subject: record.subject,
            claims,
            flow_id: record.flow_id,
        })
    }

    async fn find_by_id(
        &self,
        participant_context: &ParticipantContext,
        id: &str,
    ) -> Result<RenewableTokenEntry, TokenError> {
        let record: RenewableTokenRecord = sqlx::query_as(
            "SELECT participant_context, id, token, hashed_refresh_token, expires_at, subject, claims, flow_id
             FROM renewable_tokens
             WHERE participant_context = $1 AND id = $2",
        )
        .bind(&participant_context.id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to fetch token by id: {}", e)))?
        .ok_or_else(|| TokenError::token_not_found(id))?;

        // Verify the participant context matches (defense in depth)
        if record.participant_context != participant_context.id {
            return Err(TokenError::token_not_found(id));
        }

        let claims: HashMap<String, String> = serde_json::from_value(record.claims)
            .map_err(|e| TokenError::database_error(format!("Failed to deserialize claims: {}", e)))?;

        Ok(RenewableTokenEntry {
            id: record.id,
            token: record.token,
            hashed_refresh_token: record.hashed_refresh_token,
            expires_at: record.expires_at,
            subject: record.subject,
            claims,
            flow_id: record.flow_id,
        })
    }

    async fn update(
        &self,
        participant_context: &ParticipantContext,
        old_hash: &str,
        new_entry: RenewableTokenEntry,
    ) -> Result<(), TokenError> {
        let claims_json = serde_json::to_value(&new_entry.claims)
            .map_err(|e| TokenError::database_error(format!("Failed to serialize claims: {}", e)))?;

        let rows_affected = sqlx::query(
            "UPDATE renewable_tokens SET
                id = $3,
                token = $4,
                hashed_refresh_token = $5,
                expires_at = $6,
                subject = $7,
                claims = $8,
                flow_id = $9
             WHERE participant_context = $1 AND hashed_refresh_token = $2",
        )
        .bind(&participant_context.id)
        .bind(old_hash)
        .bind(&new_entry.id)
        .bind(&new_entry.token)
        .bind(&new_entry.hashed_refresh_token)
        .bind(new_entry.expires_at)
        .bind(&new_entry.subject)
        .bind(claims_json)
        .bind(&new_entry.flow_id)
        .execute(&self.pool)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to update renewable token: {}", e)))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(TokenError::token_not_found(old_hash));
        }

        Ok(())
    }

    async fn find_by_flow_id(
        &self,
        participant_context: &ParticipantContext,
        flow_id: &str,
    ) -> Result<RenewableTokenEntry, TokenError> {
        let record: RenewableTokenRecord = sqlx::query_as(
            "SELECT participant_context, id, token, hashed_refresh_token, expires_at, subject, claims, flow_id
             FROM renewable_tokens
             WHERE participant_context = $1 AND flow_id = $2",
        )
        .bind(&participant_context.id)
        .bind(flow_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to fetch token by flow_id: {}", e)))?
        .ok_or_else(|| TokenError::token_not_found(flow_id))?;

        // Verify the participant context matches (defense in depth)
        if record.participant_context != participant_context.id {
            return Err(TokenError::token_not_found(flow_id));
        }

        let claims: HashMap<String, String> = serde_json::from_value(record.claims)
            .map_err(|e| TokenError::database_error(format!("Failed to deserialize claims: {}", e)))?;

        Ok(RenewableTokenEntry {
            id: record.id,
            token: record.token,
            hashed_refresh_token: record.hashed_refresh_token,
            expires_at: record.expires_at,
            subject: record.subject,
            claims,
            flow_id: record.flow_id,
        })
    }

    async fn remove_by_flow_id(
        &self,
        participant_context: &ParticipantContext,
        flow_id: &str,
    ) -> Result<(), TokenError> {
        let rows_affected = sqlx::query(
            "DELETE FROM renewable_tokens
             WHERE participant_context = $1 AND flow_id = $2",
        )
        .bind(&participant_context.id)
        .bind(flow_id)
        .execute(&self.pool)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to delete token by flow_id: {}", e)))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(TokenError::token_not_found(flow_id));
        }

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct RenewableTokenRecord {
    participant_context: String,
    id: String,
    token: String,
    hashed_refresh_token: String,
    expires_at: DateTime<Utc>,
    subject: String,
    claims: serde_json::Value,
    flow_id: String,
}
