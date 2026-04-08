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
use dsdk_facet_hashicorp_vault::state::VaultClientState;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub use dsdk_facet_test_utils::wait_for_condition;

// ============================================================================
// VaultClientState Test Fixtures
// ============================================================================
//
// These factory functions provide convenient ways to create VaultClientState
// instances for testing. Use semantic helpers for common scenarios, or the
// base factory for custom configurations.
//
// Examples:
//
//   // Healthy state with defaults
//   let state = healthy_vault_state();
//   assert!(state.is_healthy());
//
//   // State with failures
//   let state = failing_vault_state(5);
//   assert!(!state.is_healthy());
//
//   // Custom configuration
//   let state = create_test_state("my-token", 7200, 0);
//
//   // For use with TokenRenewer (wrapped in Arc<RwLock>)
//   let state = wrapped_test_state("token", 3600, 0);
//
//   // Full builder control for unique cases
//   let state = VaultClientState::builder()
//       .token("special-token")
//       .last_created(specific_time)
//       .lease_duration(100)
//       .health_threshold(5)
//       .build();
//
// ============================================================================

/// Creates a VaultClientState for testing with configurable parameters.
/// This is the base factory function - use the semantic helpers below for common scenarios.
pub fn create_test_state(token: &str, lease_duration: u64, consecutive_failures: u32) -> VaultClientState {
    VaultClientState::builder()
        .token(token)
        .last_created(Utc::now())
        .lease_duration(lease_duration)
        .consecutive_failures(consecutive_failures)
        .health_threshold(3)
        .build()
}

/// Creates a healthy VaultClientState with default test values.
/// - Token: "test-token"
/// - Lease: 3600 seconds
/// - No failures
/// - Healthy status
pub fn healthy_vault_state() -> VaultClientState {
    create_test_state("test-token", 3600, 0)
}

/// Creates a VaultClientState that has been successfully renewed.
/// - Token: "test-token"
/// - Lease: 3600 seconds
/// - Recently renewed
/// - No failures
pub fn renewed_vault_state() -> VaultClientState {
    VaultClientState::builder()
        .token("test-token")
        .last_created(Utc::now())
        .last_renewed(Utc::now())
        .lease_duration(3600)
        .health_threshold(3)
        .build()
}

/// Creates a VaultClientState with the specified number of consecutive failures.
/// - Token: "test-token"
/// - Lease: 3600 seconds
/// - Last error set
/// - Unhealthy if failures >= 3
pub fn failing_vault_state(failures: u32) -> VaultClientState {
    VaultClientState::builder()
        .token("test-token")
        .last_created(Utc::now())
        .lease_duration(3600)
        .consecutive_failures(failures)
        .last_error("Test error")
        .health_threshold(3)
        .build()
}

/// Creates a VaultClientState with a nearly expired token for testing recovery scenarios.
/// - Token: "old-token"
/// - Created 1 hour ago
/// - Very short lease (10 seconds)
/// - Simulates expiration
pub fn expiring_vault_state() -> VaultClientState {
    let past = Utc::now() - TimeDelta::try_hours(1).unwrap();
    VaultClientState::builder()
        .token("old-token")
        .last_created(past)
        .lease_duration(10)
        .health_threshold(3)
        .build()
}

/// Creates a wrapped VaultClientState ready for use with TokenRenewer.
/// Returns Arc<RwLock<VaultClientState>> which is the standard pattern.
pub fn wrapped_test_state(
    token: &str,
    lease_duration: u64,
    consecutive_failures: u32,
) -> Arc<RwLock<VaultClientState>> {
    Arc::new(RwLock::new(create_test_state(
        token,
        lease_duration,
        consecutive_failures,
    )))
}
