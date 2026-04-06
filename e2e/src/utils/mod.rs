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

//! Utilities for E2E testing

mod kubectl;
mod wait;

pub use kubectl::*;
pub use wait::*;

use anyhow::Context;

/// Default namespace for E2E tests
pub const E2E_NAMESPACE: &str = "vault-e2e-test";

/// Default Kind cluster name
pub const KIND_CLUSTER_NAME: &str = "vault-e2e";

/// Verifies the E2E environment prerequisites: Kind cluster, kubectl, namespace, and Vault.
pub async fn verify_e2e_setup() -> anyhow::Result<()> {
    if !kind_cluster_exists(KIND_CLUSTER_NAME)? {
        anyhow::bail!(
            "Kind cluster '{}' not found. Run 'cd e2e && ./scripts/setup.sh' first.",
            KIND_CLUSTER_NAME
        );
    }
    if !kubectl_configured()? {
        anyhow::bail!("kubectl not configured or cluster not accessible");
    }
    if !namespace_exists(E2E_NAMESPACE)? {
        anyhow::bail!(
            "Namespace '{}' not found. Run 'cd e2e && ./scripts/setup.sh' first.",
            E2E_NAMESPACE
        );
    }
    wait_for_deployment_ready(E2E_NAMESPACE, "vault", 60)
        .await
        .context("Vault deployment not ready")?;
    Ok(())
}
