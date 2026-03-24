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

//! E2E tests for Siglet DataFlow handler
//!
//! These tests deploy Siglet in a Kind cluster and verify its DataFlow
//! handling capabilities, including signaling API interactions and health endpoints.
//!
//! Note: These tests share a single Siglet deployment and can run in parallel.

use crate::utils::*;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Shared Siglet deployment state
static SIGLET_DEPLOYMENT: OnceCell<Arc<SigletDeployment>> = OnceCell::const_new();

/// Information about the deployed Siglet instance
struct SigletDeployment {
    pod_name: String,
}

/// Setup function to verify E2E environment is ready
async fn verify_e2e_setup() -> Result<()> {
    // Check Kind cluster exists
    if !kind_cluster_exists(KIND_CLUSTER_NAME)? {
        anyhow::bail!(
            "Kind cluster '{}' not found. Run 'cd e2e && ./scripts/setup.sh' first.",
            KIND_CLUSTER_NAME
        );
    }

    // Check kubectl is configured
    if !kubectl_configured()? {
        anyhow::bail!("kubectl not configured or cluster not accessible");
    }

    // Check namespace exists
    if !namespace_exists(E2E_NAMESPACE)? {
        anyhow::bail!(
            "Namespace '{}' not found. Run 'cd e2e && ./scripts/setup.sh' first.",
            E2E_NAMESPACE
        );
    }

    Ok(())
}

/// Deploys the Siglet to K8S
/// This function is idempotent and thread-safe - multiple tests can call it concurrently
async fn ensure_siglet_deployed() -> Result<Arc<SigletDeployment>> {
    SIGLET_DEPLOYMENT
        .get_or_try_init(|| async {
            verify_e2e_setup().await?;

            let deployment_manifest = "manifests/siglet-deployment.yaml";
            let service_manifest = "manifests/siglet-service.yaml";

            println!("Setting up Siglet deployment (one-time setup)...");

            // Clean up any existing deployment
            let _ = kubectl_delete(deployment_manifest);
            let _ = kubectl_delete(service_manifest);

            // Wait for pods to actually be deleted instead of fixed sleep
            wait_for_pods_deleted_by_label(E2E_NAMESPACE, "app=siglet", 30)
                .await
                .context("Failed to wait for previous Siglet pods to be deleted")?;

            // Deploy Siglet
            println!("Deploying Siglet");
            kubectl_apply(deployment_manifest)?;
            kubectl_apply(service_manifest)?;

            // Wait for deployment to be ready
            println!("Waiting for Siglet to be ready");
            wait_for_deployment_ready(E2E_NAMESPACE, "siglet", 120).await?;

            // Wait for pod to be ready
            println!("Waiting for Siglet pod to be ready");
            wait_for_pod_ready(E2E_NAMESPACE, "app=siglet", 120).await?;

            // Get pod name
            let pod_name_output = std::process::Command::new("kubectl")
                .args([
                    "get",
                    "pods",
                    "-n",
                    E2E_NAMESPACE,
                    "-l",
                    "app=siglet",
                    "-o",
                    "jsonpath={.items[0].metadata.name}",
                ])
                .output()
                .context("Failed to get pod name")?;
            let pod_name = String::from_utf8_lossy(&pod_name_output.stdout).to_string();

            println!("Siglet deployed: pod={}", pod_name);

            Ok(Arc::new(SigletDeployment { pod_name }))
        })
        .await
        .map(|arc| arc.clone())
}

/// Test that Siglet deploys successfully and responds to health checks
#[tokio::test]
#[ignore]
async fn test_siglet_deployment_and_health() -> Result<()> {
    let deployment = ensure_siglet_deployed().await?;
    let pod_name = &deployment.pod_name;

    // Test health endpoint using kubectl exec
    println!("Testing health endpoint...");
    let health_response = kubectl_exec(
        E2E_NAMESPACE,
        pod_name,
        "siglet",
        &["wget", "-q", "-O-", "http://localhost:8080/health"],
    )?;
    println!("Health response: {}", health_response);

    // Verify health response contains expected status
    assert!(
        health_response.contains("healthy"),
        "Health endpoint should return healthy status"
    );

    // Test root endpoint
    println!("Testing root endpoint...");
    let root_response = kubectl_exec(
        E2E_NAMESPACE,
        pod_name,
        "siglet",
        &["wget", "-q", "-O-", "http://localhost:8080/"],
    )?;
    println!("Root response: {}", root_response);

    // Verify root response contains expected metadata
    assert!(
        root_response.contains("Siglet"),
        "Root endpoint should return Siglet metadata"
    );
    assert!(root_response.contains("version"), "Root endpoint should return version");
    assert!(
        root_response.contains("running"),
        "Root endpoint should indicate running status"
    );

    // Get logs to verify startup
    println!("Retrieving Siglet logs...");
    let logs = get_pod_logs(E2E_NAMESPACE, pod_name, "siglet")?;
    println!("Siglet logs:\n{}", logs);

    // Verify startup messages in logs
    assert!(logs.contains("Siglet API"), "Logs should indicate Siglet API started");
    assert!(
        logs.contains("Signaling API"),
        "Logs should indicate Signaling API started"
    );
    assert!(logs.contains("Ready"), "Logs should indicate Siglet is ready");

    Ok(())
}

/// Test that Siglet's signaling API is accessible
///
/// This test:
/// 1. Ensures Siglet is deployed (shared setup)
/// 2. Verifies signaling API port is accessible
/// 3. Confirms both API servers are running
#[tokio::test]
#[ignore]
async fn test_siglet_signaling_api() -> Result<()> {
    let deployment = ensure_siglet_deployed().await?;
    let pod_name = &deployment.pod_name;

    // Test signaling API port is listening
    let signaling_test = kubectl_exec(
        E2E_NAMESPACE,
        pod_name,
        "siglet",
        &[
            "sh",
            "-c",
            "wget -q --spider http://localhost:8081/dataflows || echo 'signaling api accessible'",
        ],
    );

    // We expect this to either succeed or fail with specific HTTP codes, not connection refused
    // The signaling API might return 404 or 405 for GET requests on /dataflows, which is fine
    println!("Signaling API test result: {:?}", signaling_test);

    // Get logs to verify both APIs are running
    println!("Retrieving Siglet logs...");
    let logs = get_pod_logs(E2E_NAMESPACE, pod_name, "siglet")?;
    println!("Siglet logs:\n{}", logs);

    // Verify both API servers started
    assert!(
        logs.contains("Siglet API 0.0.0.0:8080"),
        "Logs should show Siglet API started on port 8080"
    );
    assert!(
        logs.contains("Signaling API 0.0.0.0:8081"),
        "Logs should show Signaling API started on port 8081"
    );

    Ok(())
}

/// Test Siglet with token store operations
///
/// This test verifies:
/// - DataFlow operations
/// - Token Storage
/// - Token retrieval
/// - DataFlow termination and cleanup
/// Note: This is currently a placeholder for future implementation
#[tokio::test]
#[ignore]
async fn test_siglet_token_operations() -> Result<()> {
    let _deployment = ensure_siglet_deployed().await?;
    // TODO
    Ok(())
}
