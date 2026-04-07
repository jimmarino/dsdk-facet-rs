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

use anyhow::{Context, Result, bail};
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

/// Wait for pod to be ready
pub async fn wait_for_pod_ready(namespace: &str, pod_label: &str, timeout_secs: u64) -> Result<()> {
    let output = Command::new("kubectl")
        .args([
            "wait",
            "--for=condition=Ready",
            "pod",
            "-l",
            pod_label,
            "-n",
            namespace,
            &format!("--timeout={}s", timeout_secs),
        ])
        .output()
        .context("Failed to wait for pod")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Pod with label {} did not become ready: {}", pod_label, stderr);
    }

    Ok(())
}

/// Wait for a deployment rollout to fully complete (new pods up, old pods cleaned up).
/// Prefer this over `wait_for_pod_ready` or `wait_for_deployment_ready` after a
/// `kubectl rollout restart` — it avoids the race where a Terminating pod is still
/// visible to label-selector-based waits.
pub async fn wait_for_rollout_complete(namespace: &str, deployment_name: &str, timeout_secs: u64) -> Result<()> {
    let output = Command::new("kubectl")
        .args([
            "rollout",
            "status",
            &format!("deployment/{}", deployment_name),
            "-n",
            namespace,
            &format!("--timeout={}s", timeout_secs),
        ])
        .output()
        .context("Failed to run kubectl rollout status")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Rollout of {} did not complete: {}", deployment_name, stderr);
    }

    Ok(())
}

/// Wait for deployment to be ready
pub async fn wait_for_deployment_ready(namespace: &str, deployment_name: &str, timeout_secs: u64) -> Result<()> {
    let output = Command::new("kubectl")
        .args([
            "wait",
            "--for=condition=Available",
            &format!("deployment/{}", deployment_name),
            "-n",
            namespace,
            &format!("--timeout={}s", timeout_secs),
        ])
        .output()
        .context("Failed to wait for deployment")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Deployment {} did not become ready: {}", deployment_name, stderr);
    }

    Ok(())
}

/// Wait for pod to be deleted
pub async fn wait_for_pod_deleted(namespace: &str, pod_name: &str, timeout_secs: u64) -> Result<()> {
    let output = Command::new("kubectl")
        .args([
            "wait",
            "--for=delete",
            &format!("pod/{}", pod_name),
            "-n",
            namespace,
            &format!("--timeout={}s", timeout_secs),
        ])
        .output()
        .context("Failed to wait for pod deletion")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Pod {} was not deleted within timeout: {}", pod_name, stderr);
    }

    Ok(())
}

/// Wait for a container to complete and return its exit code.
/// Returns Ok(exit_code) if container terminated, or error if timeout.
pub async fn wait_for_container_completion(
    namespace: &str,
    pod_name: &str,
    container: &str,
    timeout_secs: u64,
) -> Result<i32> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed().as_secs() > timeout_secs {
            bail!(
                "Timeout waiting for container {} in pod {} to complete",
                container,
                pod_name
            );
        }

        let output = Command::new("kubectl")
            .args([
                "get",
                "pod",
                "-n",
                namespace,
                pod_name,
                "-o",
                &format!(
                    "jsonpath={{.status.containerStatuses[?(@.name==\"{}\")].state}}",
                    container
                ),
            ])
            .output()
            .context("Failed to get container status")?;

        let status = String::from_utf8_lossy(&output.stdout);

        if status.contains("\"terminated\"") {
            let exit_code_output = Command::new("kubectl")
                .args([
                    "get",
                    "pod",
                    "-n",
                    namespace,
                    pod_name,
                    "-o",
                    &format!(
                        "jsonpath={{.status.containerStatuses[?(@.name==\"{}\")].state.terminated.exitCode}}",
                        container
                    ),
                ])
                .output()
                .context("Failed to get container exit code")?;

            let exit_code_str = String::from_utf8_lossy(&exit_code_output.stdout);
            let exit_code = exit_code_str
                .trim()
                .parse::<i32>()
                .context("Failed to parse exit code")?;

            return Ok(exit_code);
        }

        sleep(Duration::from_millis(100)).await;
    }
}
