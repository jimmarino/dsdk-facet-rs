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

use crate::utils::*;
use anyhow::{Context, Result};
use dsdk_facet_hashicorp_vault::{HashicorpVaultClient, HashicorpVaultConfig, VaultAuthConfig};
use dsdk_facet_testcontainers::utils::get_available_port;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

static VAULT_FIXTURE: OnceCell<Arc<VaultFixture>> = OnceCell::const_new();

/// A port-forwarded Vault instance accessible from the test process.
pub struct VaultFixture {
    pub vault_url: String,
    pub vault_client: Arc<HashicorpVaultClient>,
    // Keeps the port-forward process alive for the fixture's lifetime.
    _port_forward: Mutex<std::process::Child>,
    // Temp file holding the root token for FileBasedVaultAuthClient.
    _token_file: std::path::PathBuf,
}

/// Returns a shared Vault fixture with an active port-forward and an initialized client
/// authenticated as root (for e2e test use only).
///
/// The client uses `KubernetesServiceAccount` auth pointing to a temp file containing
/// the root token `"root"`, which is the dev-mode Vault root credential in the Kind cluster.
pub async fn ensure_vault_client() -> Result<Arc<VaultFixture>> {
    VAULT_FIXTURE
        .get_or_try_init(|| async {
            verify_e2e_setup().await?;

            let local_port = get_available_port();
            let child = std::process::Command::new("kubectl")
                .args([
                    "port-forward",
                    "-n",
                    E2E_NAMESPACE,
                    "service/vault",
                    &format!("{}:8200", local_port),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .context("Failed to start kubectl port-forward for vault")?;

            let vault_url = format!("http://localhost:{}", local_port);

            // Wait for port-forward to come up
            let http = reqwest::Client::new();
            let start = std::time::Instant::now();
            loop {
                if start.elapsed().as_secs() > 30 {
                    anyhow::bail!(
                        "Vault port-forward on {} did not become ready within 30 seconds",
                        local_port
                    );
                }
                if http
                    .get(format!("{}/v1/sys/health", vault_url))
                    .timeout(tokio::time::Duration::from_secs(1))
                    .send()
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }

            // Write the root token to a temp file so FileBasedVaultAuthClient can read it.
            let token_file = std::env::temp_dir().join("e2e_vault_root_token");
            std::fs::write(&token_file, "root").context("Failed to write vault root token file")?;

            let config = HashicorpVaultConfig::builder()
                .vault_url(&vault_url)
                .auth_config(VaultAuthConfig::KubernetesServiceAccount {
                    token_file_path: token_file.clone(),
                })
                .build();

            let mut client = HashicorpVaultClient::new(config).context("Failed to create vault client")?;
            client.initialize().await.context("Failed to initialize vault client")?;

            println!("Vault port-forward ready at {}", vault_url);

            Ok(Arc::new(VaultFixture {
                vault_url,
                vault_client: Arc::new(client),
                _port_forward: Mutex::new(child),
                _token_file: token_file,
            }))
        })
        .await
        .map(|arc| arc.clone())
}
