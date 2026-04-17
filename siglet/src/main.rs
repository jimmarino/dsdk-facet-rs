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

use siglet::{
    assembly::{assemble_memory, assemble_postgres},
    config::{SigletConfig, StorageBackend, load_config},
    error::SigletError,
    server::run_server,
};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = load_config().unwrap_or_else(|e| {
        error!("Failed to load configuration: {}", e);
        std::process::exit(1);
    });

    if let Err(e) = cfg.validate() {
        error!("{}", e);
        std::process::exit(1);
    }

    match run(cfg).await {
        Ok(_) => info!("Shutdown"),
        Err(e) => {
            error!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn run(cfg: SigletConfig) -> Result<(), SigletError> {
    match &cfg.storage_backend {
        StorageBackend::Memory => {
            let runtime = assemble_memory(&cfg).await?;
            run_server(
                cfg.bind,
                cfg.signaling_port,
                cfg.siglet_api_port,
                cfg.refresh_api_port,
                runtime.sdk,
                runtime.token_api_handler,
                runtime.refresh_handler,
            )
            .await
        }
        StorageBackend::Postgres { .. } | StorageBackend::PostgresVault { .. } => {
            let runtime = assemble_postgres(&cfg).await?;
            run_server(
                cfg.bind,
                cfg.signaling_port,
                cfg.siglet_api_port,
                cfg.refresh_api_port,
                runtime.sdk,
                runtime.token_api_handler,
                runtime.refresh_handler,
            )
            .await
        }
    }
}
