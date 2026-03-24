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
use config::{Config, Environment, File};
use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    #[default]
    Memory,
    Postgres,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct SigletConfig {
    #[serde(default = "default_siglet_api_port")]
    pub siglet_api_port: u16,
    #[serde(default = "default_signaling_port")]
    pub signaling_port: u16,
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    #[serde(default)]
    pub storage_backend: StorageBackend,
}

impl Default for SigletConfig {
    fn default() -> Self {
        Self {
            siglet_api_port: 8080,
            signaling_port: 8081,
            bind: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            storage_backend: StorageBackend::Memory,
        }
    }
}

const fn default_siglet_api_port() -> u16 {
    8080
}

const fn default_signaling_port() -> u16 {
    8081
}

fn default_bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}

pub fn load_config() -> anyhow::Result<SigletConfig> {
    let path = std::env::args().nth(1);
    let config_file = std::env::var("SIGLET_CONFIG_FILE")
        .map(PathBuf::from)
        .ok()
        .or_else(|| path.map(PathBuf::from));

    let mut config_builder = Config::builder();
    if let Some(path) = config_file {
        config_builder = config_builder.add_source(File::from(path.clone()));
    }

    config_builder
        .add_source(Environment::with_prefix("SIGLET"))
        .build()?
        .try_deserialize()
        .map_err(Into::into)
}
