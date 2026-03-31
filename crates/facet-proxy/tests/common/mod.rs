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

// Allow dead code in this module since test utilities are shared across multiple test files
// and each test binary is compiled separately
#![allow(dead_code)]
#![allow(clippy::unwrap_used)]

mod mocks;
mod proxy_s3;

#[allow(unused_imports)] // Mocks are used in some test files but not others
pub use mocks::*;
#[allow(unused_imports)] // Used in some test files but not others
pub use proxy_s3::*;

// Re-export the shared test utility
pub use dsdk_facet_testcontainers::utils::get_available_port;
