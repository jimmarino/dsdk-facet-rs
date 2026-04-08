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

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Poll `condition` with `yield_now()` until it returns `true` or `timeout` expires.
///
/// Panics if the condition is not met within the timeout. Use this when tests do
/// not use `tokio::time::pause()`, since `yield_now` does not advance paused time.
pub async fn wait_until<F: Fn() -> bool>(condition: F, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        loop {
            if condition() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("Condition not met within {timeout:?}"));
}

/// Poll `state` with 10ms sleep intervals until `condition` returns `true` or `timeout` expires.
/// Returns `true` if the condition was met, `false` if the timeout expired.
///
/// Use this variant (over `wait_until`) when tests use `tokio::time::pause()`, since
/// `yield_now` does not advance paused time but `sleep` does.
pub async fn wait_for_condition<S, F>(state: &Arc<RwLock<S>>, condition: F, timeout: Duration) -> bool
where
    S: Send + Sync,
    F: Fn(&S) -> bool,
{
    let start = tokio::time::Instant::now();
    loop {
        {
            let guard = state.read().await;
            if condition(&guard) {
                return true;
            }
        }
        if tokio::time::Instant::now().duration_since(start) >= timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
