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

use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Handle for managing a background task lifecycle.
///
/// Dropping this handle will signal the background task to stop and abort it.
pub struct TaskHandle {
    shutdown_tx: watch::Sender<bool>,
    task_handle: JoinHandle<()>,
}

impl TaskHandle {
    pub fn new(shutdown_tx: watch::Sender<bool>, task_handle: JoinHandle<()>) -> Self {
        Self {
            shutdown_tx,
            task_handle,
        }
    }

    /// Signals the background task to stop and aborts it.
    #[allow(dead_code)]
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        self.task_handle.abort();
    }
}

impl Drop for TaskHandle {
    fn drop(&mut self) {
        // Signal the background task to stop
        let _ = self.shutdown_tx.send(true);
        // Abort the task as backup
        self.task_handle.abort();
    }
}
