// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 server with WebSocket subscriptions for the NOBLE protocol.

pub mod error;
pub mod state;
pub mod types;

pub mod methods;
pub mod server;

pub use error::ApiError;
pub use server::start_server;
pub use state::{ApiState, NetworkStats};
