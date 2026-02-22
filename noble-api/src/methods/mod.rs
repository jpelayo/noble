// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! RPC method modules — each defines a `#[rpc(server)]` trait and its implementation.

pub mod address;
pub mod block;
pub mod consensus;
pub mod document;
pub mod mempool;
pub mod network;
pub mod node;
pub mod subscriptions;
pub mod trace;
pub mod transaction;
pub mod wallet;
