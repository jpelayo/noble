// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE protocol node binary — orchestrates all subsystems.

#[allow(dead_code)]
mod config;

fn main() {
    println!("noble-node v{}", env!("CARGO_PKG_VERSION"));
}
