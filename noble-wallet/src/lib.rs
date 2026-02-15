// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Key storage, transaction builder and fee estimation for the NOBLE protocol.

pub mod builder;
pub mod error;
pub mod keystore;
pub mod locator;
pub mod state;

pub use builder::{TransactionBuilder, TypedSlot};
pub use error::WalletError;
pub use keystore::KeyStore;
pub use locator::decrypt_locator;
pub use state::WalletState;
