// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared error code catalog for Noble client applications.
//!
//! Each error is prefixed `NE-` (Noble Error) followed by a numeric code.
//! The code appears in user-facing messages for debugging:
//!   "Could not reach the node [NE-103]"
//!
//! Ranges:
//!   1xx — Connection & Network
//!   2xx — Wallet & Cryptography
//!   3xx — Keychain / Credential Storage
//!   4xx — Bridge / IPC
//!   5xx — Services (Faucet, WebSocket)
//!   6xx — Documents & Transactions

// 1xx — Connection & Network
pub const NE_INVALID_URL: &str          = "NE-101";
pub const NE_TLS_FAILED: &str           = "NE-102";
pub const NE_NODE_UNREACHABLE: &str     = "NE-103";
pub const NE_HTTP_ERROR: &str           = "NE-104";
pub const NE_INVALID_RESPONSE: &str     = "NE-105";
pub const NE_EMPTY_RESULT: &str         = "NE-106";
pub const NE_TLS_FINGERPRINT: &str      = "NE-107";
pub const NE_TIMEOUT: &str              = "NE-108";

// 2xx — Wallet & Cryptography
pub const NE_INVALID_PRIVATE_KEY: &str  = "NE-201";
pub const NE_INVALID_PUBLIC_KEY: &str   = "NE-202";
pub const NE_INVALID_MNEMONIC: &str     = "NE-203";
pub const NE_SIGNING_FAILED: &str       = "NE-204";
pub const NE_CBOR_ENCODING: &str        = "NE-205";
pub const NE_INVALID_CHECKSUM: &str     = "NE-206";
pub const NE_UNSUPPORTED_SCHEME: &str   = "NE-207";
pub const NE_ENTROPY_FAILED: &str       = "NE-208";
pub const NE_HD_DERIVATION: &str        = "NE-209";
pub const NE_MNEMONIC_WORD_COUNT: &str  = "NE-210";
pub const NE_WALLET_CREATION: &str      = "NE-211";

// 3xx — Keychain / Credential Storage
pub const NE_KEY_NOT_FOUND: &str        = "NE-301";
pub const NE_INVALID_KEY_DATA: &str     = "NE-302";
pub const NE_KEYCHAIN_STORE: &str       = "NE-303";
pub const NE_KEYCHAIN_LOAD: &str        = "NE-304";
pub const NE_KEYCHAIN_DELETE: &str      = "NE-305";
pub const NE_NO_PRIVATE_KEY: &str       = "NE-306";

// 4xx — Bridge / IPC
pub const NE_UNKNOWN_HANDLER: &str      = "NE-401";
pub const NE_UNKNOWN_ACTION: &str       = "NE-402";
pub const NE_MISSING_PARAM: &str        = "NE-403";
pub const NE_NOT_CONNECTED: &str        = "NE-404";
pub const NE_BRIDGE_TIMEOUT: &str       = "NE-405";
pub const NE_BRIDGE_PARSE: &str         = "NE-406";

// 5xx — Services
pub const NE_FAUCET_UNAVAILABLE: &str   = "NE-501";
pub const NE_FAUCET_ERROR: &str         = "NE-502";
pub const NE_WS_NOT_CONNECTED: &str     = "NE-503";
pub const NE_WS_SUBSCRIBE: &str         = "NE-504";
pub const NE_WS_CLOSED: &str            = "NE-505";

// 6xx — Documents & Transactions
pub const NE_VERIFICATION_FAILED: &str  = "NE-601";
pub const NE_HASH_FAILED: &str          = "NE-602";
pub const NE_TX_REJECTED: &str          = "NE-603";
pub const NE_TX_FAILED: &str            = "NE-604";

/// Format a user-facing error message with the error code appended.
///
/// ```
/// ne_message("Could not reach the node", NE_NODE_UNREACHABLE)
/// // → "Could not reach the node [NE-103]"
/// ```
pub fn ne_message(text: &str, code: &str) -> String {
    format!("{text} [{code}]")
}
