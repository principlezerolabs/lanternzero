//! Lantern Zero protocol v0: the parts of `spec/v0.md` that both servers and
//! wallets need.
//!
//! This crate holds no I/O and no Zcash-specific cryptography, so wallet SDKs
//! can embed it alongside their own pinned librustzcash versions.
//!
//! Secrets (account tokens, viewing keys) live in types whose `Debug` output
//! is redacted and whose memory is zeroed on drop (privacy invariants 1 and 6).

pub mod api;
pub mod event_id;
pub mod hex;
pub mod lease;
pub mod padding;
pub mod problem;
pub mod replay;
pub mod token;
pub mod url;
pub mod webhook;

/// The API version this crate implements; also the path prefix (`/v0/`).
pub const VERSION: &str = "v0";

/// The purpose string a Lantern Zero OHTTP gateway declares to relays
/// (spec §3.1).
pub const OHTTP_PURPOSE: &str = "LanternZero v0 4bca76ac-1094-4330-97df-03d5c81b576d";

/// Lowercase hex SHA-256 of an encoded OHTTP key configuration list, as
/// `info` publishes it in `ohttp_key_config_sha256` (spec §3.2).
pub fn key_config_sha256_hex(encoded: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(encoded))
}
