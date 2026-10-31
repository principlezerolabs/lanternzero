//! Drives the server as a wallet would: real OHTTP encapsulation of padded
//! Binary HTTP requests, through the gateway, into the API. Also checks push
//! delivery against a local push receiver, and that logs never contain tokens.

mod common;

// Integration-test submodules live under `tests/end_to_end/`; `#[path]` is
// required because the crate root is this file, not that directory.
#[path = "end_to_end/harness.rs"]
mod harness;
#[path = "end_to_end/protocol.rs"]
mod protocol;
#[path = "end_to_end/scanning.rs"]
mod scanning;
