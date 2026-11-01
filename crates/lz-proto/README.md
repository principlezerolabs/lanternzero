# lz-proto

The parts of the [v0 spec](../../spec/v0.md) that servers and wallets share:

| Module | Spec | Contents |
| --- | --- | --- |
| `api` | §4, §5 | JSON request, response, event, and ping types |
| `token` | §2.2–2.3 | Account tokens: generation, checksum, hashing |
| `url` | §2 | Connection URL parsing and token masking |
| `padding` | §3.3, §5.1 | Fixed request, response, and ping sizes |
| `replay` | §3.4 | The per-device `seq` replay window |
| `event_id` | §4.4 | Deterministic event ids |
| `lease` | §4.2 | Viewing-key leases: validation and duration clamping |

Wallet SDKs embed this crate, so it has no I/O, no async runtime, no TLS
stack, and no Zcash crates, and it builds on Rust 1.89 (librustzcash's
minimum). CI enforces this.

Account tokens and viewing keys never appear in `Debug` output and are zeroed
when dropped. Tests check both.

Test vectors live in [`spec/vectors/v0.json`](../../spec/vectors/v0.json), and
`tests/vectors.rs` fails if they drift from the code.
