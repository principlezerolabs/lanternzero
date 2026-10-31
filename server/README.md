# server

The Lantern Zero server: scheduled wake-ups, the opt-in scanner with in-memory
key leases, the hint list, and long-poll endpoints.

**Status: skeleton.** Default mode works end to end. Scanning does not exist
yet.

## What works

| Piece | Spec | Notes |
| --- | --- | --- |
| OHTTP gateway | §3.1–3.3 | Key configuration (RFC 9540), relay purpose opt-in, fixed 4096-byte inner requests and responses, zero-padding checks |
| `POST /v0/info` | §4.7 | |
| `POST /v0/devices`, `DELETE /v0/devices/{id}` | §4.1 | Shape checks, SSRF rules, per-account device cap |
| `POST /v0/wake` | §4.2 | `lease: null` only; a lease gets `501 scanning-unavailable` and its keys are dropped at once |
| Replay protection | §3.4 | `Date` within 60 s; `seq` windows per device, or per account for registration; `409 stale-seq` with `min_seq` |
| Rate limits | §3.5 | Per account and per device, per minute; `429` with `Retry-After`, delivered inside OHTTP |
| Wake-up scheduler | §5.1, §5.3 | Every 30 min on the half hour, spread over 5 min; RFC 8291 encryption, VAPID, `TTL`/`Urgency`/`Topic`; drops devices on `404`/`410`; honors a gateway's `429` `Retry-After` (capped at 24 h) |

## Not yet

- **Chain follower:** `tip` is always `0` until it exists.
- **Scanner and leases**, `POST /v0/events` long-poll, hints, and events.
- **Webhooks, token rotation, account deletion** (§4.5, §4.6).
- **OHTTP key rotation.** The key configuration never changes yet.
- **Live account loading.** `new-account` takes effect after a restart.

## Run

```sh
cargo run -p lz-server -- server/examples/config.toml new-account   # prints a URL once
cargo run -p lz-server -- server/examples/config.toml
```

Put TLS in front of it (a reverse proxy), and point an OHTTP relay at
`https://<public_host>/.well-known/ohttp-gateway`.

## Security notes

- **Data directory.** `data_dir` holds the server's own keys (OHTTP seed,
  VAPID key), token hashes, and device records. The directory is created
  `0700` and its files `0600`. It never holds viewing keys or anything
  derived from them.
- **Logs.** Nothing logs tokens, request bodies, headers, or push endpoints.
  HTTP library logs are capped at `warn` even with `RUST_LOG=trace`, because
  they include hosts. A test checks this at trace level.
- **Core dumps.** The workspace forbids `unsafe`, so the process doesn't
  disable its own core dumps. Before the scanner holds keys, deployments must
  turn them off: `LimitCORE=0` in systemd, or `--ulimit core=0` in Docker
  (spec §6.2).
- **Web Push crypto** (`src/webpush.rs`) is built on RustCrypto primitives
  and checked against the RFC 8291 test vector. Existing Web Push crates
  depend on a `crypto-bigint` with timing leaks (RUSTSEC-2026-0387).
- **Minimum Rust 1.87**, because of that `crypto-bigint` fix. The server is
  not embedded in wallets, so the 1.86 rule doesn't apply to it.
