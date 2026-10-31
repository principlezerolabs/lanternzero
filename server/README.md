# server

The Lantern Zero server: scheduled wake-ups, the opt-in scanner with in-memory
key leases, the hint list, and long-poll endpoints.

**Status: prototype.** Default mode and incoming-payment scanning work end
to end against a fake chain source, and the chain follower and block
scanning also against real Zebra and Zaino on regtest
([`deploy/regtest`](../deploy/regtest/README.md)).

## What works

| Piece | Spec | Notes |
| --- | --- | --- |
| OHTTP gateway | §3.1–3.3 | Key configuration (RFC 9540), relay purpose opt-in, fixed 4096-byte inner requests and responses, zero-padding checks |
| `POST /v0/info` | §4.7 | |
| `POST /v0/devices`, `DELETE /v0/devices/{id}` | §4.1 | Shape checks, SSRF rules, per-account device cap |
| `POST /v0/wake` | §4.2 | Leases of 1–4 UIVKs (ZIP 316 Revision 0 or 2, either case), renewed on each wake, backfilled from `from_height` (at most 7 days of blocks); `lease: null` drops the lease and its events at once; acks; hints; events paged to the fixed size |
| `POST /v0/events` | §4.3 | Long-poll held until the server-wide release (new block, match, or reorg) plus 0–2 s jitter, or 25–30 s; never early, even with events pending; `wait: 0` for `next` pages |
| Scanner | §4.4, §6.1 | Trial decryption of Sapling outputs and Orchard and Ironwood actions in compact blocks, for every active lease; deterministic event ids; `mined` → `reorged` → re-mined; confirmations up to the finality depth; events deleted on ack or after 7 days; expired leases swept every minute; catches up after falling behind |
| Mempool | §4.3, §6.1 | `GetMempoolStream`, reopened after each block; full transactions (v5 and v6) cut to `CompactTx` and trial-decrypted like blocks; matches are `mempool` events that become `mined` with the same id; a new lease is checked against the pending mempool, kept in compact form up to 64 MiB; an unknown branch id is logged, not fatal |
| Payment alerts | §5.2 | `instant`: an extra `Urgency: high` push when a payment is first seen (usually in the mempool, seconds after it was sent), one per transaction, at most 2 a minute per account; `private`: up to 4 events inside the scheduled ping, same 1024-byte size. Backfilled payments don't push |
| Replay protection | §3.4 | `Date` within 60 s; `seq` windows per device, or per account for registration; `409 stale-seq` with `min_seq` |
| Rate limits | §3.5 | Per account and per device, per minute; `429` with `Retry-After`, delivered inside OHTTP |
| Chain follower | §6.1 | Follows Zaino or lightwalletd with `GetLatestBlock` and `GetBlockRange` only; checks the network (by `chain_name` and Sapling's activation height, since Zaino reports regtest as `"test"`); rolls back reorgs up to 100 blocks and starts over at the tip on deeper ones; keeps `tip` current and announces each block to the rest of the server |
| Wake-up scheduler | §5.1, §5.3 | Every 30 min on the half hour, spread over 5 min; RFC 8291 encryption, VAPID, `TTL`/`Urgency`/`Topic`; drops devices on `404`/`410`; honors a gateway's `429` `Retry-After` (capped at 24 h) |

## Not yet

- **Dropped mempool transactions.** An event for a transaction that leaves
  the mempool unmined stays `mempool` until acknowledged or 7 days old.
- **Spend alerts.** Leases with `spend_alerts: true` get
  `501 spend-alerts-unavailable`.
- **Locked memory.** Keys are zeroed where we hold them as text, but the
  decoded Sapling and Orchard key types don't zero themselves; deployments
  must disable swap and core dumps (spec §6.2).
- **Webhooks, token rotation, account deletion** (§4.5, §4.6).
- **Key rotation.** Neither the OHTTP key configuration nor the VAPID key
  rotates yet. VAPID rotation (spec §5.3) will need a key id per device
  record, since each subscription is bound to the key it was created with.
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
- **Minimum Rust 1.89**, because `zcash_client_backend` 0.25 (the first
  release with Ironwood) needs it. The server is not embedded in wallets,
  so the 1.86 rule doesn't apply to it.
- **Chain source.** Without a `[chain]` section, `tip` stays `0`. Run Zaino
  on the same host or private network (`http://`), or use `https://`.
