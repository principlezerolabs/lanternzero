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
| `POST /v0/devices`, `DELETE /v0/devices/{id}` | §4.1 | Shape checks, SSRF rules, per-account device cap; records the VAPID key the subscription is bound to (`vapid_public_key`, or the current key), refusing keys it doesn't hold |
| `POST /v0/wake` | §4.2 | Leases of 1–4 UIVKs (ZIP 316 Revision 0 or 2, either case), renewed on each wake, backfilled from `from_height` (at most 7 days of blocks); `lease: null` drops the lease and its events at once; acks; hints; events paged to the fixed size |
| `POST /v0/token/rotate`, `DELETE /v0/account` | §4.6 | Rotation keeps the old token until the new one is first used, or for 24 h; retries succeed; reused hashes get `400`. Deletion drops token hashes, devices, replay window, lease, events, and hints at once. Both rewrite `accounts.txt` atomically under a lock shared with `new-account`, keeping comments and accounts added meanwhile |
| Scanning time and idle accounts | §4.2, §4.6, §4.7 | `[accounts]`: `scanning = "entitled"` limits leases to accounts with scanning time and clamps them to its end, answering `403 scanning-not-included` (fixed size) otherwise; `idle_account_days` deletes accounts idle longer, keeping only the UTC day of each account's last request, skipping days the server was down, and is published in `info` |
| Issuer interface | §2.3, §4.6 | [`ISSUER.md`](ISSUER.md): HTTP over `data_dir/issuer.sock` (0600), never TCP or OHTTP. `create` (live at once), `resolve`, `scan_until`, `add_scan_time` (idempotent by key), `deletions` (30 days), `delete` |
| `POST /v0/events` | §4.3 | Long-poll held until the server-wide release (new block, match, or reorg) plus 0–2 s jitter, or 25–30 s; never early, even with events pending; `wait: 0` for `next` pages |
| Scanner | §4.4, §6.1 | Trial decryption of Sapling outputs and Orchard and Ironwood actions in compact blocks, for every active lease; deterministic event ids; `mined` → `reorged` → re-mined; confirmations up to the finality depth; events deleted on ack or after 7 days; expired leases swept every minute; catches up after falling behind |
| Mempool | §4.3, §6.1 | `GetMempoolStream`, reopened after each block; full transactions (v5 and v6) cut to `CompactTx` and trial-decrypted like blocks; matches are `mempool` events that become `mined` with the same id; a new lease is checked against the pending mempool, kept in compact form up to 64 MiB; an unknown branch id is logged, not fatal |
| Payment alerts | §5.2 | `instant`: an extra `Urgency: high` push when a payment is first seen (usually in the mempool, seconds after it was sent), one per transaction, at most 2 a minute per account; `private`: up to 4 events inside the scheduled ping, same 1024-byte size. Backfilled payments don't push |
| Replay protection | §3.4 | `Date` within 60 s; `seq` windows per device, or per account for registration, rotation, and deletion; `409 stale-seq` with `min_seq` |
| Rate limits | §3.5 | Per account and per device, per minute; `429` with `Retry-After`, delivered inside OHTTP |
| Chain follower | §6.1 | Follows Zaino or lightwalletd with `GetLatestBlock` and `GetBlockRange` only; checks the network (by `chain_name` and Sapling's activation height, since Zaino reports regtest as `"test"`); rolls back reorgs up to 100 blocks and starts over at the tip on deeper ones; keeps `tip` current and announces each block to the rest of the server |
| Wake-up scheduler | §5.1, §5.3 | Every 30 min on the half hour, spread over 5 min; RFC 8291 encryption, VAPID signed with the key each device's subscription is bound to, `TTL`/`Urgency`/`Topic`; drops devices on `404`/`410`; honors a gateway's `429` `Retry-After` (capped at 24 h) |

## Not yet

- **Dropped mempool transactions.** An event for a transaction that leaves
  the mempool unmined stays `mempool` until acknowledged or 7 days old.
- **Spend alerts.** Leases with `spend_alerts: true` get
  `501 spend-alerts-unavailable`.
- **Zeroing decoded keys.** Keys are zeroed where we hold them as text,
  but the decoded Sapling and Orchard key types from the Zcash crates don't
  zero themselves on drop. Locked memory and no core dumps (below) keep
  them off disk meanwhile.
- **Webhooks** (§4.5).
- **OHTTP key rotation.** The OHTTP key configuration doesn't rotate yet.
- **More `doctor` checks and `init`** (deploy/DESIGN.md). `doctor` doesn't
  yet check that the onion service or OHTTP gateway answers from outside,
  or the clock beyond what the tip's age shows; `lz-server init` doesn't
  exist yet.
- **Live account loading for `new-account`.** Accounts the CLI adds take
  effect after a restart; accounts made through the issuer socket are live
  at once.
- **Issuer types crate.** The issuer socket's request and answer types live
  in the server; a small shared crate can follow when an issuer wants to
  link against them.

## Run

```sh
cargo run -p lz-server -- server/examples/config.toml new-account   # prints a URL once
cargo run -p lz-server -- server/examples/config.toml
```

Put TLS in front of it (a reverse proxy), and point an OHTTP relay at
`https://<public_host>/.well-known/ohttp-gateway`.

### Rotating the VAPID key

```sh
lz-server <config.toml> rotate-vapid              # routine
lz-server <config.toml> rotate-vapid --drop-old   # suspected leak
```

Then restart the server. Push subscriptions are bound to the key they were
created with (spec §5.3), so each device record keeps its key, and `info`
publishes the new one. Wallets notice the change, subscribe again with the
new key, and delete their old device record; the old key, in
`data_dir/vapid-retired/`, is deleted at the first start after no device
uses it. With `--drop-old`, old keys are deleted at once and the devices
bound to them are dropped at the next start; those wallets register again
when their next `wake` gets `unknown-device`.

## Security notes

- **Data directory.** `data_dir` holds the server's own keys (OHTTP seed,
  VAPID keys), token hashes, device records, and, when `[accounts]` uses
  them, scanning end times, last-active days, and the issuer socket
  ([`ISSUER.md`](ISSUER.md)). The directory is created
  `0700` and its files `0600`. It never holds viewing keys or anything
  derived from them.
- **Logs.** Nothing logs tokens, request bodies, headers, or push endpoints.
  HTTP library logs are capped at `warn` even with `RUST_LOG=trace`, because
  they include hosts. A test checks this at trace level.
- **Memory hygiene (spec §6.2).** At start, before loading any key, the
  server turns off its core dumps (`RLIMIT_CORE` 0; on Linux also not
  dumpable, which blocks `ptrace` too) and, on Linux with an unlimited
  memlock limit, locks all its memory (`mlockall`). Otherwise it checks
  that swap can't take its pages: no swap, a container whose cgroup
  forbids swap (`memory.swap.max` 0), or macOS, which always encrypts
  swap. A server with `[chain]` (so it may hold viewing keys) **refuses to
  start** when none of that holds. To fix it, give it an unlimited memlock
  limit (`LimitMEMLOCK=infinity` in systemd, `--ulimit memlock=-1` in
  Docker), or turn swap off for it (`--memory-swap` equal to `--memory`).
  If its swap is encrypted, set `hardening.allow_swap = true`. Locked
  memory can't be reclaimed, so it all counts against a container's memory
  limit: size the limit for the server's peak (the mempool snapshot alone
  may reach 64 MiB). The calls go through `rustix`, so the workspace still
  has no `unsafe` of its own.
- **`lz-server <config> doctor`** checks the data directory's
  permissions, core dumps, memory and swap, and the chain source (network
  and tip age), and prints pass, warn, or fail for each. Its output has no
  tokens, keys, URLs, or host names, so it's safe to paste into an issue.
- **Web Push crypto** (`src/webpush.rs`) is built on RustCrypto primitives
  and checked against the RFC 8291 test vector. Existing Web Push crates
  depend on a `crypto-bigint` with timing leaks (RUSTSEC-2026-0387).
- **Minimum Rust 1.89**, because `zcash_client_backend` 0.25 (the first
  release with Ironwood) needs it. The whole workspace uses the same
  minimum.
- **Chain source.** Without a `[chain]` section, `tip` stays `0`. Run Zaino
  on the same host or private network (`http://`), or use `https://`.
