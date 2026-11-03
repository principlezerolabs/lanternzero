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
| `POST /v0/wake` | §4.2 | Clients without a device (`device_id: null`) use the account's `seq` window and rate limit. Leases of 1–4 UIVKs (ZIP 316 Revision 0 or 2, either case), renewed on each wake, backfilled from `from_height` (at most 7 days of blocks); `lease: null` drops the lease and its events at once; acks; hints; events paged to the fixed size |
| `POST /v0/token/rotate`, `DELETE /v0/account` | §4.6 | Rotation keeps the old token until the new one is first used, or for 24 h; retries succeed; reused hashes get `400`. Deletion drops token hashes, devices, replay window, lease, events, and hints at once. Both rewrite `accounts.txt` atomically under a lock shared with `new-account`, keeping comments and accounts added meanwhile |
| Scanning time and idle accounts | §4.2, §4.6, §4.7 | `[accounts]`: `scanning = "entitled"` limits leases to accounts with scanning time and clamps them to its end, answering `403 scanning-not-included` (fixed size) otherwise; `idle_account_days` deletes accounts idle longer, keeping only the UTC day of each account's last request, skipping days the server was down, and is published in `info` |
| Issuer interface | §2.3, §4.6 | [`ISSUER.md`](ISSUER.md): HTTP over `data_dir/issuer.sock` (0600), never TCP or OHTTP. `create` (live at once), `resolve`, `scan_until`, `add_scan_time` (idempotent by key), `deletions` (30 days), `delete` |
| `POST /v0/events` | §4.3 | Long-poll held until the server-wide release (new block, match, or reorg; at most one every 5 s) plus 0–2 s jitter, or 25–30 s; never early, even with events pending; `wait: 0` for `next` pages |
| Scanner | §4.4, §6.1 | Trial decryption of Sapling outputs and Orchard and Ironwood actions in compact blocks, for every active lease; deterministic event ids; `mined` → `reorged` → re-mined; confirmations up to the finality depth; events deleted on ack or after 7 days; expired leases swept every minute; catches up after falling behind |
| Mempool | §4.3, §6.1 | `GetMempoolStream`, reopened after each block; full transactions (v5 and v6) cut to `CompactTx` and trial-decrypted like blocks; matches are `mempool` events that become `mined` with the same id; a new lease is checked against the pending mempool, kept in compact form up to 64 MiB; an unknown branch id is logged, not fatal |
| Payment alerts | §5.2 | `instant`: an extra `Urgency: high` push when a payment is first seen (usually in the mempool, seconds after it was sent), one per transaction, at most 2 a minute per account; `private`: up to 4 events inside the scheduled ping, same 1024-byte size. Backfilled payments don't push |
| Webhooks | §4.5 | `PUT`/`DELETE /v0/webhook` on a scanning server; URL (https, at most 1024 bytes, no user info, SSRF rules) and `whsec_` secret kept in `state.json`. Every event delivered on each change, Standard Webhooks signed (`webhook-id` from the event's state), retried with backoff and jitter for 24 h; a final delivered event is deleted; `410` deletes the webhook; undelivered events are exempt from the event cap. Deliveries go out on each release and every 5 s |
| Replay protection | §3.4 | `Date` within 60 s, and a `Date` on every response so wallets can correct their clocks; `seq` windows per device, or per account for registration, rotation, and deletion; `409 stale-seq` with `min_seq` |
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
- **Memos for payments first seen in a block.** Webhook memos come from
  the mempool's full transactions (spec §4.5); a payment the server first
  sees in a compact block has `memo: null`, because fetching the
  transaction by txid is ruled out (invariant 7).
- **Live account loading for `new-account`.** Accounts the CLI adds take
  effect after a restart; accounts made through the issuer socket are live
  at once.
- **Scanner in its own process.** Viewing keys share a process with the
  OHTTP gateway, the API, and the outbound push client, and every restart
  drops all leases, so payments that arrive before each wallet's next wake
  get no instant alert. A separate scanner process behind a narrow
  interface (set and end leases, stream events) would shrink what a
  breach of the network-facing code exposes, let the API restart without
  dropping leases, and is the way to scanning in an attested enclave
  (`attestation` in `info`). Planned after phase 1.
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

### Setting up a self-hosted server

`lz-server <config.toml> init …` writes `config.toml` (mode 0600, never over
an existing one), the data directory and the server's keys, and the first
account, and prints its connection URL once. With `--onion-hostname-file`
it waits for Tor to write the onion address. The Compose kit in
[`deploy/`](../deploy/README.md) runs it for you; `init` with no options
prints them all.

### Changing the chain source

`lz-server <config.toml> set-chain --lightwalletd <url> [--network …]`
checks the new source as `doctor` does, then rewrites only `network` and
`[chain] lightwalletd` in the config, keeping its comments; `--no-check`
skips the check. The server uses it from its next start. Nothing stored
depends on the chain source, so accounts carry over; after a network
change, wallets on the old network refuse the server (§4.7).

### Rotating the OHTTP key

```sh
lz-server <config.toml> rotate-ohttp              # routine: at least every 90 days
lz-server <config.toml> rotate-ohttp --drop-old   # suspected leak
```

No restart is needed: a running server re-reads its keys every 5
minutes, so a cron job or systemd timer can rotate on a schedule (every
30 days is a good choice for a hosted server). The gateway
serves only the new key configuration, under a new key id, and `info`
publishes its hash, so wallets fetch it again. The old key keeps working
for 7 days, for wallets that cached it, and is then deleted from memory
and disk (spec §3.2). Requests to a
key id the server no longer accepts get RFC 9458's `ohttp-key` problem.
With `--drop-old`, no old key is accepted after the next reload. `doctor`
warns when the key is more than 90 days old. Keys live in
`data_dir/ohttp-key` and `data_dir/ohttp-retired/`; a pre-rev-3.13
`ohttp-ikm` is migrated unchanged as key id 1.

### Rotating the VAPID key

```sh
lz-server <config.toml> rotate-vapid              # routine
lz-server <config.toml> rotate-vapid --drop-old   # suspected leak
```

Stop the server first, and start it again afterwards: while it runs, it
holds the data directory, and `rotate-vapid` refuses to start. Push
subscriptions are bound to the key they were
created with (spec §5.3), so each device record keeps its key, and `info`
publishes the new one. Wallets notice the change, subscribe again with the
new key, and delete their old device record; the old key, in
`data_dir/vapid-retired/`, is deleted at the first start after no device
uses it. With `--drop-old`, old keys are deleted at once and the devices
bound to them are dropped at the next start; those wallets register again
when their next `wake` gets `unknown-device`.

## One server per data directory

A server keeps device records and replay windows in memory and writes
`state.json` whole, so it takes `data_dir/server.lock` at start, and a
second server, or `rotate-vapid`, on the same directory refuses to start
until it stops. Run one server per deployment and give it more CPU and
memory as it grows; several servers behind one URL would also each send
every wake-up. `new-account`, `rotate-ohttp`, and `doctor` work while it
runs.

## Security notes

- **Data directory.** `data_dir` holds the server's own keys (OHTTP keys,
  VAPID keys), token hashes, device records, and, when `[accounts]` uses
  them, scanning end times, last-active days, and the issuer socket
  ([`ISSUER.md`](ISSUER.md)). The directory is created
  `0700` and its files `0600`. It never holds viewing keys or anything
  derived from them.
- **Logs.** Nothing logs tokens, request bodies, headers, or push endpoints.
  HTTP library logs are capped at `warn` even with `RUST_LOG=trace`, because
  they include hosts; so are `ohttp` and `bhttp`, whose trace logs include
  derived key material and message bytes. A test checks this at trace
  level.
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
  permissions, core dumps, memory and swap, the OHTTP key's age, the
  chain source (network and tip age), that the gateway serves this
  server's key configuration where wallets reach it, that an onion
  service answers by its name through Tor (through the Tor client in
  `LZ_TOR_SOCKS`, which the kit sets; it warns when there is none), and
  the clock against
  `pool.ntp.org` (one SNTP query), and prints pass, warn, or fail for
  each. Its output has no tokens, keys, URLs, or host names, so it's safe
  to paste into an issue.
- **Web Push crypto** (`src/webpush.rs`) is built on RustCrypto primitives
  and checked against the RFC 8291 test vector. Existing Web Push crates
  depend on a `crypto-bigint` with timing leaks (RUSTSEC-2026-0387).
- **Minimum Rust 1.89**, because `zcash_client_backend` 0.25 (the first
  release with Ironwood) needs it. The whole workspace uses the same
  minimum.
- **Chain source.** Without a `[chain]` section, `tip` stays `0`. Run Zaino
  on the same host or private network (`http://`), or use `https://`.
