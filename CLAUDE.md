# CLAUDE.md: Lantern Zero (public repo)

Lantern Zero gives Zcash wallets faster sync and payment notifications. It is a
bridge until Zcash's Tachyon upgrade changes how wallets find payments. Read
`README.md` first for the user-facing description.

**Status (2026-10-31): pre-alpha, phase 1 of 4: spec and prototype.** The
draft protocol spec is `spec/v0.md` (rev 3.8); `crates/lz-proto` holds the
shared protocol types; `server/` is a prototype (OHTTP gateway, devices,
30-minute pings, chain follower, and the scanner with in-memory leases,
events, hints, and long-poll). See `server/README.md` for what's missing.
This is the public, open-source repo (MIT OR Apache-2.0). Business and hosting details live in the private
`principlezerolabs/lanternzero-ops` repo; never put them here.

## The design, in one screen

- **Two modes.**
  - *Default:* keyless wake-ups. The server sends the same contentless ping
    to every registered device every **30 minutes**. The app wakes and
    trial-decrypts new compact blocks locally.
  - *Opt-in scanning:* the wallet lends the server an **incoming viewing key
    (IVK)** as a lease. The server trial-decrypts blocks and the mempool, then
    sends a per-payment push plus a **hint list** (heights to scan first).
    Accept a full viewing key only when the user explicitly wants spend alerts.
- **Why 30 minutes:** Apple says to send no more than 2–3 background pushes an
  hour. A ping every block exceeds that. Mainnet blocks are 75 s now and 25 s
  after NU7 (around 5 Nov 2026), so expect about 72 blocks per wake.
- **Wallets connect through a URL** (endpoint plus bearer account token) that
  the user pastes into the wallet, much like a custom lightwalletd server.
  Hosted, self-hosted, and wallet-sponsored servers all use the same URL format
  and API.
- **Push goes through the wallet vendor's gateway.** Only the app developer
  holds its APNs and FCM credentials, the same model as Matrix's Sygnal. The
  server sends each ping to the gateway encrypted to the device with RFC 8291,
  so the gateway, Apple, and Google see only timing.
- **Transport:** every client request uses Oblivious HTTP (RFC 9458) through
  a relay run by a third party (neither the server operator nor the wallet
  vendor; never the server operator). Wallet vendors ship the relay list and
  rotate among relays. Self-hosted servers may use a Tor onion service
  instead. Requests and responses are padded to fixed sizes. OHTTP is
  request/response only, so use **long-poll** (25–30 s timeout) for live
  updates, not WebSockets or SSE. Webhooks are for merchants and
  self-hosters, not phones.
- **Chain data** comes from Zebra and Zaino over the lightwalletd gRPC API
  (`CompactTxStreamer`): `GetBlockRange`, `GetBlockRangeNullifiers`,
  `GetTreeState`, `GetSubtreeRoots`, `GetMempoolStream`.
  - Pools: Sapling, Orchard (spends disabled by soft fork in June 2026), and
    Ironwood (active since NU6.3, 28 Jul 2026, block 3,428,143). One
    Orchard-protocol IVK trial-decrypts both Orchard and Ironwood notes
    (ZIP 229, ZIP 326); there is no separate Ironwood key.
- **Spam policy:** during a spam wave, scanners fall behind and catch up. Do
  not provision for peak load.

## Privacy invariants and code rules

They live in `CONTRIBUTING.md`, imported below, so humans and agents read the
same copy. Treat a violation as a bug, and test for it.

@CONTRIBUTING.md

## Where things go

| Path | Build here |
| --- | --- |
| `spec/` | URL format and HTTP API: registration, lease renewal, hint list, long-poll, webhooks. **Change the spec first**; code follows. Version it. |
| `server/` | Chain follower, wake-up scheduler, scanner with RAM leases, hint list, long-poll and webhook endpoints, OHTTP gateway side |
| `gateway/` | Reference push gateway (prototype): stateless sealed endpoints, subscriptions bound to one server's VAPID key, per-device rate limits, forwards to APNs/FCM |
| `crates/lz-proto/` | Shared protocol types from the spec: requests and responses, padding, tokens, event ids, replay window. Test vectors in `spec/vectors/` |
| `client/` | Rust client core for wallets (OHTTP, registration, lease renewal, hint list, long-poll). No I/O: the host app sends the bytes |
| `deploy/` | Docker Compose self-host kit: profiles `full` (Zebra, Zaino, server, Tor) and `byo-node` (server and Tor, pointed at an existing node), with hardening for spec §6.2. Plan in `deploy/DESIGN.md` |
| `skill/` | Claude skill that guides and troubleshoots self-hosting. The Compose files and `lz-server init` do the installing; the skill runs `lz-server doctor` and never improvises configuration. |

## Technology

- **Rust** for server, gateway, and client core. Use the Zcash crates
  (`zcash_client_backend`, `sapling-crypto`, `orchard`; Ironwood uses the
  Orchard protocol, so pick crate versions with NU6.3 support) rather than
  reimplementing note decryption.
- **OHTTP:** the `ohttp` and `bhttp` crates (Martin Thomson; also used in
  Firefox). Relays: the Payjoin relay, now in
  `payjoin/rust-payjoin` (`payjoin-mailroom`); the standalone
  `payjoin/ohttp-relay` was archived in Dec 2025. It forwards only to
  gateways declaring the BIP77 purpose, so it needs a configurable-purpose
  change before it can carry Lantern Zero traffic (spec §9).
- **Decided (2026-10-31):**
  - **Workspace:** one Cargo workspace (`crates/lz-proto`, `server`,
    `gateway`, `client/core`). Client-side crates (`lz-proto`, client core)
    must not depend on `zcash_client_backend`, tokio, or a TLS stack, and
    must build on Rust 1.86, so wallet SDKs with pinned librustzcash
    versions can embed them.
  - **Bindings:** none of our own at first. Wallet SDKs (ZODL's use
    hand-written JNI on Android and `cbindgen` on iOS, in one native
    library) compile the client crate into that library and expose it
    through their own FFI. A second Rust static library in the same app
    risks duplicate symbols. Generate UniFFI bindings only when an app
    without a Rust core asks.
  - **Client I/O:** sans-IO. The core builds and opens OHTTP messages; the
    app sends them with URLSession or OkHttp. An optional `reqwest` feature
    serves merchant backends and tests.
  - **HTTP framework:** axum, with the OHTTP gateway as a tower layer in
    front of the API.
  - **Gateway storage:** none. The device token rides encrypted inside the
    endpoint URL; rate limits live in memory.
  - **Crates:** `ohttp` with the `rust-hpke` backend (never `nss`). CI must
    fail if `ohttp`'s `unsafe-print-secrets` feature is enabled. APNs via
    our own small HTTP/2 client (`a2` is unmaintained since 2024); FCM via
    `gcp_auth` with `reqwest`; Web Push is our own small implementation on RustCrypto
    (`server/src/webpush.rs`), because the existing crates pull in a
    `crypto-bigint` with timing leaks.
- **Prior art worth reading:**
  - `samizdatproject/zeccheckout` (MIT): a UFVK scanner over compact blocks
    with mempool polling and signed webhooks.
  - `monero-lws`: the Monero light-wallet server equivalent.
  - librustzcash `ScanPriority::FoundNote`: the hint list should map onto
    it. The upstream hook does not exist yet.

## Phase 1 work (in rough order)

1. Write the URL and API spec in `spec/`.
2. Prototype the server against Zebra and Zaino: 30-min wake-ups, then the
   scanner with RAM-only leases.
3. Build the reference push gateway. It binds each subscription to one
   server's VAPID key and rate-limits per device, with no admission list
   (spec §5.3, decided in issue #6), so self-hosted servers get wake-ups.
4. Measure: iOS wake delivery, the time to scan about 72 blocks on a phone,
   and Zaino's disk usage on a synced mainnet node.
5. Self-host packaging (`deploy/DESIGN.md`): `lz-server init` and
   `lz-server doctor`, the Compose kit with its two profiles and §6.2
   hardening, signed images pinned by digest, then the Claude skill.
6. After phase 1: a StartOS package that depends on the community Zebra
   package, then Umbrel. Cloud images (AMI, 1-click) are deferred; see the
   design note for why.

## Open questions (don't assume answers)

- The hook for feeding outside hints into a wallet's scan order: librustzcash
  `suggest_scan_ranges`, and ZODL's Slipstream sync engine, which now drives
  scanning in ZODL wallets. Raise it at the light client working group and
  with ZODL.
- Whether Apple grants the notification-filtering entitlement. It is
  optional, because opt-in scanning covers fast iOS alerts.
- Which servers the Tachyon team expects third parties to run: PIR
  databases, oblivious sync, or the introduction service. After Tachyon, the
  scanner retires and the wake-up channel stays.

## Working rules

- This repo is public. No secrets, no customer or pricing details, no
  hosting specifics. Those belong in `lanternzero-ops`.
- Any code that touches keys or tokens needs tests that prove invariants 1–6
  hold: no persistence, no logging, leases expire. Run the checks listed at
  the end of `CONTRIBUTING.md`, including `cargo deny check`, before
  committing.
- Commit or push only when the user asks.
- Contributions are dual-licensed MIT OR Apache-2.0 (see `README.md`).
