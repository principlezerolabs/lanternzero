# CLAUDE.md: Lantern Zero (public repo)

Lantern Zero gives Zcash wallets faster sync and payment notifications. It is a
bridge until Zcash's Tachyon upgrade changes how wallets find payments. Read
`README.md` first for the user-facing description.

**Status (2026-10-31): pre-alpha, phase 1 of 4: spec and prototype.** Only
READMEs exist so far. This is the public, open-source repo (MIT OR Apache-2.0).
Business and hosting details live in the private `principlezerolabs/lanternzero-ops`
repo; never put them here.

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
  an independent relay. OHTTP is request/response only, so use **long-poll**
  (25–30 s timeout) for live updates, not WebSockets or SSE. Webhooks are for
  merchants and self-hosters, not phones.
- **Chain data** comes from Zebra and Zaino over the lightwalletd gRPC API
  (`CompactTxStreamer`): `GetBlockRange`, `GetBlockRangeNullifiers`,
  `GetTreeState`, `GetSubtreeRoots`, `GetMempoolStream`.
  - Pools: Sapling, Orchard (spends disabled by soft fork in June 2026), and
    Ironwood (active since NU6.3, 28 Jul 2026, block 3,428,143).
- **Spam policy:** during a spam wave, scanners fall behind and catch up. Do
  not provision for peak load.

## Privacy invariants (treat violations as bugs; test for them)

1. Viewing keys live **only in scanner memory**: never on disk, in logs, in
   crash dumps, in backups, or in metrics. A server restart drops them; apps
   re-send keys at their next wake.
2. A key is a **lease**, 24 h to 7 days, renewed by the app on each wake. It is
   dropped at once on opt-out, when the lease expires, or when the paid period
   ends.
3. Data derived from a key (matched payments) is deleted when the app
   acknowledges it, or after 7 days at most. Keep no per-key history.
4. **Default-mode and scanning-mode users must look identical on the wire.**
   Every request goes over OHTTP, and everyone gets the same scheduled pings.
5. Push payloads never carry amounts, memos, or txids in the clear. Anything
   the device must see is RFC 8291-encrypted to it.
6. Account tokens are bearer secrets. Never log them or put them where relays
   can see them; they travel inside the OHTTP-encrypted request.
7. Never call per-transaction lookups (for example `GetTransaction`) in ways
   that reveal which transactions matter to a user.

## Where things go

| Path | Build here |
| --- | --- |
| `spec/` | URL format and HTTP API: registration, lease renewal, hint list, long-poll, webhooks. **Change the spec first**; code follows. Version it. |
| `server/` | Chain follower, wake-up scheduler, scanner with RAM leases, hint list, long-poll and webhook endpoints, OHTTP gateway side |
| `gateway/` | Reference push gateway: accepts encrypted pings, forwards to APNs/FCM |
| `client/` | Rust client core for wallets (OHTTP, registration, lease renewal, hint list, long-poll), plus Swift and Kotlin bindings |
| `deploy/` | Docker Compose self-host kit: Zebra, Zaino, server, optional Tor or OHTTP relay |
| `skill/` | Claude skill that guides and troubleshoots self-hosting. The Compose files do the installing; the skill never improvises configuration. |

## Technology

- **Rust** for server, gateway, and client core. Use the Zcash crates
  (`zcash_client_backend`, `sapling-crypto`, `orchard`, and the Ironwood
  equivalents) rather than reimplementing note decryption.
- **OHTTP:** the `ohttp` and `bhttp` crates (Martin Thomson; also used in
  Firefox). Relays: `payjoin/ohttp-relay`.
- **Undecided; propose before building:** Cargo workspace layout, binding
  generator (for example UniFFI), HTTP framework, and gateway storage.
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
3. Build the reference push gateway.
4. Measure: iOS wake delivery, the time to scan about 72 blocks on a phone,
   and Zaino's disk usage on a synced mainnet node.
5. Write the Docker Compose kit and the Claude skill.

## Open questions (don't assume answers)

- The librustzcash hook for feeding outside hints into `suggest_scan_ranges`.
  Raise it at the light client working group.
- Whether Apple grants the notification-filtering entitlement. It is
  optional, because opt-in scanning covers fast iOS alerts.
- Which servers the Tachyon team expects third parties to run: PIR
  databases, oblivious sync, or the introduction service. After Tachyon, the
  scanner retires and the wake-up channel stays.

## Working rules

- This repo is public. No secrets, no customer or pricing details, no
  hosting specifics. Those belong in `lanternzero-ops`.
- Any code that touches keys or tokens needs tests that prove invariants 1–6
  hold: no persistence, no logging, leases expire.
- Commit or push only when the user asks.
- Contributions are dual-licensed MIT OR Apache-2.0 (see `README.md`).
