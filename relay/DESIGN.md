# relay: design

**Status:** prototype (2026-11-03). The crate does what this page
describes, with tests against a fake gateway and end to end with
`lz-server` and `lz-client`. Packaged: the image (`Dockerfile`, signed
and published by the Images workflow since v0.1.2), the Compose example
with Caddy (`deploy/`, tested in CI by `deploy/smoke-test.sh`), and the
operator README. Running at `relay.lanternzero.com` since 2026-11-04.
Listed in `spec/relays.md` since 2026-11-04. Tracking issue:
[#9](https://github.com/principlezerolabs/lanternzero/issues/9).

`lz-relay` is a small OHTTP relay (RFC 9458) for Lantern Zero gateways.
It's meant to be run by third parties, such as community organizations:
anyone who runs neither a Lantern Zero server nor the wallet that lists
the relay, or who refuses every server it runs (spec §1.1). It does one job: forward encapsulated requests to
gateways that declare the Lantern Zero purpose, and see as little as
possible while doing it.

## Why our own

Every Lantern Zero request goes through a relay (spec §1.1), and wallets
should pick among at least two run by different operators. Today none
qualifies:

- **payjoin-mailroom** forwards only to gateways declaring the BIP77
  purpose. Making that configurable is proposed upstream
  (payjoin/rust-payjoin#2026), and is still the best way to reach its
  existing operators. Through mailroom, the key-configuration fetch
  needs a CONNECT or WebSocket tunnel to the gateway, which our client
  core, which only builds OHTTP messages, can't provide (spec §3.2). And
  mailroom always runs its mailbox service as well.
- **Commercial relays** (Oblivious Network, Cloudflare, Fastly) work or
  may work, but they're paid, and Oblivious adds headers that describe
  the client's region (spec §9, question 3).
- **Other open relays** each miss something: Cloudflare's Workers
  sample carries only POSTs, so not the key fetch; Guardian Project's
  `pog` serves a single gateway; alpe's `ohttp-relay` needs each gateway
  registered and serves keys at a non-standard path (spec §9, question
  4).

`lz-relay` doesn't replace the upstream change: if #2026 merges, wallets
can list both kinds. It gives operators who'd rather run something small
and single-purpose a relay they can read in an afternoon, and it's the
starting point for making relays easy to host.

## What it does

- **Forward:** `POST https://<relay>/<gateway origin>`, for example
  `POST https://relay.example/https://lz.example.org`, with
  `Content-Type: message/ohttp-req`. A bare host means `https`. That's
  payjoin-mailroom's URL shape, so wallets address both alike. The relay
  sends the body to `<gateway origin>/.well-known/ohttp-gateway` and
  returns the gateway's status, `Content-Type`, and body. The gateway
  origin is a scheme, a host, and an optional port, nothing else: no
  path, query, or userinfo.
- **Key configuration:** `GET https://<relay>/<gateway origin>` returns
  the gateway's key configuration (RFC 9540
  `/.well-known/ohttp-gateway`), as Oblivious Network's relay does. The
  relay fetches it from its own address and caches it for an hour, or
  for the gateway's `max-age` if that is shorter, so every client gets
  the same bytes. That makes the relay a valid source for spec §3.2 (a
  relay that fetches it for the wallet) and, with a second operator's
  relay, a valid second source.

  An hour is harmless when a server rotates its key: it keeps accepting
  the previous one for 7 days (`server/src/ohttp_keys.rs`). After
  `rotate-ohttp --drop-old` (a suspected leak), the old key stops
  working at once, and the gateway answers requests made with it with
  the `ohttp-key` problem (spec §3.2), unencrypted because it can't
  decrypt them. When the relay forwards that answer, it fetches the
  configuration again, at most once a minute per gateway, so a client's
  refetch gets the new one and a stream of bad requests can't make the
  relay hammer the gateway.
- **Only Lantern Zero gateways.** Before forwarding to a gateway for the
  first time, the relay fetches
  `<gateway origin>/.well-known/ohttp-gateway?allowed_purposes`, the
  opt-in mailroom uses, and forwards only if the list contains the
  Lantern Zero purpose (`lz_proto::OHTTP_PURPOSE`). It caches the answer
  (yes for 24 hours, no for 1 hour). A self-hosted server needs nothing
  from the relay operator. Operators may also set an allow list (only
  these gateways) or a deny list (never these, nor names under them, so
  an operator can deny its own domain whole).
- **What the caches show.** Both caches are shared by all clients, so a
  client can tell from timing whether some client used a gateway within
  the cache time. That says only that a public server has users, never
  which client.
- **Browsers.** Responses carry `Access-Control-Allow-Origin: *`, and
  the relay answers CORS preflights, as mailroom and Oblivious do, so
  wallets running in a browser can use it. That reveals nothing: the
  relay sends no credentials and reads none.

## Rules (spec §1.1, and what operators promise)

- **Headers.** It forwards only `Content-Type`, and sets only what HTTP
  framing needs plus a constant `Accept: message/ohttp-res`. It adds nothing about the client: no `Forwarded`, no
  `X-Forwarded-For`, no region, no connection state. Responses carry
  back only `Content-Type`, framing, and the CORS header.
- **Timeouts.** It allows the gateway 40 seconds to send the first byte
  (spec §1.1 requires at least 35, for 30-second long-polls) and 60 in
  all, and a client 10 seconds to send its request body. The reverse proxy in front of it must allow at least as long;
  the Compose example's does.
- **Sizes.** Request bodies are capped at the largest encapsulated
  request (`lz_proto::padding::REQUEST_SIZE` plus HPKE overhead) and
  responses at the largest encapsulated response. Anything bigger is
  refused, never truncated.
- **No logs about clients.** No client IPs, no per-request lines, no
  gateway origins next to timestamps (which would show which server a
  client uses, and when). Logs are startup, errors that name no client,
  and periodic totals across all gateways (requests forwarded, refused,
  rate-limited); per-gateway totals would show how busy a small server
  is.
- **Rate limits** per client IP, held in memory only: a token bucket per
  IPv4 address and per IPv6 /64, dropped when idle. Restarting forgets
  them. Core dumps are off, because that table holds client addresses.
- **No server-side request forgery.** The relay fetches URLs that
  clients name. It resolves names itself, refuses loopback, private,
  link-local, and other non-public addresses, and connects only to the
  addresses it checked, so a name that changes what it resolves to
  can't slip past. It never follows redirects. Nothing is forwarded to
  a gateway before its opt-in check succeeds, so the relay can't be used
  to send POSTs to services that aren't Lantern Zero gateways. Targets
  are `https` only; ports other than 443 (self-hosted servers may use
  them) are an operator setting, and plain `http` is for tests only.
  Hosts are read the way the HTTP client reads them (WHATWG URL rules),
  so `2130706433` or `0x7f.1` is checked as the `127.0.0.1` it would
  connect to, not passed on as a name.

## Deployment

- One binary, `lz-relay`, configured by a small TOML file. The image is
  distroless, non-root, and read-only, built and signed by the same
  release workflow as the self-hosting kit's images, and pinned by
  digest.
- **TLS** comes from a reverse proxy in the example Compose file: Caddy,
  pinned by digest, which gets certificates on its own and writes no
  access log unless told to. Its error log does name the client and the
  path of each request it fails, so the Caddyfile leaves that logger
  out. The relay trusts `X-Forwarded-For` only from that proxy, and only
  for rate limits. The README tells operators who use another proxy to
  keep client addresses and request paths out of its access and error
  logs, because they would otherwise hold every client's IP.
- **Network.** Caddy and the relay share a small private network where
  Caddy has a fixed address, the one `trusted_proxies` names; other
  containers get addresses from a separate range, so none can take it.
  (Running the relay in Caddy's network namespace, on loopback, was
  simpler but broke whenever Caddy restarted.)
- **Caddy version.** 2.11.7 or newer: 2.11.6 added idle timeouts that
  cut off some held responses. The smoke test holds answers for 38
  seconds over HTTP/1.1 and HTTP/2 to catch that kind of change.
- `relay/README.md` is for operators: what the relay sees, what it keeps
  (nothing about clients), what to publish (contact, retention), and how
  to be listed in `spec/relays.md`.

## Code

- A new workspace crate, `relay/` (`lz-relay`). Server-side, like
  `server/` and `gateway/`: it may use tokio and rustls, and the
  client-side crates must never depend on it. It uses `lz-proto` only for
  the purpose string and the size constants, so the caps can't drift
  from the protocol.
- axum for the listener, as in the server and gateway. For gateway
  connections, `reqwest` (already in the workspace) with rustls and
  HTTP/2, a DNS resolver of our own that drops non-public addresses,
  redirects turned off, and proxy settings from the environment ignored
  (they would route around the resolver).
- Logging and hardening follow the server. The relay copies the
  server's address checks (`src/ssrf.rs`) and `log_filter` rather than
  sharing them: a shared server-side crate (CLAUDE.md, "No shared
  server/gateway crate yet") would mean reworking the server's imports,
  so it's a separate change, now with three users.
- **Tests:**
  - headers: a fake gateway records what arrives and asserts that only
    `Content-Type` does;
  - logs: a captured-log test asserts that no client address or gateway
    origin is written;
  - admission: forwards to a gateway that declares the purpose, refuses
    one that doesn't, honors the cache times and the allow and deny
    lists;
  - key configuration: every client gets the same bytes, and an
    `ohttp-key` answer triggers one refetch per minute at most;
  - forgery: refuses loopback, private, and link-local targets,
    including names that resolve to them, origins with a path or
    userinfo, and redirects; plus property tests for gateway-origin
    parsing, the input clients fully control;
  - limits: oversize bodies, rate limits, and the 40-second first byte
    (with a held fake long-poll);
  - end to end: `lz-server` and `lz-client` through the relay, as in the
    mailroom interop test.

## Changes elsewhere

- Spec §9, question 1 points to `lz-relay`; `spec/relays.md` names it as
  relay software.
- CLAUDE.md's "Where things go" table gets a `relay/` row.
- The Images workflow builds and signs `lantern-zero-relay` with the
  kit's images; CI runs `relay/deploy/smoke-test.sh`.

## Prior art

Read these before writing the code; none is a dependency.

- **payjoin-mailroom** (`payjoin/rust-payjoin`, Rust, MITNFA): the
  closest match, and the relay we stay compatible with. Its
  `ohttp_relay/` module has the URL parsing (`gateway_uri.rs`) and the
  `allowed_purposes` prober with caching (`gateway_prober.rs`).
- **thibmeu/ohttp-relay** (TypeScript, MIT): a pure passthrough with
  careful header stripping, deployable on Cloudflare Workers, Vercel,
  Netlify, or Node. Its one-click deploys are a model for making relays
  easy to host, though it serves a single gateway.
- **vauchi/ohttp-relay** (Rust, AGPL-3.0): has rate limiting and a fuzz
  target for gateway URL validation. Read it for ideas only: its license
  doesn't allow copying into an MIT/Apache crate.
- **cloudflare/privacy-gateway-relay** (Workers, BSD-3-Clause): the
  original sample; one fixed target, POST only.
- **RFC 9458 §6.2, §7, and §8:** what a relay is responsible for (not
  adding client information, treating clients alike, denial of
  service), and the privacy and deployment considerations.

## Not in scope

- Mailboxes, or any storage. The relay keeps nothing on disk.
- Other purposes. The purpose list is a setting, so it could serve other
  OHTTP applications later, but v0 ships with Lantern Zero's only.
- Choosing relays for anyone. Wallet vendors pick them (spec §1.1);
  `spec/relays.md` lists relays that meet the rules above.

## Open questions

1. **Rate-limit numbers.** A wallet makes a handful of requests per wake
   plus held long-polls. Start generous (for example 60 a minute and 10
   concurrent per address) and measure.
2. **Timing.** RFC 9458 §6.2.3 notes that a relay can add delay to make
   traffic analysis harder. Lantern Zero's sizes are already fixed, and
   its wakes are scheduled, so timing between a client and the gateway
   is what's left. The relay can't tell a long-poll from other requests
   (all are encrypted and the same size), so any delay applies to every
   request and slows payment alerts. Leave it out of v0; revisit if
   measurements show timing links clients to accounts.
