# Community OHTTP relays

A starting list for wallet vendors (spec §1.1). It is not authoritative.
Wallets ship their own list, and users may edit it.

A relay qualifies if it meets all of these:

- **Operator:** not a wallet vendor that ships the list. An operator that
  also runs Lantern Zero servers qualifies only if its relay refuses all
  of them; the table says which servers each relay refuses.
- **Logging:** it logs no client IPs beyond what abuse limits need, and
  publishes its retention period.
- **Gateways:** it forwards to Lantern Zero gateways, which declare the
  purpose `LanternZero v0 4bca76ac-1094-4330-97df-03d5c81b576d` (spec §3.1).
- **Timeouts:** it allows the gateway at least 35 seconds to start its
  response (spec §1.1).
- **Headers:** it forwards no headers that describe the client, such as its
  address or region (spec §1.1).

| Relay URL | Operator and policy | Software | Key configuration (§3.2) | Refuses | Added |
| --- | --- | --- | --- | --- | --- |
| `https://relay.lanternzero.com` | Principle Zero Labs ([policy](https://lanternzero.com/relay)) | `lz-relay` | yes | `lanternzero.com` and every name under it, which includes the Lantern Zero hosted service | 2026-11-04 |
| `https://relay.oblivious.network/<relay name>`, one per server, set up by the wallet vendor (below) | Oblivious Network LLC ([privacy](https://oblivious.network/privacy); retention below) | hosted service | yes | none | 2026-11-06 |

**Refuses** lists the servers a relay won't carry, usually because its
operator runs them (spec §1.1 forbids using those anyway). Wallets pick
each server's relays from the ones that don't refuse it. Today that leaves two relays for self-hosted servers, but only one
(Oblivious Network) for servers under `lanternzero.com`, so this list
isn't yet enough for those servers to have the two relays spec §1.1 asks
for.

## Notes on listed relays

### Oblivious Network

- **Setup.** It's a paid hosted service. Each relay URL forwards to one
  gateway, so the wallet vendor creates a relay in its own account for
  each server, with that server's gateway URL
  (`https://<server>/.well-known/ohttp-gateway`). Raise **First Byte
  Timeout** from its 15 s default to at least 35 s (spec §1.1).
- **Logging**, as Oblivious stated it to us on 2026-11-02 and 2026-11-05
  (quoted with permission; their privacy page doesn't say this yet):
  - It doesn't log client IP addresses.
  - Per request, it logs the minute, the duration, the gateway URL, bytes
    received and sent, the response status, and the relay region. The
    region is one of about 20.
  - These records are kept for about 90 days. Totals for billing are kept
    indefinitely.
  - Its relays run on Fly.io and Vultr by default. Those platforms may keep
    their own logs under their own terms.
- **Headers.** Since 2026-11-05 it adds no headers that describe the
  client (tested 2026-11-06). A client that sends `x-oblivious-debug: true`
  turns region and connection headers back on for its own requests.
  Wallets shouldn't send it.
- **Key configuration.** A GET with `Accept: application/ohttp-keys` is
  forwarded (spec §3.2). Without that header, the relay answers 404 itself.
- **Quirks.**
  - The relay drops query strings, so `?allowed_purposes` can't be fetched
    through it. Wallets don't need it.
  - Gateway error responses arrive with `Content-Type: message/ohttp-res`.
    Clients should recognise an `ohttp-key` problem by its body; the client
    core already does.

## Software

- **`lz-relay`** ([`relay/`](../relay/README.md)) meets the rules
  above as shipped, and fetches key configurations for wallets. Requests
  go to `https://<relay>/<server origin>`.
- **payjoin-mailroom** will qualify once it can accept purposes other
  than BIP77 ([payjoin/rust-payjoin#2026](https://github.com/payjoin/rust-payjoin/pull/2026)).
  It carries the key-configuration fetch only through a tunnel, which the
  client core can't open, so wallets using it also need a mirror or
  another source that hides the wallet's IP (spec §3.2).

## Adding a relay

Open a pull request with the operator's public contact, its retention
policy, and the servers it refuses. [`relay/README.md`](../relay/README.md)
covers running `lz-relay`.
