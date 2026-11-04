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

**Refuses** lists the servers a relay won't carry, usually because its
operator runs them (spec §1.1 forbids using those anyway). Wallets pick
each server's relays from the ones that don't refuse it. Today that leaves one relay for self-hosted servers and none for
servers under `lanternzero.com`, so this list isn't enough yet for the
two relays per server that spec §1.1 asks for.

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
