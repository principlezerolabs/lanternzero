# Community OHTTP relays

A starting list for wallet vendors (spec §1.1). It is not authoritative.
Wallets ship their own list, and users may edit it.

A relay qualifies if it meets all of these:

- **Operator:** neither a Lantern Zero server operator nor a wallet vendor
  that ships the list.
- **Logging:** it logs no client IPs beyond what abuse limits need, and
  publishes its retention period.
- **Gateways:** it forwards to Lantern Zero gateways, which declare the
  purpose `LanternZero v0 4bca76ac-1094-4330-97df-03d5c81b576d` (spec §3.1).
- **Timeouts:** it allows the gateway at least 35 seconds to start its
  response (spec §1.1).
- **Headers:** it forwards no headers that describe the client, such as its
  address or region (spec §1.1).

| Relay URL | Operator | Software | Added |
| --- | --- | --- | --- |
| *none yet* | | | |

Most relays can't carry the key-configuration fetch (spec §3.2). Wallets
using them also need a mirror or another source that hides the wallet's IP.

To add a relay, open a pull request with the operator's public contact and
retention policy.
