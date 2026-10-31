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

| Relay URL | Operator | Software | Added |
| --- | --- | --- | --- |
| *none yet* | | | |

To add a relay, open a pull request with the operator's public contact and
retention policy.
