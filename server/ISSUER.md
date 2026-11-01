# Issuer interface

Whoever issues accounts on a Lantern Zero server, whether a hosted sign-up
site, a wallet company sponsoring its users, or a self-hoster sharing with
friends, uses this interface to create accounts and give them scanning
time (spec §2.3, §4.6). It belongs to the reference server, not to the wire
protocol: wallets never see it.

## Turning it on

```toml
[accounts]
scanning = "all"          # or "entitled": only accounts with scanning time left
idle_account_days = 0     # 0 = never delete idle accounts; otherwise at least 8
issuer_socket = false     # true: serve <data_dir>/issuer.sock
```

With the defaults, a server behaves as it did before the interface
existed: every account may scan, accounts never expire, there is no socket,
and the server stores no activity dates. `scanning = "entitled"` requires
`issuer_socket = true`, because nothing else can give an account scanning
time.

## Transport

HTTP/1.1 over a Unix domain socket, `<data_dir>/issuer.sock`, mode `0600`.
Only processes running as the server's user can connect. The server never
serves it over TCP or through the OHTTP gateway. To try it:

```sh
curl --unix-socket lz-data/issuer.sock -H 'content-type: application/json' \
  -d '{"token_hash":"<64 hex>"}' http://localhost/create
```

Every call is a `POST` with a JSON body. Errors are RFC 9457 problem
details, as in the API (spec §3.6). Account ids are the server's random
16-byte ids in lowercase hex; times are Unix seconds.

## Calls

| Path | Body | Answer | Errors |
| --- | --- | --- | --- |
| `/create` | `{token_hash}` | `201 {account}`. Live at once, with no restart | `409 hash-taken` |
| `/resolve` | `{token_hash}` | `{account}`, or `{account: null}`. Covers a token still in its rotation grace (spec §4.6). It neither retires a token nor counts as activity | |
| `/scan_until` | `{account}` | `{until}`, or `{until: null}` when no time is left | `404 unknown-account` |
| `/add_scan_time` | `{account, secs, key}` | `{until}`. Adds after whatever is left, or from now | `404 unknown-account`, `409 key-reused`, `400` if `secs` is 0 or over 10 years, or `key` isn't 1–128 bytes |
| `/deletions` | `{after}` (0 to start) | `{accounts, next}`: deleted account ids after cursor `after`, oldest first, up to 1000. Pass `next` as `after` the next time | |
| `/delete` | `{account}` | `204`. The same as `DELETE /v0/account` | `404 unknown-account` |

- **`token_hash`** is the lowercase hex SHA-256 of the token's text form
  (spec §2.2). The issuer gets it from the user's device at sign-up (spec
  §2.3) and never sees the token.
- **`key`** makes `add_scan_time` idempotent. Use something unique to the
  payment or grant, such as an invoice id. A retry with the same key adds
  nothing and returns the current end time, so a lost answer can't add time
  twice. Keys are kept, hashed, for 30 days.
- **`deletions`** keeps ids for 30 days, whoever deleted the account: the
  user (`DELETE /v0/account`), the idle sweep, or `/delete`. An issuer that
  keeps its own records about accounts should poll it at least every few
  weeks and drop those records.

## What it can't do

- It can't list accounts, read token hashes back out, or show activity
  days. An issuer reaches only accounts it created or whose token hash it
  already holds.
- It can't take scanning time away; `/delete` is the only way to end it
  early.
- Nothing it handles is logged: no token hashes, account ids, or keys.

## What the server stores

All of it is in `data_dir/state.json`, and none of it comes from a viewing
key (invariants 1 and 3):

- each account's scanning end time, until it passes;
- with `idle_account_days` set, the UTC day of each account's last
  authenticated request, and nothing finer (spec §4.6). It is written with
  the periodic flush, so at most about once a day per account. Turning idle
  expiry off deletes these dates at the next start;
- SHA-256 hashes of `add_scan_time` keys, for 30 days;
- with the socket on, ids of deleted accounts, for 30 days.

## Idle expiry

With `idle_account_days = N`, the server checks every hour and deletes
accounts with no authenticated request for more than N days, as
`DELETE /v0/account` would, unless they have scanning time left. Days on
which the server was down (no check ran) don't count. `info` publishes N
(spec §4.7). N must be at least 8, more than the longest lease, so a phone
that is switched off for a week keeps its account.
