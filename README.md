# Lantern Zero

Faster sync and payment notifications for Zcash wallets, without handing your
keys to anyone by default.

> **Status: pre-alpha.** The server, wallet client core, push gateway, and
> self-hosting kit are working prototypes. They are tested end to end with
> each other, against real Zebra and Zaino on a private regtest chain, and
> against stand-ins for Apple's and Google's push services. They haven't
> been tried on mainnet or with real phones, no wallet ships Lantern Zero
> yet, and APIs and formats will change. Don't use it with real funds.

## What it does

Shielded Zcash wallets find their payments by scanning the chain, so a wallet
that has been closed for a while starts slow and can't alert you when you get
paid. Lantern Zero is a small server that wallets connect to through a URL. It
offers two modes:

- **Wake-ups (default).** The server sends the same contentless ping to every
  registered device every 30 minutes. The wallet wakes, scans the new blocks
  locally, and stays close to the chain tip. The server holds no keys and
  learns nothing about your payments.
- **Opt-in scanning.** If you choose, your wallet lends the server an incoming
  viewing key as a short, in-memory lease. The server then alerts you within
  seconds of a payment, including in the mempool, and tells your wallet where
  to scan first. The operator can see your incoming payments while the lease
  is active, so this mode is off unless you turn it on.

Wallets should keep their own background sync; wake-ups are one more wake
source on top of it. Whether they wake phones more reliably than the phone's
own scheduling is still being measured, and this page will say what we find.
Default mode also protects people who turn on scanning: because every user
gets the same pings and sends the same padded requests, nobody watching the
network can tell who has lent a key. Instant payment alerts are the one
exception (below).

Lantern Zero is a bridge until Zcash's Tachyon upgrade changes how wallets find
payments. The wake-up channel is designed to keep working after that.

## Who sees what

Wallets reach the server through [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458)
relays run by third parties, or, for a self-hosted server, over a Tor onion
service.

| Party | Sees | Doesn't see |
| --- | --- | --- |
| Relay | your IP address, which server you use, and when you send a request | anything inside it |
| Server | your requests, and with a scanning lease your incoming payments | your IP address |
| Push gateway, Apple, Google | which server pings your device, and when; with instant payment alerts, also when you got paid | what a push says |
| The server's chain source (Zebra and Zaino) | that the server reads every block and the mempool | which transactions matter to anyone |
| Your wallet's own light wallet server, as today | your IP address and which blocks your wallet downloads | which payments are yours |

- **Same on the wire.** Requests and responses have fixed sizes, and every
  wallet sends the same requests on the same schedule, so the relay can't
  tell default-mode users from scanning users.
- **Instant alerts.** Scanning mode's default alert is an extra push sent
  the moment you're paid. Push providers can see its timing, which suggests
  you lent a key and got paid then. The `private` alert mode avoids that by
  waiting for the next scheduled ping, up to about 35 minutes.
- **Limits.** This holds only while the relay and the server are run by
  different parties. It hides you among the server's other users, so it
  hides little on a server with few users. The spec lists these limits
  (§1.2).
- **Self-hosted wake-ups.** Wake-ups go through your wallet vendor's push
  gateway, so a self-hosted server can wake your phone only if that gateway
  accepts it. Without that, the wallet still gets live updates while it is
  open.

No public relay carries Lantern Zero traffic yet: the change that lets the
Payjoin project's relay forward it is under review
([payjoin/rust-payjoin#2026](https://github.com/payjoin/rust-payjoin/pull/2026)).
Self-hosted servers on Tor don't need one.

## Where to start

- **Running your own server:** the Docker Compose kit in
  [`deploy/`](deploy/README.md), or the [Claude skill](skill/README.md) that
  walks you through it.
- **Building a wallet integration:** the Rust [client core](client/README.md),
  which wallet SDKs compile into their own native library; the reference
  [push gateway](gateway/README.md); and the [protocol spec](spec/v0.md).
- **Merchant backends:** webhooks for payment notifications (spec §4.5).
  The client core sets one up, and `lz-proto` checks each delivery's
  signature.

A hosted service from Principle Zero Labs is planned for people who would
rather not run a server. Self-hosting stays a first-class path: everything a
server needs is in this repository.

## Repository layout

| Path | Contents |
| --- | --- |
| [`spec/`](spec/) | URL and API specification |
| [`server/`](server/) | Wake-ups, scanner, key leases, hint list, long-poll |
| [`gateway/`](gateway/) | Reference push gateway for wallet vendors |
| [`crates/lz-proto/`](crates/lz-proto/) | Shared protocol types, padding, tokens, and test vectors |
| [`client/`](client/) | Rust client core that wallet SDKs embed |
| [`deploy/`](deploy/) | Docker Compose kit for self-hosting |
| [`skill/`](skill/) | Claude skill that walks you through self-hosting |

## Contributing

Contributions are welcome. Lantern Zero handles data that can reveal people's
finances, so read [CONTRIBUTING.md](CONTRIBUTING.md) first: it lists the
privacy rules every change must keep, and the checks to run.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
