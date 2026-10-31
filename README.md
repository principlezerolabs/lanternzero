# Lantern Zero

Faster sync and payment notifications for Zcash wallets, without handing your
keys to anyone by default.

> **Status: pre-alpha.** Nothing here is ready to run yet. The design is settled
> enough to start building; APIs and formats will change.

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

All client requests travel over [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458)
through an independent relay, so the server never sees your IP address.

Lantern Zero is a bridge until Zcash's Tachyon upgrade changes how wallets find
payments. The wake-up channel is designed to keep working after that.

## Run your own, or use ours

Everything needed to run a server lives in this repository, and self-hosting is
a first-class path. A hosted service from Principle Zero Labs is planned for
people who would rather not run one.

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
