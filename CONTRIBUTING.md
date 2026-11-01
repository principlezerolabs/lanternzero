# Contributing to Lantern Zero

Thanks for helping. Lantern Zero handles data that can reveal people's
finances, so a few rules here are stricter than in most projects. Please read
this page before opening a pull request.

- **Security issues:** don't open a public issue or pull request. Follow
  [SECURITY.md](SECURITY.md).
- **License:** contributions are dual-licensed MIT OR Apache-2.0, as described
  in the [README](README.md#license).

## Before you start

- **Spec first.** The protocol lives in [`spec/v0.md`](spec/v0.md). A change
  to the wire format, the API, or a privacy property starts as a change to the
  spec, in the same pull request as the code or before it.
- **Propose big changes.** Open an issue before adding a crate, a new
  endpoint, or a new dependency that client-side crates would pull in.
- **Public repo.** Never commit secrets, real viewing keys, real account
  tokens, or anything about a specific deployment.

## Privacy invariants

These are requirements, not goals. A change that breaks one is a bug, even if
every test passes.

1. Viewing keys live **only in scanner memory**: never on disk, in logs, in
   crash dumps, in backups, or in metrics. A server restart drops them; apps
   re-send keys at their next wake.
2. A key is a **lease**, 24 h to 7 days, renewed by the app on each wake. It
   is dropped at once on opt-out, when the lease expires, or when the paid
   period ends.
3. Data derived from a key (matched payments) is deleted when the app
   acknowledges it, or after 7 days at most. Keep no per-key history.
4. **Default-mode and scanning-mode users must look identical on the wire.**
   Every request goes over OHTTP, requests and responses have fixed sizes,
   and everyone gets the same scheduled pings.
5. Push payloads never carry amounts, memos, or txids in the clear. Anything
   the device must see is RFC 8291-encrypted to it.
6. Account tokens are bearer secrets. Never log them or put them where relays
   can see them; they travel inside the OHTTP-encrypted request.
7. Never make per-transaction lookups (for example `GetTransaction`) that
   reveal which transactions matter to a user.

## Code rules

### Secrets

- **Types.** Hold tokens, viewing keys, and other secrets in dedicated types,
  such as `AccountToken` and `ViewingKey` in `lz-proto`. Those types must:
  - implement `Debug` by hand to print `<redacted>`, never the value;
  - not implement `Display`;
  - zero their memory on drop (`zeroize`).
- **Printing.** Never put a secret in a log line, error message, panic
  message, metric label, or trace span field. That includes hashes of
  tokens.
- **Copies.** Parse secrets straight into those types. Don't keep extra
  `String` or `Vec<u8>` copies.
- **Comparing.** Compare token hashes in constant time (`TokenHash::ct_eq`).
- **Crash dumps and swap.** Server processes that hold keys follow spec
  §6.2: locked memory, no core dumps.

### Wire behavior

- **Uniform requests (invariant 4).** A wallet in scanning mode must not make
  a request that a default-mode wallet wouldn't make, at a different time, or
  of a different size. If a feature needs a new request, both modes send it.
- **Padding.** Pad with the constants in `lz_proto::padding`. Never hand-pick
  a size.
- **Replay protection.** Every authenticated request carries a `seq` checked
  by `lz_proto::replay::SeqWindow`.

### General

- **No `unsafe`.** It is forbidden workspace-wide. If you believe you need
  it, open an issue first.
- **No logging of request bodies**, at any level, in any crate.
- **Errors.** Return errors; don't `unwrap` or `expect` on data from the
  network. Errors sent to clients use RFC 9457 problem details and say
  nothing about other accounts.

### Client-side crates

`lz-proto` and the client core are compiled into wallet SDKs, next to the
SDK's own pinned Zcash crates. So they:

- do no I/O of their own; the host app sends the bytes;
- must not depend on tokio, any TLS stack, or Zcash wallet crates
  (`zcash_client_backend`, `zcash_client_sqlite`);
- must build on Rust **1.86**.

CI checks the dependency and Rust version rules; reviewers check the first.

## Tests

- **Invariant tests.** Code that touches keys or tokens needs tests showing
  that invariants 1–6 hold for it: secrets are redacted from debug output,
  nothing persists, leases expire, sizes are fixed.
- **Test vectors.** If you change something with a vector in
  [`spec/vectors/v0.json`](spec/vectors/v0.json), regenerate it with
  `LZ_REGEN_VECTORS=1 cargo test -p lz-proto --test vectors` and explain why
  in the pull request.
- **Fake keys only.** Use obviously fake keys and tokens in tests (for
  example, fixed byte patterns). Never use a key that ever held funds.

## Dependencies

Every new dependency is code that runs inside people's wallets. Before adding
one:

- **Need it.** Check whether the standard library or an existing dependency
  already covers it.
- **Maintained.** Prefer widely used crates with recent releases. For
  cryptography, use crates from RustCrypto or the Zcash ecosystem; don't
  write your own.
- **Match librustzcash.** In client-side crates, use the same major
  versions of shared crates (`sha2`, `hmac`, `base64`, `getrandom`, and so
  on) as the librustzcash release wallets ship. A newer one puts a second
  copy into every wallet app. Bump them when librustzcash does, or sooner
  only for a security fix.
- **Allowed.** `cargo deny check` must pass. [`deny.toml`](deny.toml) lists
  the allowed licenses and banned crates.

## Before you open a pull request

Fmt and clippy use the pinned toolchain in [`rust-toolchain.toml`](rust-toolchain.toml).
MSRV checks override it with `cargo +1.86` and `cargo +1.89`.

```sh
scripts/check.sh                # fmt, clippy, privacy guards, typos; deny/machete if installed
cargo +stable test --workspace  # CI stable matrix leg (+stable, not the fmt/clippy pin)
cargo +1.86 test -p lz-proto      # client-side crates' minimum Rust
cargo +1.89 test -p lz-server -p lz-gateway   # server and gateway minimum Rust
cargo deny check                  # required; also run by scripts/check.sh when cargo-deny is installed
```

Optional binaries for a full local match to CI lint:
[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny),
[`cargo-machete`](https://github.com/bnjbvr/cargo-machete),
[`typos`](https://github.com/crate-ci/typos) (`cargo install typos-cli --locked`).

If you change the chain follower, scanner, or mempool code, also run the
regtest tests against real Zebra and Zaino (needs Docker; CI runs them too):

```sh
docker compose -f deploy/regtest/compose.yaml up -d --wait
cargo test -p lz-server --test regtest -- --ignored --test-threads 1
docker compose -f deploy/regtest/compose.yaml down
```

Keep pull requests focused, and fill in the checklist in the template.
