# client/uniffi

Swift and Kotlin bindings for the [client core](../README.md) (`lz-client`),
generated with [UniFFI](https://mozilla.github.io/uniffi-rs/), for apps
that have no Rust library of their own: native apps, and React Native or
other cross-platform apps through a native module over these.

**Status: prototype.** Tested in Rust against a stand-in OHTTP gateway
(`tests/bindings.rs`). CI generates the Swift and Kotlin and compiles
both (`check-bindings.sh`: Kotlin against JNA, Swift against the
generated header), and the Swift runs against the static library on
macOS. Not yet built for iOS or Android targets in CI.

**Wallet SDKs don't need this.** If the app already ships a Rust library
(as ZODL's SDKs do), compile `lz-client` into it and expose it through
that library's own FFI. Two Rust static libraries in one app risk
duplicate symbols.

## What it exposes

The phone side of the protocol, as in `lz-client`: build a request, send
it with the app's own HTTP stack (URLSession, OkHttp), and pass the
response to the matching `finish_*` call.

| | |
| --- | --- |
| `Client` | `new_ohttp` / `new_onion`; `info`, `register`, `unregister`, `unregister_device`, `wake`, `poll`, `rotate_token`, `delete_account`, each with its `finish_*`; `check_key_config`, `ack`, `state` (JSON to persist), `connection`, `device_id` |
| `Pending` | `request()` to send (a fresh copy each call); `new_connection_url()` for a rotation. A wrong `finish_*` call leaves it untouched |
| `PushReceiver` | `generate`, `from_bytes`, `push_keys`, `open_ping`, `open_ping_b64` (the gateway's `lz` field) |
| Functions | `parse_connection_url`, `connection_url`, `generate_account_token` (in-app sign-up, spec §2.3), `classify_viewing_key`, `long_poll_wait_secs` |
| `LzError` | One variant per `lz_client::Error`, plus key-configuration, push, URL, and state errors |

Webhooks and clients without a device are for merchant backends, which
use `lz-client` from Rust, so they are left out.

## Rules for the app

The spec's obligations still apply (§3.3, §5.2, §6.3); these are the ones
the binding layer can't enforce:

- **Secrets stay native.** The connection URL (it holds the token),
  viewing keys, and the `PushReceiver` secrets cross into Swift or Kotlin
  as strings and bytes, which those languages can't wipe. Keep them in the
  keychain and in native code. A React Native module MUST NOT pass them
  into JavaScript, where debuggers, error reporters, and logs can see
  them: JavaScript gets events and outcomes, never keys or the token.
- **Never log requests or responses.** Over Tor the headers carry the
  token and bodies may carry viewing keys.
- **One `wake` per scheduled ping, nothing after a payment push**, to any
  service (spec §3.3). Show the alert from the ping itself.
- **Alerts are claims** (spec §6.3). An app that is not a wallet can never
  confirm a payment: show every event as unconfirmed.
- **Persist `state()` after every call.**
- **Pings in the notification extension.** On iOS, open payment pushes in
  a Notification Service Extension with `PushReceiver::from_bytes`, using
  secrets from a keychain access group shared with the app.

## Generate the bindings

```sh
cargo build -p lz-client-uniffi --release
cargo run -p lz-client-uniffi --features bindgen --bin uniffi-bindgen -- \
  generate --library target/release/liblz_client_uniffi.dylib \
  --language swift --language kotlin --out-dir out/
```

Generate from a host build (`.dylib` on macOS, `.so` on Linux). The
sources are the same for every target. Then build the static library for
each app target (`aarch64-apple-ios`, `aarch64-apple-ios-sim`,
`aarch64-linux-android`, and so on). For iOS, package it as an
XCFramework with the generated header and module map. For Android, build
`cdylib`s with the NDK for JNA.

**An app with other Rust code too** (note decryption, a PIR client) makes
its own crate that depends on this one and on those, builds one library
from it, and runs `generate --library` on that library: UniFFI's library
mode generates bindings for every crate in it. The app still links one
Rust library.

On Android, `cargo-ndk` copies every shared library the build produced
into `jniLibs`. This crate is also a `cdylib` (for apps that use it on
its own), so next to the app's library you get a
`liblz_client_uniffi-<hash>.so`. Nothing loads it, since the app's
library already contains the crate, so delete it from `jniLibs` after
the build rather than shipping a second Rust library.

To check that the bindings still compile after changing the exported
API, run `client/uniffi/check-bindings.sh` (needs a JDK; downloads a
pinned Kotlin compiler and JNA). Some names break only one language: a
field named `message` or `cause` clashes with Kotlin's `Throwable`
(issue #14).

## Versioning

The bindings track `lz-client` and the protocol version. v0 has no
compatibility promises (spec §7), so pin a commit until there is a tagged
release, and regenerate the bindings whenever you move the pin.

## License

UniFFI is MPL-2.0. Its license is copyleft per file: apps may link it
into closed code, but changes to UniFFI's own files must be shared.
`deny.toml` allows MPL-2.0 for the UniFFI crates only.
