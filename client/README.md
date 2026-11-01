# client

Rust client core for wallets (`client/core`, crate `lz-client`).

**Status: prototype.** Tested against a stand-in OHTTP gateway and, end to
end, against the real server (`server/tests/end_to_end/client.rs`). Not yet
embedded in a wallet SDK.

It does no networking itself. Each call builds a request as bytes and
returns a pending value; the app sends the bytes with its own HTTP stack
(URLSession, OkHttp) and hands the response back:

```rust
let pending = client.wake(now_ms, lease)?;        // build
let (status, body) = app_send(pending.request()); // the app's networking
let outcome = client.finish_wake(pending, HttpResponse { status, retry_after: None, date: None, body: &body })?;
```

Wallet SDKs compile it into their existing native library and expose it
through their own FFI, so the app never links a second Rust library. It
pulls in no async runtime, no TLS stack, and no Zcash wallet crates, and it
builds on Rust 1.89, librustzcash's own minimum.

## What it covers

| Spec | |
| --- | --- |
| §3.1–3.3 | OHTTP encapsulation of Binary HTTP padded to 4096 bytes; responses that aren't exactly 4096 bytes are refused. `.onion` servers over Tor instead (`Transport::Onion`) |
| §3.2 | `KeyConfig::from_two_relays`: refuses configurations that differ between relays; `info` must name the same one (`Error::KeyConfigChanged`). After a rotation, `Error::KeyConfigRejected` (RFC 9458's `ohttp-key` problem) means fetch the configuration again, `set_key_config`, and build the request again; do the same after an `Error::Relay` if the configuration is more than an hour old |
| §3.4 | `Date` header and time-based `seq`, with `stale-seq` recovery: on `Error::StaleSeq`, build the request again and send it once more. A device clock more than 60 s off is corrected from the server's `bad-date` answer (`ClientState::clock_offset_ms`): on `Error::ClockCorrected`, do the same |
| §4.1 | Device registration and removal. Registration names the VAPID key `info` last reported (call `info` first); `Error::UnknownVapidKey` means read `info` again and resubscribe. When `info` reports a new key, register a subscription bound to it, then delete the old record with `unregister_device`. `Error::UnknownDevice` clears the device so the app registers again |
| §4.2 | `wake`, with or without a lease. Leases are checked first: no full viewing key without spend alerts |
| §4.3 | The long-poll: `poll` uses a 25 s `wait`, or `wait: 0` when the last response said more events are waiting |
| §4.4 | Acknowledgements ride on the next request and stay queued until one succeeds. Only `mined` events are acknowledged |
| §4.6 | `rotate_token` to a token the app generated and stored first; `finish_rotate` switches to it and returns the new connection URL. `delete_account` clears the client |
| §4.7 | `info`: network and version checks; reports when the server's VAPID key changed |
| §5 | `PushReceiver`: the device's RFC 8291 keys, and opening a fixed-size ping (checked against the RFC 8291 example) |

Events that every `wake` repeats are reported to the app once, and again
only when they change.

## What the app does

- Keep the connection URL (it holds the account token) and the
  `PushReceiver` secrets in the keychain, and persist `ClientState` (no
  secrets) after each call.
- Fetch the server's key configuration through two different relays, and
  send each request to one of the vendor's relays, rotating among them.
- Send exactly one `wake` per wake and long-poll while in the foreground,
  in both modes (spec §3.3).
- If the app forwards Rust `log` records (for example to logcat), cap the
  `ohttp` and `bhttp` targets at `warn`: at trace level `ohttp` logs
  derived key material and message bytes.
- Get the user's consent before the first lease (spec §6.3), and use hints
  only to reorder its normal sync.
- Show payment alerts and events as incoming and unconfirmed until the
  wallet's own sync finds the transaction in a block (spec §6.3).
- Subscribe at the vendor's push gateway with the server's
  `vapid_public_key`, renew before the subscription expires, and revoke it
  when the user removes the server. The reference gateway's wallet API is
  in [`gateway/README.md`](../gateway/README.md).

## Not yet

- Webhooks: the server doesn't have them yet either.
- An optional `reqwest` feature that sends requests itself, for merchant
  backends.
- Choosing relays. Relay addressing differs between relay software
  (spec §9).
