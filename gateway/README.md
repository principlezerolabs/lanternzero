# gateway

Reference push gateway for wallet vendors (spec §4.1, §5.3, §5.4). The
vendor runs it with its APNs and FCM credentials. Lantern Zero servers push
to it with standard Web Push (RFC 8030, VAPID RFC 8292, RFC 8291 payloads),
and it forwards each push to Apple or Google.

**Status: prototype.** Tested against fake APNs and FCM endpoints and against
the real server's wake round; not yet against Apple or Google.

## How it works

- **Stateless.** A subscription is sealed into its own endpoint URL:
  the device token, the platform, and the bound server key, encrypted and
  authenticated with the gateway's key (XChaCha20-Poly1305). The gateway
  stores only that key (`data_dir/endpoint-key`, mode 0600). Servers never
  see raw device tokens.
- **Bound to one server** (spec §5.3, decided in issue #6). A push is
  accepted only if its VAPID `k=` is the key the subscription was created
  with, and the JWT is a valid ES256 signature by that key, addressed to
  this gateway (`aud`), and current (`exp` at most 24 h ahead). There is no
  admission list, so self-hosted servers work like any other.
- **Rate-limited** per device and server, with separate hourly budgets for
  background wakes (`Urgency` other than `high`) and payment alerts
  (`Urgency: high`), and per server key per minute. Over budget gets `429`
  with `Retry-After`. Budgets are fixed hourly windows, so a server can
  briefly send up to twice its budget across a window boundary. A wallet
  with two servers gets two budgets; Apple may then throttle some wakes,
  which wallets must tolerate anyway (spec §5.4).
- **Blind.** Only `aes128gcm` bodies are accepted, and they are forwarded
  unchanged, base64url in the `lz` field. Payment alerts show a fixed,
  generic title (`alert_title`); the app's Notification Service Extension
  decrypts the real content. Nothing logs device tokens, endpoints, or
  payloads; HTTP library logs are capped at `warn` (a test checks this at
  trace level).

## Wallet API

Not part of the Lantern Zero spec: each vendor's app talks to its own
gateway. The reference one takes:

```
POST /v0/subscriptions
{ "platform": "apns" | "fcm",
  "token": "<APNs device token, hex | FCM registration token>",
  "server_key": "<vapid_public_key from the server's info, base64url>" }
→ 201 { "endpoint": "https://<public_origin>/wp/<opaque>" }
```

The wallet then registers that endpoint with the server (`POST /v0/devices`).
A wallet connected to two servers subscribes twice.

## Push API (servers)

`POST /wp/<opaque>`, a standard Web Push request:

| Answer | When |
| --- | --- |
| `201` | Forwarded |
| `400` | Missing `TTL`, body not `aes128gcm`, bad `Urgency` or `Topic` |
| `401` / `403` | Bad VAPID / signed by a key the subscription isn't bound to |
| `404` | Endpoint not sealed by this gateway |
| `410` | Apple or Google says the token is gone (the server drops the device) |
| `413` | Body over 4096 bytes |
| `429` | Over a rate limit, or the platform asked us to slow down |
| `502` | The platform failed |

## Platform mapping (spec §5.4)

| | Background wake | Payment alert |
| --- | --- | --- |
| APNs | `apns-push-type: background`, priority 5, `content-available: 1`, `apns-collapse-id` from `Topic` | `apns-push-type: alert`, priority 10, generic title, `mutable-content: 1` |
| FCM | data message, `priority: normal`, `collapse_key` from `Topic` | data message, `priority: high` |

APNs uses token (JWT) authentication from the `.p8` key, refreshed every 40
minutes. FCM uses a service account (`gcp_auth`).

## Run

```sh
cargo run -p lz-gateway -- gateway/examples/config.toml
```

## Not yet

- **Revocation.** Spec §4.1 says a wallet SHOULD ask its gateway to revoke a
  subscription when the user removes a server. A stateless gateway can't
  forget an endpoint it never stored; options are a small revocation list,
  or endpoints that expire (each sealed endpoint already records when it
  was created). To decide.
- **Sealing-key rotation.** Rotating `endpoint-key` invalidates every
  endpoint at once; a second, older key for opening would allow a
  changeover.
- **Tests against real APNs and FCM**, which need the vendor's credentials
  and a device.
