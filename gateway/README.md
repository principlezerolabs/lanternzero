# gateway

Reference push gateway for wallet vendors (spec §4.1, §5.3, §5.4). The
vendor runs it with its APNs and FCM credentials. Lantern Zero servers push
to it with standard Web Push (RFC 8030, VAPID RFC 8292, RFC 8291 payloads),
and it forwards each push to Apple or Google.

**Status: prototype.** Tested against fake APNs and FCM endpoints and against
the real server's wake round; not yet against Apple or Google.

## How it works

- **No device records.** A subscription is sealed into its own endpoint
  URL: the device token, the platform, the bound server key, the expiry,
  and the hash of a revocation secret, encrypted and authenticated with the
  gateway's sealing key (XChaCha20-Poly1305). Servers never see raw device
  tokens. On disk, mode 0600, there are only:
  - `endpoint-keys`: the current sealing key, and retired keys that still
    open the endpoints they sealed;
  - `revoked`: a 40-byte record per revoked subscription (the hash and the
    expiry), dropped once that subscription would have expired anyway.
- **Expiring.** Subscriptions last `endpoint_lifetime_days` (default 90,
  at most 365). Pushes after that get `410`, so the server drops the
  device; wallets renew before then (spec §4.1).
- **Revocable.** When the user removes a server, the wallet revokes the
  subscription with the secret it got when subscribing. Every later push
  gets `410`, so that server can't keep waking the device or showing it
  alerts. The server holds only the endpoint, so it can't revoke.
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
  which wallets must tolerate anyway (spec §5.4). The wallet API is also
  limited per client address (an IPv4 address or an IPv6 /64): 60
  subscriptions and 60 revocations an hour by default. The counters hold
  salted hashes of addresses, in memory only, and are never logged.
  Behind a proxy, list it in `trusted_proxies` so its `X-Forwarded-For`
  names the client; from anyone else that header is ignored.
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
{ "platform": "apns" | "apns-sandbox" | "fcm",
  "token": "<APNs device token, hex | FCM registration token>",
  "server_key": "<vapid_public_key from the server's info, base64url>" }
→ 201 { "endpoint": "https://<public_origin>/wp/<opaque>",
        "expires": <unix seconds>,
        "revoke_secret": "<base64url>" }

DELETE /v0/subscriptions/<opaque>
Authorization: Bearer <revoke_secret>
→ 204 (also when already revoked or expired)
  401 no secret · 403 wrong secret · 404 not this gateway's endpoint
  503 revocation list full, try later
```

Both answer `429` with `Retry-After` past the per-address limits.

`apns-sandbox` is for development builds (Xcode), whose device tokens
work only in Apple's development environment. The gateway accepts it
when `[apns] allow_sandbox = true`, and sends those pushes there with the
same auth key; `apns` goes to the environment `sandbox` picks
(production by default). So one gateway serves development, TestFlight
and App Store builds. The app knows which it is from its
`aps-environment` entitlement. Turning `allow_sandbox` off later makes
existing `apns-sandbox` endpoints answer `410`.

The wallet registers the endpoint with the server (`POST /v0/devices`) and
keeps `revoke_secret` on the device; the server never sees it. A wallet
connected to two servers subscribes twice. Before `expires`, the wallet
subscribes again, registers the new endpoint, deletes the old device record,
and revokes the old subscription.

## Push API (servers)

`POST /wp/<opaque>`, a standard Web Push request:

| Answer | When |
| --- | --- |
| `201` | Forwarded |
| `400` | Missing `TTL`, body not `aes128gcm`, bad `Urgency` or `Topic` |
| `401` / `403` | Bad VAPID / signed by a key the subscription isn't bound to |
| `404` | Endpoint not sealed by a key this gateway holds |
| `410` | Subscription expired or revoked, or Apple or Google says the token is gone (the server drops the device) |
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

Releases publish a signed image, `ghcr.io/principlezerolabs/lantern-zero-gateway`
(linux/amd64 and linux/arm64; `RELEASING.md` says how to verify one). It
runs as uid 65532 with config at `/etc/lz-gateway/config.toml`:

```sh
docker run --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -v /srv/gateway/config.toml:/etc/lz-gateway/config.toml:ro \
  -v /srv/gateway/secrets:/etc/lz-gateway/secrets:ro \
  -v lz-gateway-data:/var/lib/lz-gateway \
  ghcr.io/principlezerolabs/lantern-zero-gateway@sha256:<digest>
```

with `listen = "0.0.0.0:8090"`, `data_dir = "/var/lib/lz-gateway"` and
the credential paths under `/etc/lz-gateway/secrets/`, readable by uid
65532. A named volume gets the right owner and mode by itself; a host
directory must be owned by 65532, mode 0700. Back it up: it holds the
sealing keys. Put TLS, and a per-address limit on `/v0/subscriptions`
(see "Not yet"), in front. `gateway/smoke-test.sh` builds the image and
checks it this way (CI runs it).

### Rotating the sealing key

```sh
lz-gateway rotate-key <config.toml>              # routine
lz-gateway rotate-key <config.toml> --drop-old   # suspected leak
```

Then restart the gateway. After a routine rotation, new endpoints use the
new key; the old key keeps opening the endpoints it sealed for 365 days
(the longest lifetime), by which time they have all expired, and is then
dropped. With `--drop-old`, every existing endpoint stops working at once
(`404`): servers drop the devices, and wallets find out at their next wake
(`unknown-device`) and subscribe again. Use it when a key may have leaked,
because a leaked key can forge endpoints.

Losing `data_dir` has the same effect as `--drop-old`, and also forgets
revocations.

## Not yet

- **Abuse of the open wallet API.** Anyone can subscribe and then revoke,
  so the revocation list could be filled; past 1,000,000 entries,
  revocations get `503` until old ones expire. The per-address limits
  make that slow (at 60 an hour, about 17,000 address-hours), not
  impossible for someone with many addresses. App attestation (App
  Attest, Play Integrity) would close it properly.
- **Several gateway instances.** Rate limits live in memory per instance,
  and the revocation list is a local file. Run one instance, or share the
  list.
- **Tests against real APNs and FCM**, which need the vendor's credentials
  and a device.
