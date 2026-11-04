# lz-relay: an OHTTP relay for Lantern Zero

**Status: prototype.** It works end to end with the Lantern Zero server
and client, and its Compose example is tested in CI, but no wallet ships
a relay list yet. Design and rules: [`DESIGN.md`](DESIGN.md). Tracking
issue: [#9](https://github.com/principlezerolabs/lanternzero/issues/9).

Lantern Zero wallets send every request to their server through an
Oblivious HTTP relay (RFC 9458) run by someone else. The relay sees
which IP address a request comes from, but not what it says. The server
sees what the wallet says, but not who's saying it.
That split works only if the relay and the server are run by different
people. So relays need operators who run neither a Lantern Zero server
nor the wallet that lists the relay (spec §1.1): community
organizations, privacy groups, anyone willing to run a small service
honestly.

This page is for those operators.

## What running one means

- **What you see.** Client IP addresses, and the hostname of the
  Lantern Zero server each request is for. Request and response bodies
  are encrypted to the server, and are padded to fixed sizes. You can't
  read them, and you can't tell a wallet that lent a viewing key from
  one that didn't.
- **What you keep.** Nothing about clients. The relay writes no access
  log and no per-request lines, and keeps client addresses in memory only,
  for rate limits, and only for about a minute. It logs startup,
  errors that name no client, and hourly totals across all servers. The
  example's Caddy is set up to log nothing about requests either.
- **What you promise.** That you keep it that way. To be listed in
  [`spec/relays.md`](../spec/relays.md), you publish a contact and your
  log retention, and confirm you run no Lantern Zero server and no
  wallet that lists your relay.
- **Which servers it serves.** Only Lantern Zero servers. Before
  forwarding to a server for the first time, the relay asks it whether
  it accepts Lantern Zero traffic (the `allowed_purposes` opt-in, as
  payjoin-mailroom does), so it can't be pointed at anything else. You
  can also limit it to an allow list, or block servers with a deny list.
- **What it costs.** Very little. Requests are small (a few KB) and a
  wallet makes a few per wake-up, every 30 minutes or so. Any small VPS
  will do.

## Requirements

- A Linux machine with a public IPv4 address, and Docker with Compose
  v2.
- A DNS name for the relay, with an A record pointing at the machine.
  (IPv6: see below.)
- Ports 80 and 443 (TCP) and 443 (UDP, for HTTP/3) open to the
  internet. Caddy uses port 80 to get its certificate.

## Set up

```sh
git clone https://github.com/principlezerolabs/lanternzero
cd lanternzero/relay/deploy
cp .env.example .env          # set LZ_RELAY_DOMAIN
docker compose pull relay     # the release's signed image; to check it, see "The image"
docker compose up -d --no-build
```

Caddy gets a certificate for `LZ_RELAY_DOMAIN` within a minute or so.
Then check that it's up:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://relay.example.org/health   # 200
```

To check it against a Lantern Zero server, fetch that server's key
configuration through the relay. `lz.example.net` here stands for any
Lantern Zero server's host:

```sh
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' \
  https://relay.example.org/https://lz.example.net
# 200 application/ohttp-keys
```

A host that hasn't opted in to Lantern Zero traffic gets `403`; one the
relay can't reach gets `502`.

`docker compose logs relay` shows the relay's own lines: one at start,
then totals every hour.

## How wallets use it

Wallets address a server through the relay by putting the server's
origin in the path, the same URL shape as payjoin-mailroom:

- `POST https://<relay>/<server origin>` with
  `Content-Type: message/ohttp-req`: forwards an encrypted request to
  `<server origin>/.well-known/ohttp-gateway`.
- `GET https://<relay>/<server origin>`: the server's key configuration,
  cached by the relay for up to an hour so every client gets the same
  bytes (spec §3.2).

A bare host means `https`. Only the scheme, host, and port are allowed:
no path, query, or credentials.

## Configuration

`relay.toml`, next to `compose.yaml`. Its values suit most relays:

| Setting | In the example | What it does |
| --- | --- | --- |
| `limits.per_minute` | 60 | Requests per minute from one client (an IPv4 address, or an IPv6 /64). Over it, clients get `429` with `Retry-After`. |
| `limits.concurrent` | 10 | Requests in flight at once from one client. Long-polls are held up to 30 seconds. |
| `gateways.ports` | none | Ports other than 443 that servers may use. Some self-hosted servers use another port; add it if their operator asks. |
| `gateways.allow` | none | If set, only these server hosts (which must also opt in). |
| `gateways.deny` | none | Never these server hosts, nor any name under them (`example.org` also covers `api.example.org`). If you run a Lantern Zero server yourself, list it here. |
| `trusted_proxies` | Caddy's address | Whose `X-Forwarded-For` names the client. Change it only with the network (below). |

Restart after a change: `docker compose restart relay`, or
`docker compose restart caddy` after changing the `Caddyfile`.

The relay and Caddy talk over a private network, `172.30.250.0/28`,
where Caddy has the fixed address `172.30.250.2`. If that subnet clashes
with one you use, change it in `compose.yaml` (the subnet, `ip_range`,
and Caddy's `ipv4_address`) and `trusted_proxies` in `relay.toml`,
together.

### IPv6

Docker publishes ports to IPv6 clients through a proxy that hides their
address, so the relay would see them all as one client and rate-limit
them together. Either publish only an A record, or turn on IPv6 for the
Compose network (Docker's `enable_ipv6`, with an IPv6 subnet). Then
give Caddy a fixed IPv6 address too, and add it to `trusted_proxies`,
since Caddy may reach the relay over IPv6.

## Running it behind another proxy

If you already run nginx, HAProxy, or another proxy, you can skip Caddy
and run the relay image on its own. Your proxy must:

- **log nothing about requests:** turn off its access log for the relay,
  and keep its error log from recording client addresses or request
  paths (the path holds the server's hostname);
- **set `X-Forwarded-For`** to the client's address, replacing or
  appending to whatever the client sent, and be listed in the relay's
  `trusted_proxies`;
- **allow at least 60 seconds** for the relay's response (the relay
  gives a server 40 seconds to start answering, for long-polls), and
  stream responses without buffering;
- **add nothing** about the client to responses or to the request
  beyond `X-Forwarded-For`, which the relay reads and never forwards.

## The image

Each release from v0.1.2 on publishes
`ghcr.io/principlezerolabs/lantern-zero-relay` for amd64 and arm64,
signed in this repository's release workflow, and `compose.yaml` pins
the latest by digest, as the self-hosting kit does. To check the
signature, with cosign 3 or newer and the digest from `compose.yaml`:

```sh
cosign verify ghcr.io/principlezerolabs/lantern-zero-relay@sha256:<digest> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/principlezerolabs/lanternzero/\.github/workflows/images\.yml@refs/tags/v'
```

To build it yourself instead, set `LZ_RELAY_IMAGE=lantern-zero/relay:local`
in `.env`, then `docker compose build relay` and `docker compose up -d`.
`--no-build` in the steps above makes sure Compose never builds over the
pinned image.

The image is distroless and runs as a non-root user; the Compose
example adds a read-only file system and drops every Linux capability.
The relay turns core dumps off at start, because the rate-limit table
holds client addresses.

## Updating

```sh
git pull
docker compose pull relay
docker compose up -d --no-build
```

If you build the image yourself, run `docker compose build relay` and
`docker compose up -d` instead. Caddy's certificates are kept in the `caddy-data` volume across
updates. Don't remove it with `down -v`, or Caddy asks for new
certificates and may hit Let's Encrypt's rate limits.

## Getting listed

Open a pull request adding your relay to
[`spec/relays.md`](../spec/relays.md), with your public contact and your
log retention. Wallet vendors build their relay lists from it, and pick
relays by different operators so no single one sees all of a wallet's
traffic.

## Testing changes

`relay/deploy/smoke-test.sh` builds the image and runs the Compose
example against a fake server. It checks that held responses get through
Caddy, that servers see no client headers, that each client gets its own
rate limit and a forged `X-Forwarded-For` can't get around it, and that
neither log names a client. The crate's own tests: `cargo test -p lz-relay`.
