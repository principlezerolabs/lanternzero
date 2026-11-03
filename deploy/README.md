# deploy

Docker Compose kit for self-hosting: the Lantern Zero server and a Tor onion
service, plus Zebra and Zaino if you don't already run a node.

[`regtest/`](regtest/README.md) holds a private Zebra and Zaino regtest
chain for the server's integration tests.

**Status: prototype.** The `byo-node` profile works end to end on regtest
(`smoke-test.sh`, run by CI). Releases will publish signed images (below);
none is published yet, so for now you build them here. Not yet: mainnet
testing, and an OHTTP setup in the kit. The plan is
in [`DESIGN.md`](DESIGN.md).

## What runs

| Service | Profile | What it does |
| --- | --- | --- |
| `server` | always | The Lantern Zero server, hardened for spec §6.2 (below) |
| `tor` | always | The onion service wallets reach the server through (spec §3.1); built here from Debian's `tor` package |
| `init` | `tools` (run by hand) | `lz-server init`: writes the config, keys, and first account |
| `zebra`, `zaino` | `full` | A Zcash node and its lightwalletd API, for a box with about 500 GB free |

With no profile you get **`byo-node`**: point `LZ_LIGHTWALLETD` at the
Zaino or lightwalletd you already run. That's the better choice for anyone
with a node, because a mainnet sync takes days.

> **Zaino and NU7.** Zaino's released images (0.10.x) stop indexing at NU7,
> mainnet height 3,543,405, around 5 Nov 2026 (zingolabs/zaino#1731). Until
> a release with the fix ships, use the fallback below, for `full` and for
> your own Zaino alike. `full` also hasn't been tried on mainnet yet.

### The NU7 fallback

[`zaino/Dockerfile`](zaino/Dockerfile) builds Zaino from one pinned commit
of its fix (zingolabs/zaino#1655, not yet merged), with pinned base images
and packages. CI runs the regtest suite against it on a normal chain and
across NU7 (`.github/workflows/zaino-fallback.yml`). Build it on this
machine; it isn't published, and it compiles Zaino from source, so it
takes a while:

```sh
docker build -t lantern-zero/zainod:nu7 zaino
```

- **`full`:** set `LZ_ZAINO_IMAGE=lantern-zero/zainod:nu7` in `.env`, and
  `LZ_ZAINO_PLATFORM` to this machine's platform (`linux/amd64` or
  `linux/arm64`; the image is built natively, so no emulation). Then
  `docker compose up -d`. Zaino may rebuild its index; Zebra's synced
  chain is kept.
- **Your own Zaino (`byo-node`):** run this image in place of yours with
  your own config, or build the same commit from source. The server needs
  no change.

Once Zaino ships a fixed release, the kit pins it and this fallback goes
away.

## Set up

```sh
cd deploy
cp .env.example .env              # set LZ_VAPID_CONTACT, and LZ_LIGHTWALLETD or COMPOSE_PROFILES=full
docker compose build              # the server and Tor images
docker compose run --rm init      # starts Tor, then prints your connection URL once
docker compose up -d
```

Paste the connection URL into your wallet the way you would a custom
lightwalletd server. It holds your account token, so treat it like a
password. `init` refuses to run twice; for more accounts:

```sh
docker compose exec server lz-server /var/lib/lantern-zero/config.toml new-account
docker compose restart server
```

To point the server at another node, or another network, later (`.env`
is read only by `init`):

```sh
docker compose exec server lz-server /var/lib/lantern-zero/config.toml \
  set-chain --lightwalletd http://host.docker.internal:8137
docker compose restart server
```

Add `--network main` (or `test`, `regtest`) to change the network too. It
checks the new node first and changes nothing if that fails.

`init` takes its options from `.env`. To pass others (`lz-server
<config> init` with no options prints them all), give them after `init`:

```sh
docker compose run --rm init --network test --onion-hostname-file /tor/lz/hostname \
  --lightwalletd http://host.docker.internal:9067 --vapid-contact mailto:you@example.org \
  --listen 0.0.0.0:8080
```

## Published images

Each tagged release publishes both images for amd64 and arm64 to GitHub's
container registry, signed with [cosign](https://docs.sigstore.dev/)
(keyless, by the release workflow `.github/workflows/images.yml`) and with
an SBOM and build provenance attached. The workflow's run summary lists
each image's digest; release notes will too.

To use them instead of building:

1. Verify each digest was signed by a tagged release of this repository:

   ```sh
   cosign verify ghcr.io/principlezerolabs/lantern-zero-server@sha256:<digest> \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-identity-regexp '^https://github\.com/principlezerolabs/lanternzero/\.github/workflows/images\.yml@refs/tags/v'
   ```

   Do the same for `lantern-zero-tor`.
2. Set `LZ_SERVER_IMAGE` and `LZ_TOR_IMAGE` in `.env` to the full
   `…@sha256:<digest>` references. Never use a tag: digests can't change.
3. Run `docker compose pull server tor` instead of `docker compose build`,
   and `docker compose up -d --no-build` instead of `docker compose up -d`.

To see what an image contains:

```sh
docker buildx imagetools inspect ghcr.io/principlezerolabs/lantern-zero-server@sha256:<digest> \
  --format '{{ json .SBOM }}'
```

## Check it

```sh
docker compose exec server lz-server /var/lib/lantern-zero/config.toml doctor
```

It prints pass, warn, or fail for the data directory, core dumps, memory
and swap, the OHTTP key's age (not used by onion services), and the chain
source. The output has no tokens, keys, URLs, or
onion names, so it's safe to paste into an issue.

## Hardening (spec §6.2)

| Rule | How the kit does it |
| --- | --- |
| No core dumps | `ulimits: core: 0`; the server also turns them off itself |
| No swap | `memlock` unlimited, so the server locks its memory; and `memswap_limit` equal to `mem_limit` (`LZ_SERVER_MEMORY`) |
| Nothing written outside the data dir | `read_only: true`, `tmpfs` for `/tmp`; data in the `lz-data` volume (mode 0700) |
| Least privilege | non-root (uid 65532), `cap_drop: [ALL]`, `no-new-privileges`; the server image is distroless, with no shell |
| Logs | stdout only, capped at 3 × 10 MB |
| Chain data | Zaino sits only on the internal `chain` network, which has no route out. Zebra's RPC has no auth and is reachable from the kit's containers only; no port is published to the host |

The `init` container mounts Tor's data volume read-only to read the onion
hostname; the server never does. `init` runs as the same uid as Tor for
that reason, and has no network.

## Files

| Path | |
| --- | --- |
| `compose.yaml` | The kit |
| `.env.example` | Options; copy to `.env` (git ignores it). No secrets |
| `server.Dockerfile` | Server image, built from the repository root |
| `tor/` | Tor image and `torrc`; the `tor` package is pinned to a version in a fixed Debian snapshot |
| `zebra/`, `zaino/` | Node configs for `full`; `zaino/Dockerfile` builds the NU7 fallback |
| `smoke-test.sh` | `byo-node` end to end against `regtest/`: `init`, hardening, `doctor` |
