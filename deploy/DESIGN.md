# Self-host packaging: design note

**Status:** proposal (2026-10-31). Layer 1 is a prototype (2026-11-01):
`lz-server init` and `doctor`, and the Compose kit with both profiles and
the §6.2 hardening, tested on regtest by `smoke-test.sh`. Not built yet:
signed, published images, a `doctor` check of the onion name itself (it
checks the address Tor forwards to), and layers 3 and 4.

Packaging is not the hard part of self-hosting Lantern Zero. Two other
things are:

1. **The node.** Zebra needs about 300 GB and days to sync mainnet. No
   installer makes that fast. The biggest shortcut is reusing a node the
   person already runs.
2. **Push admission.** A self-hosted server can wake a phone only if the
   wallet vendor's push gateway accepts its pings. Decided in
   [issue #6](https://github.com/principlezerolabs/lanternzero/issues/6)
   (spec rev 3.8, §5.3): gateways bind each subscription to the VAPID key
   of the server the user chose and must not refuse unknown servers, so a
   self-hosted server is treated like any other. This depends on wallet
   vendors' gateways following §5.3; until they do, a self-hosted server
   still gives long-poll and webhooks.

So the packaging stays thin, and the effort goes into the node, and into
getting gateways to follow §5.3.

## Layers, in build order

### 1. Compose kit, plus `init` and `doctor`

The Compose kit in this folder is the only installer. The server binary gets
two more subcommands next to `new-account`:

- **`lz-server init`** writes `config.toml` and the data directory
  (`0700`). It generates the server's own keys (OHTTP key, VAPID key, event-id
  secret),
  reads the onion hostname from the Tor container, and prints the
  connection URL once, the same way `new-account` does. It writes no
  secrets into Compose files. `.env` holds paths and options only.
- **`lz-server doctor`** checks a running install and prints pass, warn,
  or fail for each check. Its output contains no tokens, keys, URLs, or
  onion names, so it is safe to paste into an issue or give to the Claude
  skill. Checks:
  - the chain source's network matches the config (the chain follower
    also refuses a mismatch, but only logs it);
  - the chain tip is current, plus Zebra's sync progress when the kit runs
    Zebra;
  - core dumps are off (`RLIMIT_CORE`);
  - memory can be locked (`RLIMIT_MEMLOCK` unlimited), or swap is off for
    the container (`memory.swap.max`), or the host's swap is encrypted;
  - data directory permissions;
  - the onion service or the OHTTP gateway answers `/.well-known/ohttp-gateway`;
  - the clock is within the 60 s replay window (spec §3.4).

The skill (`skill/`) runs `doctor` and explains its results. It never edits
configuration by hand.

**Profiles:**

| Profile | Runs | For |
| --- | --- | --- |
| `full` | Zebra, Zaino, server, Tor | A new box with about 500 GB free |
| `byo-node` | server, Tor | Someone who already runs Zebra/Zaino or lightwalletd; set `[chain]` to point at it |

`byo-node` should be the documented default for anyone who already has a
node. A chain source run by a third party works too. It cannot learn which
payments matter, because the server reads blocks in bulk only (spec §6.1),
but it could hide blocks and cause missed alerts.

**Transport:** self-hosted servers default to a Tor onion service (spec
§3.1), so no OHTTP relay is needed. OHTTP stays available as an option.

### 2. Hardening that enforces invariant 1

The server protects itself at start (`server/src/hardening.rs`, through
`rustix`, so still no `unsafe` of our own). It turns off its core dumps,
locks its memory when the memlock limit is unlimited, and with `[chain]`
refuses to start if swap could hold its memory. The decoded Sapling and
Orchard key types from the Zcash crates don't zero themselves on drop,
which is one more reason swap must not hold them. The kit sets the
limits that let those protections hold, and `doctor` checks them:

| Spec §6.2 rule | Compose setting |
| --- | --- |
| No core dumps | `ulimits: { core: 0 }` (the server also sets this itself) |
| No swap | `ulimits: { memlock: -1 }` so the server locks its memory; or `memswap_limit` equal to `mem_limit` (cgroup v2); or the host's swap encrypted, with `hardening.allow_swap` |
| Nothing written outside the data dir | `read_only: true`, with `tmpfs` for `/tmp` |
| Least privilege | non-root user, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]` |
| Logs | stdout only, with size-capped rotation; the server already never logs tokens, endpoints, or bodies |

This is a reason to ship a packaged setup at all: a hand-rolled install is
more likely to leave swap or core dumps on.

### 3. Home-node app stores

Self-hosting Zcash users mostly run home-node boxes. Those platforms already
handle updates, Tor, and backups.

- **StartOS first.** A community package, `bitcoinismoral/zebrad-startos`
  (Zebra plus lightwalletd), exists as of 2026-10-31. A Lantern Zero
  package could depend on it, which is the `byo-node` profile in package
  form. Check its maintenance and its lightwalletd version before
  depending on it.
- **Umbrel later.** No Zcash app was found in `getumbrel/umbrel-apps` on
  2026-10-31, so an Umbrel package would have to ship Zebra too, or wait
  for someone else to.

### 4. Cloud images: deferred, maybe never

An AMI or a DigitalOcean 1-click image is not planned:

- A cloud VM big enough for a full node is expensive to keep running, for
  little gain over the hosted service.
- The viewing keys end up on someone else's hardware anyway, which undercuts
  the reason to self-host.
- Each image is one more release artifact to sign and patch.

A short "Compose on any VPS" page covers this case.

## Releases

- Container images are signed (cosign) and published with an SBOM. The kit
  pins images by digest, never `latest`.
- Updates are opt-in: the scanner holds viewing keys, so nothing
  auto-updates. Release notes say whether a release touches key handling.
- `curl | sh` is never the only install path. If a script exists, it only
  downloads the signed release, verifies it, and runs `init`.
- Once reproducible builds exist (planned for the enclave), the same images
  serve self-hosters, so anyone can check them against the source.

## Not decided

- Whether the `full` profile uses Zaino or lightwalletd, pending the Zaino
  disk measurements (phase 1, item 4). The prototype uses Zaino, as the
  rest of the repo does.
- Which Tor image to use, and who maintains it. The prototype builds its
  own (`tor/Dockerfile`: Debian's `tor` package, non-root), so the kit
  trusts no third-party image; we would maintain it. Its package version
  isn't pinned yet.
- Minimum host size for `full`, pending the same measurements.
