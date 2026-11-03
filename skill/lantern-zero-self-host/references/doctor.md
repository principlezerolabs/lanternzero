# `doctor`'s checks

`lz-server <config> doctor` prints one line per check: `pass`, `warn`, or
`FAIL`, a name, and a detail. It exits non-zero if anything failed. Its
output never contains tokens, keys, URLs, or onion names, so the user can
paste it into an issue.

Explain each line in plain words, then give the fix below. Don't apply a
fix that edits files other than `.env` (SKILL.md, rule 2).

## `data-dir`

- **pass** `owner-only permissions`: fine.
- **warn** `not created yet`: `init` hasn't run. Do setup step 4.
- **FAIL** `readable by group or others: …`: the kit creates everything
  owner-only, so something outside the kit changed it. Don't fix it
  yourself; ask the user what touched the volume, and suggest an issue.

## `core-dumps`

- **pass**: the server turns core dumps off at start.
- **FAIL** `can't turn them off on this system`: the host's container
  runtime blocks it. Suggest an issue, with `docker version` and
  `uname -a`.

## `memory`

Viewing keys must never reach swap (spec §6.2).

- **pass** with `memory can be locked`, `no swap`, `swap is off for this
  container`, or `swap is always encrypted`: fine.
- **warn** `…without [chain] no viewing keys are held`: only when the
  config has no chain source, which the kit never writes. Suggest an issue.
- **warn** `allowed by hardening.allow_swap`: only with a hand-written
  config. The kit doesn't set it.
- **FAIL** `swap may hold viewing keys, so the server won't start`: the
  kit asks Docker for unlimited locked memory and no swap. If this still
  fails, the container runtime ignored those settings: common with rootless
  Docker, Podman, and some NAS or VPS hosts. Explain the options and let
  the user choose:
  1. Run Docker rootful (the usual install), where the kit's settings work.
  2. Turn host swap off (`sudo swapoff -a`, and remove it from
     `/etc/fstab`), if the host has enough memory.
  Encrypting swap and setting `hardening.allow_swap` needs a config edit,
  which the kit doesn't support yet; suggest an issue instead.

## `ohttp-key`

- **pass** `not used: wallets reach this server as an onion service`: the
  kit's setup; nothing to do.
- **pass** `N days old` / **warn** `… rotate it`: only for servers reached
  through OHTTP relays, which the kit doesn't set up yet. See
  maintenance.md, "Key rotation".
- **FAIL** `unreadable or corrupt`: don't touch the file. Suggest an issue.

## `chain`

The node the server reads blocks from.

- **pass** `network ok, tip N, M min old`: fine.
- **warn** `…: still syncing, or stalled`: the newest block is over 20
  minutes old. Normal while a node syncs (`full`: days). If it stays at one
  height:
  - near mainnet height 3,543,405 with Zaino, it's the NU7 stall: use the
    fallback in `deploy/README.md`, "Zaino and NU7";
  - otherwise check the node itself (`docker compose logs --tail 50 zaino`
    or `zebra` for `full`, or the user's own node).
- **warn** `tip … in the future: check this machine's clock`: the clock is
  behind. Wallet requests more than 60 s off are rejected. Turn on time
  sync (`timedatectl set-ntp true` on systemd hosts).
- **FAIL** `can't reach the chain source`: the URL in the config doesn't
  answer. Check the node is up and reachable from Docker (on Linux, a node
  listening only on 127.0.0.1 can't be reached through
  `host.docker.internal`). If the URL itself is wrong, see
  troubleshooting.md, "Wrong chain source or network after init".
- **FAIL** `the chain source isn't on <network>`: the node is on another
  network than `LZ_NETWORK` was at `init`. Same section.
- **FAIL** `didn't report a tip` / `didn't serve its tip block`: the node
  answers but isn't serving blocks yet, usually because it just started.
  Wait a few minutes and run `doctor` again.
- **FAIL** `invalid [chain] lightwalletd URL`: same as a wrong URL.
- **warn** `no [chain]`: the kit always writes a chain source; suggest an
  issue.

## `gateway`

Whether the server answers where wallets reach it, with its own key
configuration.

- **pass** `answers on the listen address, where Tor forwards (the onion
  check covers the onion name)`: the server side is fine; see `onion` for
  the Tor side.
- **pass** `the public gateway answers with this server's key
  configuration`: for servers behind OHTTP relays, which the kit doesn't
  set up yet.
- **FAIL** `nothing answers on the listen address: is the server
  running?`: start it (`docker compose up -d`), then check its logs. When
  `doctor` runs with the server stopped, this line always fails.
- **FAIL** `can't reach the public gateway over HTTPS…`: only for OHTTP
  servers; the kit doesn't set them up. Suggest an issue.
- **FAIL** `the gateway answered N`: something other than the server
  answers at that address. Suggest an issue with `docker compose ps`.
- **FAIL** `it serves another key configuration…`: another server answers
  at that address, or a cache in front of it is stale. In the kit this
  means two installs share an address (for example `LZ_SERVER_IP` reused
  in another project). Ask the user before changing anything.

## `onion`

Whether wallets can reach the server by its onion name, checked through
the kit's own Tor, as a wallet would. It can take up to two minutes.

- **pass** `reachable through Tor by its onion name…`: fine. If a wallet
  still can't connect, the problem is on the wallet's side (its Tor, or
  the URL).
- **pass** `not used: …OHTTP relays`: not an onion service.
- **warn** `not checked: no Tor client…`: `LZ_TOR_SOCKS` is empty. The kit
  sets it; someone set it empty in `.env` or the environment. Nothing is
  wrong, it just wasn't checked.
- **FAIL** `can't reach the Tor client in LZ_TOR_SOCKS…`: the `tor`
  container isn't running. `docker compose ps tor`, then
  `docker compose up -d tor`.
- **FAIL** `Tor can't reach the onion service…` or `no answer through Tor
  within N s…`: if `gateway` failed too, the server is down; fix that
  first. Otherwise, right after a start, Tor may not have published the
  service yet; wait a few minutes and run `doctor` again. If it persists,
  read `docker compose logs --tail 50 tor`: Tor needs outbound internet.
- **FAIL** `the onion service answered N` or `…serves another key
  configuration…`: something else answers at that name, for example a
  second install restored from the same Tor volume. Ask the user before
  changing anything; suggest an issue.

## `clock`

This machine's clock, against `pool.ntp.org`. `doctor` sends it one
time query (UDP port 123); nothing else is sent.

- **pass** `within N s of NTP time`: fine.
- **warn** `N s behind` / `ahead: turn on time sync`: within the 60 s
  replay window, but drifting. Turn on time sync on the host
  (`timedatectl set-ntp true` on systemd hosts). Containers use the
  host's clock, so fix it on the host.
- **FAIL** `… past the 60 s replay window`: webhook receivers and push
  gateways may refuse what the server sends. Same fix, then run `doctor`
  again.
- **warn** `couldn't ask a time server…`: the host or network blocks
  outgoing NTP. The clock isn't checked; if the host keeps time some other
  way, nothing to do.
