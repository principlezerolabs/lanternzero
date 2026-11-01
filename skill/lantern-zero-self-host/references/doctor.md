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
  - near mainnet height 3,543,405 with Zaino, it's the NU7 stall in
    `deploy/README.md`;
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
