# Troubleshooting

Find the message the user sees, explain it, and give the fix. Run `doctor`
whenever the server is running (SKILL.md, "Checking an install").

## Before the server starts

**`required variable LZ_VAPID_CONTACT is missing a value`** (any `docker
compose` command): set `LZ_VAPID_CONTACT` in `.env` (setup step 3).

**`Pool overlaps with other one on this address space`** or **`invalid
pool request`**: the kit's network, `172.30.77.0/24`, collides with one
already on this host. In `.env`, pick a free private /24 and set both:
`LZ_SUBNET=172.30.<n>.0/24` and `LZ_SERVER_IP=172.30.<n>.10`. Then
`docker compose down` (no `-v`) and start again. Changing them after
`init` is fine: the address is only used inside the kit.

**`docker compose version` older than 2.20**, or errors about `required`
under `depends_on`: update Docker Compose.

**Build fails**: show the last lines of `docker compose build`. Disk full
is the most common cause (`df -h`); `docker builder prune` frees build
cache after asking the user. Otherwise suggest an issue with the output.

## `init`

The user runs it in their own terminal (SKILL.md, rule 1), so ask them to
copy only the error line, never the URL.

**`Tor hasn't written the onion hostname file yet; is the tor service
running?`**: check `docker compose ps tor` and `docker compose logs --tail
50 tor`. Tor needs outbound internet to publish the onion service. Fix the
cause, then run `init` again.

**`a config file already exists there; init never overwrites one`**: this
install is already set up. For another wallet or device, add an account
(maintenance.md). Starting over is destructive (SKILL.md, rule 5).

**`the onion hostname file doesn't hold a v3 onion address`**: Tor's data
is damaged. Suggest an issue; don't edit Tor's volume.

**A usage message** (`--network is required`, `unknown option`, …): `init`
was given options by hand. Run it plainly, with options from `.env`.

## The server won't start, or restarts in a loop

Read `docker compose logs --tail 50 server` and match the error:

**`bad config` … `cannot read config: No such file`**: `init` hasn't run.
Do setup step 4, then `docker compose up -d`.

**`bad config`** with anything else: the config was edited by hand or
damaged. Don't edit it. Suggest an issue with the error line.

**`refusing to start: viewing keys could reach swap or a core dump`**: see
doctor.md, `memory` FAIL. To run `doctor` while the server is down, stop it
first, because the one-off container takes the server's address:

```sh
docker compose stop server
docker compose run --rm --no-deps server /var/lib/lantern-zero/config.toml doctor
docker compose up -d server
```

**`startup failed`** with `key file … is corrupt`, or a store error: the
data volume is damaged. Don't touch it. Suggest an issue; restoring from a
backup (maintenance.md) is the user's decision.

**Killed with exit code 137, or `OOMKilled` in `docker inspect`**: the
server hit `LZ_SERVER_MEMORY`. Locked memory counts against it. Raise it in
`.env` (for example to `2g`) and run `docker compose up -d`.

## Wrong chain source or network after init

`init` copies `LZ_NETWORK` and `LZ_LIGHTWALLETD` into the config once;
editing `.env` later changes nothing. Use `set-chain`, with the user's
agreement on the new values. It checks the new source first and changes
nothing if the check fails:

```sh
docker compose exec server lz-server /var/lib/lantern-zero/config.toml \
  set-chain --lightwalletd <url> [--network <main|test|regtest>]
docker compose restart server
```

Also update `LZ_LIGHTWALLETD` and `LZ_NETWORK` in `.env` to match, so the
two don't disagree later. If the server isn't running, stop it and use
`docker compose run --rm --no-deps server …` instead of `exec`. If the
new node isn't up yet, `--no-check` skips the check; run `doctor` once it
is.

Changing the network keeps the accounts, but wallets on the old network
refuse the server, so they need accounts on the right one. Accounts and
URLs otherwise stay the same. Don't edit `config.toml` by hand instead
(SKILL.md, rule 2).

**`another lz-server process is using this data directory; stop it
first`**: something ran a command that needs the server stopped (only
`rotate-vapid` does), or a second server started on the same volume. Stop
the server, run the command with `docker compose run --rm --no-deps
server …`, then start it again (maintenance.md).

## The wallet can't connect

- Run `doctor`; a `chain` failure also breaks the wallet.
- `docker compose ps`: `server` and `tor` must be up.
- The wallet must reach `.onion` addresses over Tor; Tor can take a minute
  or two to publish the service after a restart.
- `account token not accepted`: the URL is wrong or the account was
  deleted. Make a new account (maintenance.md).
- An account made with `new-account` works only after
  `docker compose restart server`.

## Wake-ups don't arrive

Self-hosted wake-ups depend on the wallet vendor's push gateway accepting
this server (spec §5.3). If `doctor` passes and the wallet shows live
updates while open, the gateway is the likely cause; the user can ask the
wallet vendor. The server's logs never show push endpoints, by design.
