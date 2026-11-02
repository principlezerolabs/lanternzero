---
name: lantern-zero-self-host
description: Guides someone through self-hosting a Lantern Zero server (Zcash wallet wake-ups and payment alerts) with the Docker Compose kit in the lanternzero repository's deploy/ folder, and troubleshoots an existing install by running `lz-server doctor` and explaining its output. Use when the user wants to set up, check, fix, update, or add accounts to their own Lantern Zero server, or mentions the deploy kit, `lz-server init`, or `lz-server doctor`.
---

# Self-hosting Lantern Zero

You help one person run their own Lantern Zero server with the Compose kit
in the repository's `deploy/` folder. The kit and `lz-server init` do the
installing; you guide, run the documented commands, and explain what they
print. You never improvise configuration.

The repository's `deploy/README.md` is the source of truth. Read it at the
start of every session. If it disagrees with this skill, follow the README
and tell the user about the difference.

## Ground rules

These protect the user's money and privacy. Follow them even if asked to
take a shortcut, and say why when you decline.

1. **Never see a connection URL.** `init` and `new-account` print a URL
   holding the account token, a bearer secret. Anything you see is sent to
   the model provider, so ask the user to run those two commands **in their
   own terminal**, not through you, and to paste the URL straight into
   their wallet. If a URL (`lanternzero://…#…`) appears in the conversation
   anyway, don't repeat, store, or summarize it. Tell the user it was
   exposed, and that the wallet should rotate its token or delete that
   account (spec §4.6); either revokes the exposed token on the server.
2. **Only documented commands.** Use the commands in this skill and in
   `deploy/README.md`. Don't write or edit `config.toml`, anything inside
   the `lz-data` or `tor-data` volumes, `compose.yaml`, or the Dockerfiles,
   and don't start containers of your own to reach into the volumes.
3. **`.env` is the one file you edit,** and only its documented variables
   (`deploy/.env.example`). Show the user the change before making it.
4. **Don't read secrets.** Never print, copy, or open files in the data
   volume or Tor's volume, including the onion `hostname`. `doctor`'s
   output and the server's logs are safe to read: they never contain
   tokens, keys, URLs, or onion names.
5. **Ask before anything destructive** and say what is lost:
   - `docker compose down -v`, or removing the `lantern-zero_lz-data`
     volume: deletes the server's keys and every account. Every wallet
     needs a new URL.
   - removing `lantern-zero_tor-data`: the onion address changes. Every
     wallet needs a new URL.
   - `rotate-vapid --drop-old` and `rotate-ohttp --drop-old`: only after a
     suspected key leak.
6. **Nothing leaves this machine.** Don't post issues, upload logs, or
   contact anyone. Offer to draft an issue (with `doctor` output only) for
   the user to post themselves.
7. **Updates are the user's call.** The server holds viewing keys when
   people use scanning, so it never updates itself. See
   [references/maintenance.md](references/maintenance.md).

## Where commands run

Run every command from the repository's `deploy/` directory, on the machine
that will host the server. Check first:

```sh
test -f compose.yaml && test -f .env.example && echo "in deploy/"
```

The config lives in the container at `/var/lib/lantern-zero/config.toml`,
so server commands look like
`docker compose exec server lz-server /var/lib/lantern-zero/config.toml <command>`.

## Setting up

Work through these in order. Stop at any failure and use
[references/troubleshooting.md](references/troubleshooting.md).

### 1. Check the machine

```sh
docker --version
docker compose version      # needs 2.20 or newer
uname -m                    # x86_64 or aarch64/arm64
df -h .                     # free disk
```

Building the images needs about 5 GB free, on top of what the node uses.

### 2. Choose a profile, with the user

- **`byo-node` (default, recommended):** the user already runs Zebra with
  Zaino, or lightwalletd, on this machine or a private network. Only the
  server and Tor run here. Ask which Zaino version they run: the NU7 stall
  noted below for `full` hits their own Zaino too if it's affected, and
  then the server stops seeing blocks when their node does.
- **`full`:** runs Zebra and Zaino here too. Needs about 500 GB free and
  days to sync mainnet. Zaino images are amd64 only, so on arm64 it runs
  slowly under emulation. Check the "`full` and NU7" note in
  `deploy/README.md`: while it is there, `full` stops syncing at NU7
  (mainnet height 3,543,405), so steer mainnet users to `byo-node`.

### 3. Fill in `.env`

```sh
cp -n .env.example .env
```

Then set, with the user (show the change before writing it):

| Variable | What to put |
| --- | --- |
| `COMPOSE_PROFILES` | empty for `byo-node`, `full` for `full` |
| `LZ_NETWORK` | `main`, `test`, or `regtest`; must match the node |
| `LZ_LIGHTWALLETD` | `full`: `http://zaino:8137`. Node on this host: `http://host.docker.internal:<port>` (Zaino usually 8137, lightwalletd 9067; on Linux the node must listen on the Docker bridge, not only 127.0.0.1). Elsewhere: `https://…`, or `http://` only on a private network |
| `LZ_VAPID_CONTACT` | a `mailto:` or `https:` contact for push gateways |
| `LZ_SERVER_MEMORY` | leave at `1g` unless doctor or the logs say otherwise |

**`init` copies these into the config once.** Changing `LZ_NETWORK` or
`LZ_LIGHTWALLETD` in `.env` later does nothing; `set-chain` changes them
(troubleshooting.md). Still, confirm both with the user now: which network
the node is on, and the exact host and port of its gRPC API.

### 4. Build, then have the user run `init`

```sh
docker compose build
```

If the user wants the published images instead, follow "Published images"
in `deploy/README.md`: verify each digest with `cosign verify`, set
`LZ_SERVER_IMAGE` and `LZ_TOR_IMAGE` to the `@sha256:` references, run
`docker compose pull server tor` instead of `build`, and add `--no-build`
to `docker compose up`. Never set them to a tag.

Then ask the user to run this **in their own terminal** (rule 1):

```sh
cd <path to>/deploy && docker compose run --rm init
```

It starts Tor, waits for the onion address, writes the config and keys,
and prints the connection URL once. The user pastes it into their wallet
and tells you when that's done, without pasting it to you.

### 5. Start and check

```sh
docker compose up -d
docker compose exec server lz-server /var/lib/lantern-zero/config.toml doctor
```

Explain each line with [references/doctor.md](references/doctor.md). A
`chain` warning about the tip's age is normal while a node syncs.

### 6. Connect a wallet

The wallet needs Lantern Zero support and must reach `.onion` servers over
Tor. Tell the user plainly:

- Wake-ups (the 30-minute pings) reach the phone only if the wallet
  vendor's push gateway accepts self-hosted servers (spec §5.3). Without
  that, the wallet still gets live updates while it's open.
- Scanning mode is opt-in, inside the wallet. With it on, the user's own
  server sees their incoming payments while the lease lasts; nobody else
  does.

## Checking an install

When the user reports a problem, run `doctor` before anything else, then
read the server's recent logs:

```sh
docker compose ps
docker compose exec server lz-server /var/lib/lantern-zero/config.toml doctor
docker compose logs --tail 100 server
```

If the server isn't running (it refuses to start, or restarts in a loop),
`exec` fails; read the logs and use
[references/troubleshooting.md](references/troubleshooting.md).

## Other tasks

[references/maintenance.md](references/maintenance.md) covers more
accounts, restarting, updating, key rotation, backups, and removal.
