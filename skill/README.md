# skill

A Claude skill, `lantern-zero-self-host`, that walks you through
self-hosting with the [`deploy/`](../deploy/README.md) kit. It guides and
troubleshoots; the Compose files and `lz-server init` do the installing.
For troubleshooting, it runs `lz-server doctor` and explains the output
instead of editing configuration by hand. See
[`../deploy/DESIGN.md`](../deploy/DESIGN.md).

**Status: prototype**, like the kit. Its commands are checked against the
kit on regtest; it hasn't guided a mainnet install yet.

## Install

Copy the folder into your Claude Code skills, on the machine that will run
the server:

```sh
cp -R skill/lantern-zero-self-host ~/.claude/skills/
```

Then start Claude Code in the repository and ask it to set up or check
your Lantern Zero server.

## What it will and won't do

- It runs only the kit's documented commands, and edits only `deploy/.env`,
  after showing you the change.
- It never sees your connection URL: it asks you to run `init` and
  `new-account` in your own terminal, because the URL holds your account
  token and anything Claude sees is sent to the model provider.
- It doesn't read the server's data or Tor's volume, and asks before
  anything that deletes keys, accounts, or the onion address.
- It doesn't post issues or send anything off the machine; it can draft an
  issue from `doctor` output for you to post.

## Files

| Path | |
| --- | --- |
| `lantern-zero-self-host/SKILL.md` | Ground rules, setup, checking an install |
| `lantern-zero-self-host/references/doctor.md` | Every `doctor` check: what it means, how to fix it |
| `lantern-zero-self-host/references/troubleshooting.md` | Error messages from Compose, `init`, and the server |
| `lantern-zero-self-host/references/maintenance.md` | Accounts, updates, key rotation, backups, removal |

When the kit, `init`, or `doctor` changes, update the skill in the same
pull request.
