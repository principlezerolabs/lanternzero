# Maintenance

All commands run from `deploy/`.

## Another account

One per wallet or person. Like `init`, it prints a URL once, so the user
runs it **in their own terminal** (SKILL.md, rule 1):

```sh
docker compose exec server lz-server /var/lib/lantern-zero/config.toml new-account
docker compose restart server
```

The new account works after the restart. To remove an account, the user
deletes it from the wallet that holds it, with the wallet's delete-account
setting (spec §4.6), which also removes it from the server. Just removing
the server from the wallet leaves the account in place.

## Restart, stop, logs

```sh
docker compose restart server
docker compose stop          # keeps all data
docker compose up -d
docker compose logs --tail 100 server
```

Logs never contain tokens, keys, push endpoints, or request bodies.

## Updating

The server holds viewing keys for users who turn on scanning, so updates
are opt-in. Before updating, show the user what changed and point out
anything that touches key handling:

```sh
git fetch
git log --oneline HEAD..origin/main
```

Then, if the user agrees:

```sh
git pull
docker compose build
docker compose up -d
docker compose exec server lz-server /var/lib/lantern-zero/config.toml doctor
```

The data volumes carry over; wallets keep their URLs.

## Key rotation

- **OHTTP key:** onion setups (the kit's default) don't use it; `doctor`
  says `not used`. Servers reached through OHTTP relays rotate it at least
  every 90 days:
  `docker compose exec server lz-server /var/lib/lantern-zero/config.toml rotate-ohttp`.
  A running server switches within 5 minutes; no restart needed.
- **VAPID key** (signs pushes to gateways): no routine rotation needed.
  After a suspected leak, and with the user's agreement, rotate it. This
  needs the server stopped, because the running server holds the data
  directory:

  ```sh
  docker compose stop server
  docker compose run --rm --no-deps server /var/lib/lantern-zero/config.toml rotate-vapid --drop-old
  docker compose up -d server
  ```

  Wallets register again on their own.

## Backups

Two volumes matter, and both are secrets:

- `lantern-zero_lz-data`: the server's keys and account list. Losing it
  means new URLs for every wallet.
- `lantern-zero_tor-data`: the onion service's identity. Losing it changes
  the onion address, which also means new URLs.

Neither holds viewing keys or payment data. Whether and where to back them
up is the user's decision; anyone with a copy can impersonate the server.
If the user wants one, suggest an encrypted destination, and let them run
the backup themselves, with the server stopped.

## Removing everything

Destructive (SKILL.md, rule 5); confirm first:

```sh
docker compose down -v
```

This deletes the keys, accounts, onion identity, and, for `full`, the
synced chain.
