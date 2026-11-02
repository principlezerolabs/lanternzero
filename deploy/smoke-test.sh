#!/usr/bin/env bash
# Smoke test for the self-hosting kit's byo-node profile: builds the images,
# runs `init` against the regtest chain in deploy/regtest (as the "existing
# node"), starts the server with the kit's hardening, and runs `doctor`.
# It doesn't reach the onion service over the Tor network, which would be
# slow and flaky in CI. Needs Docker; CI runs it.
#
#   deploy/smoke-test.sh          # leaves nothing behind
#   KEEP=1 deploy/smoke-test.sh   # keeps the kit running to look at
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME=lz-smoke
export COMPOSE_PROFILES=
export LZ_NETWORK=regtest
# The regtest Zaino, reached over the regtest network (below). Not
# host.docker.internal: on Linux that can't reach ports bound to 127.0.0.1.
export LZ_LIGHTWALLETD=http://lz-regtest-zaino-1:8137
export LZ_VAPID_CONTACT=mailto:smoke-test@example.org
# A subnet unlikely to collide with a real kit on the same machine.
export LZ_SUBNET=172.30.78.0/24
export LZ_SERVER_IP=172.30.78.10
# Attach the server to the regtest chain's network, as a byo-node install
# would reach its node.
override=$(mktemp)
cat >"$override" <<'YAML'
services:
  server:
    networks:
      regtest: {}
networks:
  regtest:
    name: lz-regtest_default
    external: true
YAML
# Ignore any .env here: the variables above are the whole configuration.
kit=(docker compose --env-file /dev/null -f compose.yaml -f "$override")

cleanup() {
  if [[ "${KEEP:-}" != 1 ]]; then
    "${kit[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
    docker compose -p lz-regtest -f regtest/compose.yaml down >/dev/null 2>&1 || true
  fi
  rm -f "$override"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  "${kit[@]}" logs --tail 50 >&2 || true
  exit 1
}

docker compose -p lz-regtest -f regtest/compose.yaml up -d --wait
"${kit[@]}" build

# `init` starts Tor first and waits for the onion hostname.
out=$("${kit[@]}" run --rm -T init) || fail "init failed"
# The URL holds a token: check its shape, never print it.
grep -Eq '^lanternzero://[a-z2-7]{56}\.onion#[A-Za-z0-9_-]+$' <<<"$out" \
  || fail "init printed no connection URL"
echo "ok: init printed a connection URL"

if "${kit[@]}" run --rm -T init >/dev/null 2>&1; then
  fail "a second init succeeded; it must refuse"
fi
echo "ok: a second init refuses"

"${kit[@]}" up -d
config=/var/lib/lantern-zero/config.toml
for _ in $(seq 1 30); do
  if "${kit[@]}" logs server 2>&1 | grep -q "chain follower at tip"; then
    break
  fi
  sleep 1
done
"${kit[@]}" logs server 2>&1 | grep -q "memory hygiene ok" \
  || fail "the server didn't report memory hygiene ok"
"${kit[@]}" logs server 2>&1 | grep -q "chain follower at tip" \
  || fail "the server didn't follow the chain"
echo "ok: the server started, hardened, and follows the chain"

report=$("${kit[@]}" exec -T server lz-server "$config" doctor) \
  || { echo "$report"; fail "doctor failed"; }
echo "$report"
for check in data-dir core-dumps memory ohttp-key; do
  grep -Eq "^pass +$check " <<<"$report" || fail "doctor: $check didn't pass"
done
# Regtest blocks carry old timestamps, so `chain` warns about the tip's
# age; it must not fail.
grep -Eq "^(pass|warn) +chain " <<<"$report" || fail "doctor: chain failed"
grep -Eq "^pass +gateway " <<<"$report" || fail "doctor: gateway didn't pass"
# CI runners may block NTP, which only warns.
grep -Eq "^(pass|warn) +clock " <<<"$report" || fail "doctor: clock failed"
echo "ok: doctor"

# set-chain checks a new source before changing anything, and the server
# uses it from its next start.
if "${kit[@]}" exec -T server lz-server "$config" set-chain \
  --lightwalletd http://127.0.0.1:1 >/dev/null 2>&1; then
  fail "set-chain accepted an unreachable chain source"
fi
"${kit[@]}" exec -T server lz-server "$config" set-chain \
  --lightwalletd "http://zaino:8137" --network test >/dev/null 2>&1 \
  && fail "set-chain accepted a source on the wrong network"
# The same Zaino under its other name on the regtest network.
"${kit[@]}" exec -T server lz-server "$config" set-chain \
  --lightwalletd http://zaino:8137 --network regtest >/dev/null 2>&1 \
  || fail "set-chain refused a working chain source"
"${kit[@]}" restart server >/dev/null
for _ in $(seq 1 30); do
  if "${kit[@]}" logs --since 30s server 2>&1 | grep -q "chain follower at tip"; then
    break
  fi
  sleep 1
done
"${kit[@]}" logs --since 30s server 2>&1 | grep -q "chain follower at tip" \
  || fail "the server didn't follow the new chain source"
echo "ok: set-chain"
