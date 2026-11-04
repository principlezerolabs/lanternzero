#!/usr/bin/env bash
# Runs the regtest suite on a chain of its own: a Compose project named
# for this run, with ports Docker picks, so it neither collides with nor
# tears down a chain already running here (the shared `lz-regtest` one,
# another session's, or deploy/smoke-test.sh's). Removes its chain when
# done, and prints the chain's logs if a test fails. Needs Docker.
#
#   deploy/regtest/test.sh                               # the whole suite
#   deploy/regtest/test.sh follower_tracks_the_real_tip  # arguments go to the test binary
#   KEEP=1 deploy/regtest/test.sh                        # keeps the chain; prints how to remove it
#   ZEBRA_CONFIG=zebrad-nu7.toml LZ_REGTEST_NU7=1 deploy/regtest/test.sh crosses_the_nu7_boundary
#
# Extra cargo flags (for example --locked in CI) go in CARGO_FLAGS.
set -euo pipefail
cd "$(dirname "$0")"

project=lz-regtest-$$
# Empty: Docker picks free host ports (compose.yaml).
export LZ_REGTEST_ZEBRA_PORT= LZ_REGTEST_ZAINO_PORT=
compose=(docker compose -p "$project" -f compose.yaml)

finish() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    "${compose[@]}" logs --tail 200 || true
  fi
  if [[ "${KEEP:-}" == 1 ]]; then
    echo "kept: ${compose[*]} down" >&2
  else
    "${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap finish EXIT

"${compose[@]}" up -d --wait
LZ_REGTEST_ZEBRA="http://$("${compose[@]}" port zebra 18232)"
LZ_REGTEST_LWD="http://$("${compose[@]}" port zaino 8137)"
export LZ_REGTEST_ZEBRA LZ_REGTEST_LWD
echo "chain $project: zebra $LZ_REGTEST_ZEBRA, zaino $LZ_REGTEST_LWD" >&2

# shellcheck disable=SC2086 # CARGO_FLAGS is a list of flags
cargo +stable test -p lz-server --test regtest ${CARGO_FLAGS:-} -- --ignored --test-threads 1 "$@"
