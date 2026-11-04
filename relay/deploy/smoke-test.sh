#!/usr/bin/env bash
# Smoke test for the relay's Compose example: builds the relay image from
# this checkout, runs it behind the example's Caddy (with a local
# certificate for a made-up domain), and sends requests through both to
# a fake gateway on the private network (smoke/). Checks what
# relay/README.md promises operators:
#   - requests and the key configuration get through;
#   - a gateway may take up to 40 s to answer, over HTTP/1.1 and HTTP/2,
#     and the relay gives up after that;
#   - the gateway sees no headers from the client;
#   - each client gets its own rate limit, and can't dodge it with its own
#     X-Forwarded-For;
#   - the relay keeps working when Caddy restarts;
#   - neither log names the client's address or the gateway.
# Needs Docker; CI runs it. About a minute once the image is built, most
# of it the held requests.
#
#   relay/deploy/smoke-test.sh          # leaves nothing behind
#   PINNED=1 relay/deploy/smoke-test.sh # the image compose.yaml pins
#                                       # (once a release has one)
#   KEEP=1 relay/deploy/smoke-test.sh   # keeps it running; then, in relay/deploy,
#     LZ_SMOKE_CADDYFILE=/dev/null LZ_SMOKE_RELAY_TOML=/dev/null docker compose -p lz-relay-smoke \
#       -f compose.yaml -f smoke/compose.yaml down -v
set -euo pipefail
cd "$(dirname "$0")"

export COMPOSE_PROJECT_NAME=lz-relay-smoke
export LZ_RELAY_DOMAIN=relay.test
# A local tag, so `build` doesn't try to tag the build with a digest.
if [[ "${PINNED:-}" != 1 ]]; then
  export LZ_RELAY_IMAGE=lantern-zero/relay:local
fi
compose() { docker compose -f compose.yaml -f smoke/compose.yaml "$@"; }
# The example's own Caddyfile, told to use its local CA for the made-up
# domain instead of asking Let's Encrypt.
work=$(mktemp -d)
export LZ_SMOKE_CADDYFILE=$work/Caddyfile
awk 'NR == 1, /^\{$/ { print; if (/^\{$/) print "\tlocal_certs"; next } { print }' \
  Caddyfile >"$LZ_SMOKE_CADDYFILE"
grep -q '^	local_certs$' "$LZ_SMOKE_CADDYFILE" || { echo "FAIL: can't adapt the Caddyfile" >&2; exit 1; }
# The example's relay.toml, also allowing the fake gateway: plain http
# on a private address, port 8000.
export LZ_SMOKE_RELAY_TOML=$work/relay.toml
{
  echo 'allow_private_targets = true'
  sed 's/^ports = \[\]$/ports = [8000]/' relay.toml
} >"$LZ_SMOKE_RELAY_TOML"
grep -q '^ports = \[8000\]$' "$LZ_SMOKE_RELAY_TOML" || { echo "FAIL: can't adapt relay.toml" >&2; exit 1; }
caddy_ip=172.30.250.2
gateway=http://gateway:8000

cleanup() {
  if [[ "${KEEP:-}" == 1 ]]; then
    echo "KEEP=1: left running (see the header of this script to remove it)"
  else
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$work"
  fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  compose logs >&2 || true
  exit 1
}

# One request through Caddy and the relay, from CLIENT (default
# `client`). Prints `<http version> <status> <seconds>`.
request() {
  compose exec -T "${CLIENT:-client}" curl -sk --resolve "relay.test:443:$caddy_ip" \
    -o /dev/null -w '%{http_version} %{http_code} %{time_total}\n' "$@" \
    "https://relay.test/$gateway"
}
post() { request -H 'Content-Type: message/ohttp-req' "$@"; }
status() { cut -d' ' -f2 <<<"$1"; }
seconds() { cut -d' ' -f3 <<<"$1" | cut -d. -f1; }

if [[ "${PINNED:-}" == 1 ]]; then
  compose pull relay
else
  compose build relay
fi
compose up -d --wait ||
  fail "the services didn't start"
# Caddy issues its local certificate just after it starts.
for _ in $(seq 1 20); do
  [[ "$(status "$(request)")" == 200 ]] && break
  sleep 1
done

r=$(request)
[[ "$(status "$r")" == 200 ]] || fail "key configuration: $r"
keys=$(compose exec -T client curl -sk --resolve "relay.test:443:$caddy_ip" \
  "https://relay.test/$gateway" | od -An -tx1 | tr -d ' \n')
[[ "$keys" == 01020304 ]] || fail "key configuration body: $keys"
echo "ok: the key configuration comes through"

r=$(post -H 'X-Forwarded-For: 192.0.2.7' -H 'Cookie: a=b' -H 'X-Client: c' \
  --data-binary hello)
[[ "$(status "$r")" == 200 ]] || fail "POST: $r"
echo "ok: requests come through"

# A gateway holding its answer for 38 s (a long-poll), over HTTP/1.1 and
# HTTP/2 at once, and one holding it for 45 s, past the relay's 40.
h1=$(mktemp) h2=$(mktemp) late=$(mktemp)
post --http1.1 --data-binary slow38 >"$h1" &
post --http2 --data-binary slow38 >"$h2" &
post --data-binary slow45 >"$late" &
wait
for f in "$h1" "$h2"; do
  r=$(<"$f")
  [[ "$(status "$r")" == 200 && "$(seconds "$r")" -ge 38 ]] ||
    fail "a 38 s answer: $r"
done
r=$(<"$late")
[[ "$(status "$r")" == 504 && "$(seconds "$r")" -lt 45 ]] ||
  fail "a 45 s answer should time out at 40 s: $r"
rm -f "$h1" "$h2" "$late"
echo "ok: answers held for 38 s get through on HTTP/1.1 and HTTP/2; 45 s gets 504"

# The fake gateway prints each request's headers, lowercased.
seen=$(compose logs --no-log-prefix gateway | grep '^POST' |
  grep -o "'[a-z0-9-]*':" | tr -d "':" | sort -u | tr '\n' ' ')
[[ "$seen" == "accept content-length content-type host " ]] ||
  fail "the gateway saw headers: $seen"
echo "ok: the gateway sees only Content-Type, Accept, and framing"

compose restart caddy >/dev/null
for _ in $(seq 1 20); do
  [[ "$(status "$(post --data-binary x)")" == 200 ]] && break
  sleep 1
done
r=$(post --data-binary x)
[[ "$(status "$r")" == 200 ]] || fail "after Caddy restarted: $r"
echo "ok: the relay keeps working when Caddy restarts"

# 70 requests, each claiming another address. The relay keys its limit
# on the address Caddy saw, so the limit (60 a minute) still applies.
# The loop runs in the client container, so its variables expand there.
# shellcheck disable=SC2016
limited=$(compose exec -T -e CADDY="$caddy_ip" -e GATEWAY="$gateway" client sh -c '
  for i in $(seq 1 70); do
    curl -sk --resolve "relay.test:443:$CADDY" -o /dev/null -w "%{http_code}\n" \
      -H "X-Forwarded-For: 198.51.100.$i" -H "Content-Type: message/ohttp-req" \
      --data-binary x "https://relay.test/$GATEWAY"
  done' | grep -c '^429$' || true)
[[ "$limited" -ge 1 ]] || fail "a spoofed X-Forwarded-For got around the rate limit"
# Another client has its own limit, so the relay does tell clients apart
# (trusted_proxies names Caddy).
r=$(CLIENT=other-client post --data-binary x)
[[ "$(status "$r")" == 200 ]] || fail "another client was limited too: $r"
echo "ok: rate limits are per client, and a client's own X-Forwarded-For doesn't get around them"

# With the relay down, Caddy answers 502 itself: the request its error
# log would describe.
compose stop relay >/dev/null
r=$(post --data-binary x)
[[ "$(status "$r")" == 502 ]] || fail "with the relay stopped: $r"
ip_of() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$(compose ps -q "$1")"
}
logs=$(compose logs caddy relay)
for needle in "$(ip_of client)" "$(ip_of other-client)" gateway:8000 \
  192.0.2.7 198.51.100.; do
  if grep -qF "$needle" <<<"$logs"; then
    fail "the logs mention $needle"
  fi
done
echo "ok: neither log names the client's address or the gateway"
