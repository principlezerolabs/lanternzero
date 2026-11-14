#!/usr/bin/env bash
# Builds the gateway image (gateway/Dockerfile) and checks it: it starts
# with a read-only root as uid 65532, makes its sealing key in a named
# volume with mode 0600, rejects bad requests, and logs nothing about
# them. The APNs key is a throwaway made here; nothing reaches Apple.
#
#   bash gateway/smoke-test.sh      # from anywhere in the repository
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=${LZ_GATEWAY_IMAGE:-lantern-zero/gateway:smoke}
NAME=lz-gateway-smoke
VOLUME=lz-gateway-smoke-data
PORT=${PORT:-18090}
WORK=$(mktemp -d)
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; docker logs "$NAME" 2>&1 | tail -20 || true; exit 1; }

if [ -z "${LZ_GATEWAY_IMAGE:-}" ]; then
  docker build -q -f gateway/Dockerfile -t "$IMAGE" . >/dev/null
fi

mkdir -p "$WORK/secrets"
openssl ecparam -name prime256v1 -genkey -noout |
  openssl pkcs8 -topk8 -nocrypt >"$WORK/secrets/apns-key.p8"
chmod 0755 "$WORK/secrets" && chmod 0644 "$WORK/secrets/apns-key.p8"
cat >"$WORK/config.toml" <<'TOML'
listen = "0.0.0.0:8090"
public_origin = "https://push.example.test"
data_dir = "/var/lib/lz-gateway"

[apns]
team_id = "ABCDE12345"
key_id = "KEY1234567"
key_path = "/etc/lz-gateway/secrets/apns-key.p8"
topic = "app.example.wallet"
sandbox = true
TOML
chmod 0644 "$WORK/config.toml"

docker volume rm "$VOLUME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  -p "127.0.0.1:$PORT:8090" \
  -v "$WORK/config.toml:/etc/lz-gateway/config.toml:ro" \
  -v "$WORK/secrets:/etc/lz-gateway/secrets:ro" \
  -v "$VOLUME:/var/lib/lz-gateway" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  docker logs "$NAME" 2>&1 | grep -q serving && break
  [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true ] || fail "exited"
  sleep 1
done
docker logs "$NAME" 2>&1 | grep -q serving || fail "never started"

[ "$(docker inspect -f '{{.Config.User}}' "$NAME")" = "65532:65532" ] || fail "not uid 65532"

# The sealing key: in the volume, owned by the gateway's user, mode 0600.
# busybox:1.37
BUSYBOX=busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
perms=$(docker run --rm -v "$VOLUME:/d:ro" "$BUSYBOX" stat -c '%u %a' /d/endpoint-keys) \
  || fail "no endpoint-keys in the volume"
[ "$perms" = "65532 600" ] || fail "endpoint-keys is '$perms', want '65532 600'"

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
[ "$(code -X POST "http://127.0.0.1:$PORT/v0/subscriptions" -H 'content-type: application/json' \
  -d '{"platform":"apns","token":"zz","server_key":"x"}')" = 400 ] || fail "bad token not 400"
[ "$(code -X POST "http://127.0.0.1:$PORT/wp/not-an-endpoint" -H 'TTL: 60' \
  -H 'content-encoding: aes128gcm' --data-binary x)" = 404 ] || fail "unknown endpoint not 404"

# Nothing from the requests in the log.
if docker logs "$NAME" 2>&1 | grep -E 'not-an-endpoint|"zz"|server_key'; then
  fail "request data in the log"
fi

echo "gateway image OK"
