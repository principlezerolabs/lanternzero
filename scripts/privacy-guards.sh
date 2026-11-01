#!/usr/bin/env bash
# Client-side crates are embedded in wallet SDKs: no async runtime, no TLS
# stack, no Zcash wallet crates that would clash with the SDK's pins.
set -euo pipefail
cd "$(dirname "$0")/.."

for crate in lz-proto lz-client; do
  if cargo tree -p "$crate" --locked --target all -e normal --prefix none \
      | grep -E '^(tokio|rustls|openssl|native-tls|zcash_client_backend|zcash_client_sqlite) '; then
    echo "$crate pulls in a forbidden dependency"
    exit 1
  fi
done
