#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings

if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check
else
  echo "skip: cargo-deny not installed (required in CI; see CONTRIBUTING.md)"
fi

bash "$(dirname "$0")/privacy-guards.sh"

if command -v cargo-machete >/dev/null 2>&1; then
  cargo machete
else
  echo "skip: cargo-machete not installed (cargo install cargo-machete --locked)"
fi

if command -v typos >/dev/null 2>&1; then
  typos
else
  echo "skip: typos not installed (cargo install typos-cli --locked)"
fi
