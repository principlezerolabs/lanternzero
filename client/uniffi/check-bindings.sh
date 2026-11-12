#!/usr/bin/env bash
# Generates the Swift and Kotlin bindings and compiles both, so a change
# to the exported API that breaks one language fails here, not in an app
# (issue #14: a field named `message` clashed with `Throwable.message`).
#
# Needs: cargo, a JDK (java on PATH or JAVA_HOME), curl, unzip. Swift is
# checked when `swiftc` is on PATH (Xcode on macOS, preinstalled on
# GitHub's Ubuntu runners). The Kotlin compiler and JNA are downloaded at
# pinned versions and checked against their published SHA-256 sums.
#
# Usage: client/uniffi/check-bindings.sh [work-dir]
set -euo pipefail

KOTLIN_VERSION=2.4.21
KOTLIN_SHA256=7cc140e76daf416a0424a5557f99afd7ca89ebd463ea1101261e3e01c33e75cd
JNA_VERSION=5.17.0
JNA_SHA256=b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0

root=$(cd "$(dirname "$0")/../.." && pwd)
work=${1:-"$root/target/uniffi-check"}
mkdir -p "$work"
work=$(cd "$work" && pwd)
cd "$root"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# fetch URL FILE SHA256: download once, verify every time.
fetch() {
  if [[ ! -f "$work/$2" ]]; then
    curl -fsSL --retry 3 -o "$work/$2.part" "$1"
    mv "$work/$2.part" "$work/$2"
  fi
  local got
  got=$(sha256 "$work/$2")
  if [[ "$got" != "$3" ]]; then
    echo "check-bindings: $2 has SHA-256 $got, expected $3" >&2
    rm -f "$work/$2"
    exit 1
  fi
}

case "$(uname -s)" in
  Darwin) lib=liblz_client_uniffi.dylib ;;
  *) lib=liblz_client_uniffi.so ;;
esac

# shellcheck disable=SC2086 # CARGO_FLAGS is a list of flags
cargo build -p lz-client-uniffi ${CARGO_FLAGS:-}
out="$work/out"
rm -rf "$out"
# shellcheck disable=SC2086
cargo run -p lz-client-uniffi --features bindgen --bin uniffi-bindgen ${CARGO_FLAGS:-} -- \
  generate --library "target/debug/$lib" \
  --language swift --language kotlin --no-format --out-dir "$out"

# Kotlin: compile against JNA, as an Android app does.
fetch "https://github.com/JetBrains/kotlin/releases/download/v$KOTLIN_VERSION/kotlin-compiler-$KOTLIN_VERSION.zip" \
  "kotlin-compiler-$KOTLIN_VERSION.zip" "$KOTLIN_SHA256"
fetch "https://repo1.maven.org/maven2/net/java/dev/jna/jna/$JNA_VERSION/jna-$JNA_VERSION.jar" \
  "jna-$JNA_VERSION.jar" "$JNA_SHA256"
kotlinc="$work/kotlinc-$KOTLIN_VERSION/bin/kotlinc"
if [[ ! -x "$kotlinc" ]]; then
  rm -rf "$work/kotlinc-$KOTLIN_VERSION" "$work/kotlinc"
  unzip -q "$work/kotlin-compiler-$KOTLIN_VERSION.zip" -d "$work"
  mv "$work/kotlinc" "$work/kotlinc-$KOTLIN_VERSION"
fi
rm -rf "$work/classes"
"$kotlinc" -nowarn -cp "$work/jna-$JNA_VERSION.jar" \
  "$out/uniffi/lz_client_uniffi/lz_client_uniffi.kt" -d "$work/classes"
echo "check-bindings: Kotlin compiles"

# Swift: typecheck against the generated C header and module map.
if command -v swiftc >/dev/null; then
  swiftc -typecheck -I "$out" \
    -Xcc -fmodule-map-file="$out/lz_client_uniffiFFI.modulemap" \
    "$out/lz_client_uniffi.swift"
  echo "check-bindings: Swift typechecks"
else
  echo "check-bindings: no swiftc on PATH; Swift not checked" >&2
fi
