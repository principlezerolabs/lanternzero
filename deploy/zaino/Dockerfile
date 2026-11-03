# syntax=docker/dockerfile:1
# Zaino built from one pinned commit: our NU7 fallback (deploy/README.md,
# "Zaino and NU7"). Zaino 0.10.x stops indexing at NU7
# (zingolabs/zaino#1731); the fix is zingolabs/zaino#1655 (`feat/nu7`),
# not yet released. Once a release with it ships, the kit goes back to
# Zaino's own image and this file goes away.
#
#   docker build -t lantern-zero/zainod:nu7 deploy/zaino
#
# Pinned, so rebuilds get the same thing: Zaino's source by commit, both
# base images by digest, and apt packages from a fixed Debian snapshot.
# To move to a newer commit, change ZAINO_COMMIT (a full commit id) and run
# the regtest suite against it, normal and NU7 (deploy/regtest/README.md).

ARG ZAINO_COMMIT=aaf8122a703704e05147d984f08ff82c789860ad
ARG DEBIAN_SNAPSHOT=20261101T000000Z

# rust:1.96.0-trixie, Zaino's rust-toolchain.toml version.
FROM rust@sha256:58fe97504a0e4cbba5d85599619a589923d3e779472a6fb0840d58d1c4ba99d7 AS build
ARG ZAINO_COMMIT
ARG DEBIAN_SNAPSHOT
# The image's toolchain as is; rust-toolchain.toml would also fetch fmt
# and clippy.
ENV RUSTUP_TOOLCHAIN=1.96.0 \
    CARGO_TERM_COLOR=never
RUN printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" \
      'Suites: trixie trixie-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
      'Check-Valid-Until: no' \
      '' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}" \
      'Suites: trixie-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
      'Check-Valid-Until: no' \
      > /etc/apt/sources.list.d/debian.sources \
    && rm -f /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends clang cmake protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
# Only Zaino's source at that commit; its one submodule is documentation.
ADD --keep-git-dir=false "https://github.com/zingolabs/zaino.git#${ZAINO_COMMIT}" /src
WORKDIR /src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p zainod --features no_tls_use_unencrypted_traffic \
    && install -D -m 0755 target/release/zainod /out/zainod
# The data mount point, owned by the runtime user, so a new named volume
# starts out writable by it.
RUN install -d -m 0700 -o 65532 -g 65532 /out/zaino-data

# debian:trixie-slim, the same base as the Tor image.
FROM debian@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
ARG ZAINO_COMMIT
# Zaino's HTTP client won't start without root certificates, even for the
# plain-http connection to Zebra.
COPY --from=build /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.source="https://github.com/zingolabs/zaino" \
      org.opencontainers.image.revision="${ZAINO_COMMIT}" \
      org.opencontainers.image.description="zainod built from ${ZAINO_COMMIT} (no TLS) for Lantern Zero's NU7 fallback"
RUN groupadd -g 65532 zaino && useradd -u 65532 -g 65532 -M -s /usr/sbin/nologin zaino
COPY --from=build /out/zainod /usr/local/bin/zainod
COPY --from=build --chown=65532:65532 /out/zaino-data /zaino-data
USER 65532:65532
# Zaino puts its RPC cookie under XDG_RUNTIME_DIR and, unless the config
# names one, its database under XDG_CACHE_HOME, else under $HOME, which
# this user doesn't have. The database goes on the data volume.
ENV XDG_RUNTIME_DIR=/tmp \
    XDG_CACHE_HOME=/zaino-data
EXPOSE 8137
ENTRYPOINT ["/usr/local/bin/zainod"]
CMD ["start", "--config", "/etc/zaino/zainod.toml"]
