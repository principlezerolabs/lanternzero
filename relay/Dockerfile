# syntax=docker/dockerfile:1
# The lz-relay image (relay/README.md). Build from the repository root:
#   docker build -f relay/Dockerfile -t lantern-zero/relay:local .
# (`docker compose build` in relay/deploy/ does the same.) Base images are
# pinned by digest, the same ones as deploy/server.Dockerfile; bump them
# together.

# rust:1.95.0-slim-trixie, the same toolchain as rust-toolchain.toml.
FROM rust@sha256:e14e87345b4d5964ddcc3491d27ee046a0f23820f340c3c1e24da6880141f7c0 AS build
# Use the image's toolchain as is: rust-toolchain.toml would make rustup
# download fmt and clippy, which a release build doesn't need.
ENV RUSTUP_TOOLCHAIN=1.95.0 \
    CARGO_TERM_COLOR=never
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p lz-relay \
    && install -D -m 0755 target/release/lz-relay /out/lz-relay

# gcr.io/distroless/cc-debian13:nonroot: glibc and libgcc, no shell,
# runs as uid 65532. The relay keeps no state, so it needs no volume, and
# it runs with a read-only root file system.
FROM gcr.io/distroless/cc-debian13@sha256:08476c244888bfb425bae1ae4dd7c17f093e972aab8426883d97f3c6f280f7c1
COPY --from=build /out/lz-relay /usr/local/bin/lz-relay
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/lz-relay"]
CMD ["/etc/lz-relay/relay.toml"]
