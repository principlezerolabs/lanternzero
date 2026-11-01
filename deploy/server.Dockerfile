# syntax=docker/dockerfile:1
# The Lantern Zero server image. Build from the repository root:
#   docker build -f deploy/server.Dockerfile -t lantern-zero/server:local .
# (`docker compose build` in deploy/ does the same.) Base images are pinned
# by digest; bump them deliberately.

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
    cargo build --release --locked -p lz-server \
    && install -D -m 0755 target/release/lz-server /out/lz-server
# The volume mount point, owned by the runtime user with mode 0700, so a
# new named volume starts out owner-only (spec §6.1).
RUN install -d -m 0700 -o 65532 -g 65532 /out/lantern-zero

# gcr.io/distroless/cc-debian13:nonroot: glibc and libgcc, no shell,
# runs as uid 65532.
FROM gcr.io/distroless/cc-debian13@sha256:08476c244888bfb425bae1ae4dd7c17f093e972aab8426883d97f3c6f280f7c1
COPY --from=build /out/lz-server /usr/local/bin/lz-server
COPY --from=build --chown=65532:65532 /out/lantern-zero /var/lib/lantern-zero
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/lz-server"]
CMD ["/var/lib/lantern-zero/config.toml"]
