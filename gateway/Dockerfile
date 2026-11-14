# syntax=docker/dockerfile:1
# The lz-gateway image (gateway/README.md). Build from the repository root:
#   docker build -f gateway/Dockerfile -t lantern-zero/gateway:local .
# Base images are pinned by digest, the same ones as deploy/server.Dockerfile
# and relay/Dockerfile; bump them together.

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
    cargo build --release --locked -p lz-gateway \
    && install -D -m 0755 target/release/lz-gateway /out/lz-gateway \
    && install -d -m 0700 /out/data

# gcr.io/distroless/cc-debian13:nonroot: glibc and libgcc, no shell,
# runs as uid 65532. The gateway's only state is data_dir (sealing keys
# and the revocation list): mount a volume at /var/lib/lz-gateway (a
# named volume takes the image's owner, 65532, and mode 0700; a host
# directory must have them), and the config and the APNs and FCM
# credentials read-only. The root file system can be read-only.
FROM gcr.io/distroless/cc-debian13@sha256:08476c244888bfb425bae1ae4dd7c17f093e972aab8426883d97f3c6f280f7c1
COPY --from=build /out/lz-gateway /usr/local/bin/lz-gateway
COPY --from=build --chown=65532:65532 /out/data /var/lib/lz-gateway
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/lz-gateway"]
CMD ["/etc/lz-gateway/config.toml"]
