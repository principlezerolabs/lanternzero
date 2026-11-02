# A minimal Tor image that serves the Lantern Zero onion service. Built
# here rather than taken from a third party, so the kit trusts only
# Debian's tor package (deploy/DESIGN.md, "Which Tor image").
#
# Pinned, so rebuilds get the same packages: the base image is pinned by
# digest, apt reads a fixed Debian snapshot, and tor is pinned to a
# version in it. To update (for example for a Tor security release): set
# TOR_VERSION to the new version and DEBIAN_SNAPSHOT to a snapshot after
# it reached both archives (its "first seen" dates at
# https://snapshot.debian.org/package/tor/). Bump the base image digest
# from time to time too.

# debian:trixie-slim
FROM debian@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
ARG DEBIAN_SNAPSHOT=20261101T000000Z
ARG TOR_VERSION=0.4.9.15-0+deb13u1
# Plain http: the image has no CA certificates, and apt checks Debian's
# signatures on everything it fetches. Snapshot Release files have expired
# by design, hence Check-Valid-Until.
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
    && apt-get update \
    && apt-get install -y --no-install-recommends "tor=${TOR_VERSION}" \
    && rm -rf /var/lib/apt/lists/* \
    # The same uid as the server image, so `init` can read the hostname.
    && groupadd -g 65532 lz && useradd -u 65532 -g 65532 -M -s /usr/sbin/nologin lz \
    && install -d -m 0700 -o 65532 -g 65532 /var/lib/tor
COPY torrc /etc/tor/torrc
USER 65532:65532
# The hostname appears once Tor has created the onion service.
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s \
    CMD test -s /var/lib/tor/lz/hostname
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
