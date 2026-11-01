# A minimal Tor image that serves the Lantern Zero onion service. Built
# here rather than taken from a third party, so the kit trusts only
# Debian's tor package (deploy/DESIGN.md, "Which Tor image").

# debian:trixie-slim
FROM debian@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor \
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
