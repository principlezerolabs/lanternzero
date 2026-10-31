# skill

A Claude skill that walks you through self-hosting with the `deploy/` kit. It
guides and troubleshoots; the Compose files and `lz-server init` do the
installing. For troubleshooting, the skill runs `lz-server doctor` and
explains its output rather than editing configuration by hand. See
[`../deploy/DESIGN.md`](../deploy/DESIGN.md).
