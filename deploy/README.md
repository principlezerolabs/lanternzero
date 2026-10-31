# deploy

Docker Compose kit for self-hosting: Zebra, Zaino, the Lantern Zero server,
and optionally Tor or an OHTTP relay.

[`regtest/`](regtest/README.md) holds a private Zebra and Zaino regtest
chain for the server's integration tests.

**Status of the self-hosting kit: not built yet.** [`DESIGN.md`](DESIGN.md) holds the plan: two
profiles (`full`, and `byo-node` for people who already run a node),
`init` and `doctor` subcommands, Compose hardening for spec §6.2, signed
images pinned by digest, and StartOS and Umbrel packages after that.
