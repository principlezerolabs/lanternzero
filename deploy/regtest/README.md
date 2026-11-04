# regtest

A private regtest chain (Zebra and Zaino in Docker) for the server's
integration tests against real software, not the fake chain source the
other tests use. Not a self-hosting kit, and never for real funds.

```sh
deploy/regtest/test.sh
```

It starts a chain of its own (a Compose project named for the run, on
ports Docker picks), runs the tests, prints the chain's logs if one
fails, and removes the chain. So it neither collides with nor tears down
a chain already running on this machine. Arguments go to the test
binary (`deploy/regtest/test.sh follower_tracks_the_real_tip`); `KEEP=1`
keeps the chain. CI runs it on every push.

For a chain that stays up, for example to point a server at by hand:

```sh
docker compose -f deploy/regtest/compose.yaml up -d --wait   # Zebra on 18232, Zaino on 8137
cargo test -p lz-server --test regtest -- --ignored --test-threads 1
docker compose -f deploy/regtest/compose.yaml down
```

`LZ_REGTEST_ZEBRA_PORT` and `LZ_REGTEST_ZAINO_PORT` change the ports; the
tests then need `LZ_REGTEST_ZEBRA` and `LZ_REGTEST_LWD` (the URLs).

## What the tests check

- Zaino's answers match what the server assumes: the network check, the
  consensus branch id, and the byte order of compact block hashes.
- The chain follower tracks Zebra's tip through Zaino.
- The scanner finds real payments, by backfill and live. Zebra pays each
  block reward to the test wallet's Sapling address (`miner_address` in
  `zebrad.toml`), so every mined block is a payment to find.
- `GetMempoolStream` stays open while the mempool is empty and ends when a
  block is mined.

## NU7

NU7 activates on mainnet at height 3,543,405. To test across the upgrade,
start the kit with the NU7 variant, which activates it at height 10:

```sh
ZEBRA_CONFIG=zebrad-nu7.toml LZ_REGTEST_NU7=1 deploy/regtest/test.sh crosses_the_nu7_boundary
```

**Known failure (2026-11-01):** Zaino 0.10.1 and 0.10.2 stop at the last
pre-NU7 block, logging `invalid consensus branch id`
([zingolabs/zaino#1731](https://github.com/zingolabs/zaino/issues/1731)).
Their `zebra-chain` 12 parses transaction headers against an upgrade table
that still lists NU7 as a placeholder (`0xfffffffe`), and their
`zcash_protocol` 0.10 has one too. The real id, `0x77190ad9`, arrived in
`zebra-chain` 15 (Zebra 7.0.0) and `zcash_protocol` 0.11. Zebra 7.0.0
handles the upgrade, and so does our server: its follower just sees the tip
stop, and warns after 10 minutes. A CI canary job (`regtest-nu7`, allowed to
fail) runs this test, so a fixed Zaino shows up as soon as it's pinned here.

**The fallback.** `deploy/zaino/Dockerfile` builds Zaino from a pinned
commit of the fix (zingolabs/zaino#1655). To run the kit with it:

```sh
docker build -t lantern-zero/zainod:nu7 deploy/zaino
export LZ_ZAINO_IMAGE=lantern-zero/zainod:nu7 LZ_ZAINO_PLATFORM=linux/arm64  # or linux/amd64
ZEBRA_CONFIG=zebrad-nu7.toml LZ_REGTEST_NU7=1 deploy/regtest/test.sh
```

CI does the same on both chains (`zaino-fallback.yml`), and that one must
pass. Leave `LZ_REGTEST_NU7` unset on the normal chain: the NU7 test runs
whenever it is set.

## Notes

- **Activation heights.** Zebra 7.0.0 activates only Canopy on regtest by
  default; `zebrad.toml` activates NU5 through NU6.3 at height 1.
- **Network name.** Zaino reports `chain_name: "test"` on regtest, the same
  as on testnet. The server tells them apart by Sapling's activation height
  (`chain::network_of`).
- **Not covered yet.** Mempool payments need a wallet to build and prove a
  transaction (for example `zcash-devtool`); reorgs need a second node.
  Both are covered against the fake chain source in `server/tests/`.
- The images are pinned by digest. Zaino publishes amd64 only, so on Apple
  silicon it runs under emulation.
