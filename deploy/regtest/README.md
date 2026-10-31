# regtest

A private regtest chain (Zebra and Zaino in Docker) for the server's
integration tests against real software, not the fake chain source the
other tests use. Not a self-hosting kit, and never for real funds.

```sh
docker compose -f deploy/regtest/compose.yaml up -d --wait
cargo test -p lz-server --test regtest -- --ignored --test-threads 1
docker compose -f deploy/regtest/compose.yaml down
```

CI runs the same steps on every push.

## What the tests check

- Zaino's answers match what the server assumes: the network check, the
  consensus branch id, and the byte order of compact block hashes.
- The chain follower tracks Zebra's tip through Zaino.
- The scanner finds real payments, by backfill and live. Zebra pays each
  block reward to the test wallet's Sapling address (`miner_address` in
  `zebrad.toml`), so every mined block is a payment to find.
- `GetMempoolStream` stays open while the mempool is empty and ends when a
  block is mined.

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
