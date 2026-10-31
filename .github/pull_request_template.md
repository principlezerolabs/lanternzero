## What and why

<!-- What this changes, and the problem it solves. Link an issue if there is one. -->

## Privacy checklist

See [CONTRIBUTING.md](https://github.com/principlezerolabs/lanternzero/blob/main/CONTRIBUTING.md#privacy-invariants). Tick each box, or
explain below why it doesn't apply.

- [ ] No viewing key, token, or key-derived data can reach disk, logs, errors,
      metrics, or crash output.
- [ ] New secret-holding types redact `Debug` and zero on drop.
- [ ] Scanning-mode and default-mode wallets still send the same requests, at
      the same times, at the same sizes.
- [ ] Push payloads carry nothing in the clear beyond the fixed ping.
- [ ] No per-transaction chain lookups were added.
- [ ] The spec (`spec/v0.md`) is updated if the wire format or a privacy
      property changed, and the test vectors are regenerated if needed.
- [ ] Code touching keys or tokens has tests for the invariants above.
- [ ] Nothing here is a secret, a real key, or a deployment detail.

## Testing

<!-- What you ran: scripts/check.sh, cargo deny check, cargo +stable/+1.86/+1.89 tests, regtest if applicable. -->
