# What has been proven

Recorded 30 October 2026. No transaction was broadcast from this checkout.

## Local

`cargo test --workspace` passes. That includes:

- Mandate decisions for an in-mandate payment, a payment over the per-payment cap (the policy share is not asked to sign), an unknown recipient, an expired mandate, an unset expiry, change sent to an address that is not the mandate change address, a fee above the fee cap, a second payment that stays under the per-payment cap but crosses the daily cap, a replayed sighash, a memo that is too long, a memo that does not match, a memo the co-signer cannot see when one is required, a dummy spend key, a redacted value, transparent or Sapling value, both pools, and an unbound or mismatched value commitment.
- The nine cases in `spec/vectors/mandate.json`.
- A re-randomized RedPallas 2-of-3 signature from a test dealer, and the same after distributed key generation. The signature verifies against the randomized verifying key.
- A repeated commitment id is refused before a second signature.
- `pczt-inspect` parses `crates/pczt-inspect/tests/ironwood_v6.pczt` (header `PCZT`) and returns the shielded sighash `7d48149e6ae74a301bc74c7e1a5af48c52c0d20550a086899db07555e73f53a5`. That is the sighash published with the Zcash Foundation fixture. Parsing it is not a broadcast, and it is not a mainnet transaction.

`cargo clippy --workspace --all-targets -- -D warnings` passes. `cargo fmt --all -- --check` passes.

The ZIP-321 helpers pass `tsc --noEmit` and the five Node tests in `test/`.

## Not run

There is no funded testnet or mainnet wallet in this checkout. Distributed key generation has not been run across three machines. No testnet payment, no phone approval, and no mainnet x402 payment was sent. There are no transaction ids and no screen recording.

`agent-signer broadcast` posts JSON to `ZCASH_BROADCAST_URL` when that variable is set. It does not speak lightwalletd gRPC. With the variable unset it exits 2 and does not pretend a transaction went out.
