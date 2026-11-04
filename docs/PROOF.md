# What has been proven

Recorded 4 November 2026. Two mainnet transactions were broadcast from the one-machine demo wallet. The shares are not in this repo.

## Local

`cargo test --workspace` passes. That includes:

- Mandate decisions for an in-mandate payment, a payment over the per-payment cap (the policy share is not asked to sign), an unknown recipient, an expired mandate, an unset expiry, change sent to an address that is not the mandate change address, a fee above the fee cap, a second payment that stays under the per-payment cap but crosses the daily cap, a replayed sighash, a memo that is too long, a memo that does not match, a memo the co-signer cannot see when one is required, a dummy spend key, a redacted value, transparent or Sapling value, both pools, a cross-address transfer, and an unbound or mismatched value commitment.
- The nine cases in `spec/vectors/mandate.json`.
- A re-randomized RedPallas 2-of-3 signature from a test dealer, and the same after distributed key generation. The signature verifies against the randomized verifying key.
- A repeated commitment id is refused before a second signature.
- `pczt-inspect` parses `crates/pczt-inspect/tests/ironwood_v6.pczt` (header `PCZT`) and returns the shielded sighash `7d48149e6ae74a301bc74c7e1a5af48c52c0d20550a086899db07555e73f53a5`. That is the sighash published with the Zcash Foundation fixture. Parsing it is not a broadcast, and it is not a mainnet transaction.
- In that fixture the inspector finds one Ironwood spend still waiting for a signature, reports every output by its own receiver, and finds no cross-address transfer. The fixture leaves spend values out, so the policy share refuses it as `redacted_value` and signs nothing.
- `apply` rejects a signature that does not verify against the spend's `rk`, and an action index that does not exist.

`cargo clippy --workspace --all-targets -- -D warnings` passes. `cargo fmt --all -- --check` passes.

The ZIP-321 helpers pass `tsc --noEmit` and the five Node tests in `test/`.

## Mainnet, one machine

`scripts/local-dkg.sh` and `zcash-sign generate` produced a 2-of-3 group and an Orchard-only mainnet address. `zcash-devtool` imported the UFVK, synced, and `scripts/pay.sh` drove create, prove, co-sign, and broadcast. The wallet had been funded with 0.015 ZEC in the Ironwood pool. All three shares were on this machine. This is a demo, not the three-device setup.

On 4 November 2026, chain height 3541787:

- 100000 zatoshis to the wallet's own allowlisted address. The policy share returned `allow` (fee 10000) and co-signed. Transaction `ee34835e70743d34ee65011f1b2893b5743bd791e051f23cb14f032dbd02701d`, mined in block 3541787.
- 100000 zatoshis to an address that is not on the allowlist. The policy share returned `refuse` / `unknown_recipient` and did not sign. Nothing was broadcast.
- 500000 zatoshis, over the 200000 per-payment cap. The policy share returned `needs_user` / `over_cap` and did not sign. Nothing was broadcast.
- The same 500000 zatoshis again, with the user share co-signing instead of the policy share. Transaction `49599bbd74e4ca6a9a16684d211e6bfa4c6eacc3ab3ec726253c80462ba47c1d`. Mined in block 3541793.

## Not run

Distributed key generation has not been run across three machines. No phone approval and no mainnet x402 payment was sent. There is no testnet transaction and no screen recording.

`agent-signer broadcast` posts JSON to `ZCASH_BROADCAST_URL` when that variable is set. It does not speak lightwalletd gRPC. With the variable unset it exits 2 and does not pretend a transaction went out.
