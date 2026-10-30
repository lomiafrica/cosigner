# Architecture

The spending key is a FROST 2-of-3 group over the RedPallas ciphersuite used for Orchard spend authorization (ZIP 312). The signature is re-randomized. The randomizer is the PCZT spend alpha, not a seed chosen later. A plain FROST signature would not verify against the randomized verifying key.

## Shares

| Id | Holder | What it can do |
| --- | --- | --- |
| 1 | The agent's own machine | Propose a PCZT. Hold one share. Cannot spend alone. |
| 2 | A separate policy service | Decode the PCZT. Check the mandate. Sign only on allow. |
| 3 | The user | Recovery, and the second share for a payment above the cap. |

The policy service does not sign a payment that needs the user. Agent plus user is that path. The policy share stays out of it.

A trusted dealer exists for tests. It sees every share, so production setup is the three-round distributed key generation in `cosigner`. After key generation the group verifying key is forced to even Y, and the share is negated with it. The draft FROST member backup (the Zkool `zkfrost` string) does the same. Skipping it exports a bad share about half the time.

## PCZT

The wallet engine is not in this repo. Construction and note selection stay in `zcash_client_backend` with lightwalletd or Zaino, or in a caller that already has a PCZT (Zashi, or the Zcash Foundation `zcash-sign` tool). This repo inspects that PCZT with the `pczt` crate and co-signs the shielded sighash.

`pczt-inspect` reads Orchard and Ironwood actions through the low-level signer role, which is the path that exposes spend values, alpha, and the value-commitment trapdoor. It then:

- rejects a spend that still carries `dummy_sk` (ZIP 374)
- rejects an output whose value or recipient is missing
- checks that `user_address` is a unified address containing the Orchard receiver
- recomputes the action value commitment from the explicit values and the trapdoor, and compares it to `cv_net`
- checks that the sum of explicit nets matches the bundle value sum
- flags transparent inputs or outputs, Sapling value, and a PCZT that moves value in both Orchard and Ironwood

The fee is the non-negative bundle value sum (spends minus outputs). The bool on the PCZT value sum is the sign. An empty bundle is `(0, false)`, so `false` means the magnitude is non-negative. A negative sum is refused.

Change is not a flag on the output. The mandate's `change_address` is the only change address. Any other address must be on the allowlist. An output to some other address is a refusal, including one a proposer might call change.

## Mandate

The shape follows the Open Wallet Standard policy engine: an expiry, and a check that runs before a signature. OWS declarative rules do not carry a per-payment cap or a recipient allowlist, and they decrypt the key in the same process that asked. Those checks live in `mandate::evaluate`.

Order:

1. Expiry unset or in the past: refuse.
2. Sighash already signed: refuse.
3. Transparent, Sapling, both pools, dummy key, redacted value, unbound recipient, value not bound to `cv`: refuse.
4. Address that is not change and not on the allowlist: refuse.
5. Memo longer than the cap, a memo that does not match `memo_exact`, or a required memo that is not visible: refuse.
6. Fee missing or above `fee_cap`: refuse.
7. Amount above the per-payment, daily, or total cap: needs the user.
8. Otherwise allow.

A fee-only payment back to the change address is an allow, inside the fee cap. A payment of zero with a zero fee is a refusal.

The daily window is a date string the caller supplies, in the user's time zone. This crate does not guess a zone.

## Replay

Signing nonces are one-time. `ReplayGuard` refuses a sighash or a commitment id it has already seen. Returning a cached signature for the same sighash is the service's job. It must not sign again.

## Out of scope

Scanning, proving, and broadcasting through lightwalletd are out of scope. x402 and MPP settlement stay with the facilitator the caller already uses. This profile adds an automated co-signer. It does not add a new payment rail.
