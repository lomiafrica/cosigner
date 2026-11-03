# Automated co-signer profile

This profile sits on the interoperable FROST co-signing messages (Zcash Community Grants issue 490). It does not replace a QR or air-gapped signer. It adds a signer that will refuse a PCZT outside its mandate.

## Roles

The group is 2-of-3 RedPallas, even Y, identifiers 1, 2, and 3.

The coordinator is the agent (identifier 1). ZIP 312 already trusts the coordinator for privacy and not for the spend. The agent can build the proof and can withhold a message. It cannot produce a valid spend authorization signature by itself.

The automated signer is identifier 2. It decodes the PCZT with `pczt-inspect` and runs `mandate::evaluate`. It returns one of:

- `allow`, then a FROST signature share
- `needs_user`, with a reason and the amount, and no signature share
- `refuse`, with a reason, and no signature share

Identifier 3 is the user. `needs_user` is completed by identifier 1 and identifier 3. Identifier 2 does not join that signature.

The automated signer takes no message and no randomizer from the coordinator. It reads both from the PCZT it judged. Otherwise a coordinator could get an `allow` for one PCZT and a signature share over the sighash of another.

## Randomizer

Round 2 uses the Orchard spend alpha as the FROST randomizer (`Randomizer::from_scalar`). Every action has its own alpha. A seed derived later will not match `rk` in the PCZT, and `apply_signature` will reject it.

Only real spends are signed. Padding spends are signed by the IO Finalizer and already carry a signature. A PCZT with several real spends needs one FROST round per spend, each with fresh nonces. The automated signer receives them as a list in action order.

## Outputs

Wallets leave `user_address` empty on change and on zero-value padding. The signer compares outputs by Orchard receiver: each output is reported as the Orchard-only unified address of its own receiver, and the mandate's change address and allowlist are rewritten the same way. A zero-value output with no address is padding. A valued output with no address has to be the mandate's change address or an allowlisted address, or it is refused.

The signer also runs the Orchard cross-address check. Since NU6.3 the Orchard pool only allows an action to send back to the receiver it spends from. New funds arrive in the Ironwood pool, which has the same action shape.

## Backup

The user share should be exported with the draft FROST member backup (the Zkool `zkfrost` string, discussed in zcash/zips issue 1413 and drafted in zcash/zips pull request 1432). Version 1 is a 68-byte payload: version, member index, threshold, group size, the 32-byte signing share, and the 32-byte secret. Even Y has to be applied before that export.

## Decisions

The vectors in `spec/vectors/mandate.json` are the decision cases:

- in mandate: allow
- over the per-payment cap: needs the user
- a second payment that would pass the daily cap if the first were forgotten: needs the user
- unknown recipient, including an output described as change: refuse
- expired mandate: refuse
- fee above the fee cap: refuse
- the same sighash again: refuse
- a memo that does not match the required memo: refuse

Caps are `needs_user` so a real larger payment can still be approved on the user's device. Everything else is a refusal. The policy share does not sign either one.

## What this profile is not

It is not a facilitator, an Accept invoice rail, or a wallet scanner. Payment construction stays in a PCZT wallet. x402 settlement stays with the facilitator that already speaks it.
