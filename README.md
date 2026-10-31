# cosigner

A FROST 2-of-3 co-signer for a shielded Zcash agent, and a small ZIP-321 receive helper. Built by [lomi.](https://lomi.africa) for its Nomad agent.

An agent that holds its own spending key can ignore its spending limits. This repo splits that key. The agent holds one share. A separate policy service holds the second share and signs only after it has decoded the PCZT itself. The user holds the third share, for recovery and for payments above the cap.

Two shares are enough to spend. The agent alone is not.

An earlier ZIP-321 receive lab from the same team is at [rillongit/zcash](https://github.com/rillongit/zcash). This repo replaces it.

## Crates

| Crate | Role |
| --- | --- |
| `mandate` | Caps, allowlist, expiry, memo rules. Pure. No Zcash types. |
| `pczt-inspect` | Decodes a PCZT and does not trust the proposer's summary. |
| `cosigner` | The policy share. FROST rounds, and `authorize`: judge a PCZT, then sign only that PCZT. |
| `agent-signer` | The agent share (and the user share on the phone side): propose, commit, sign, aggregate, apply, request. |

`spec/automated-cosigner-profile.md` is the message profile. `spec/vectors/mandate.json` is the decision vectors.

## What this does not do

This repo does not scan the chain and it does not build or prove a PCZT. A wallet engine does that. `scripts/pay.sh` uses [zcash-devtool](https://github.com/zcash/zcash-devtool) as a view-only wallet: it creates and proves the PCZT, and it broadcasts the result after this repo has added the spend signatures.

One FROST share cannot derive the outgoing viewing key. Note memos stay inside the ciphertext. If a mandate requires a memo and the memo is not visible, the decision is a refusal.

`agent-signer broadcast` posts a raw transaction only when `ZCASH_BROADCAST_URL` is set. It does not speak lightwalletd.

## A payment end to end

```sh
cargo build --release
scripts/local-dkg.sh ~/.cosigner/demo            # all three shares, demo only
zcash-sign generate --ak "$(jq -r .ak_hex ~/.cosigner/demo/group.json)" --network main
zcash-devtool wallet -w ~/.cosigner/demo/wallet init-fvk --name agent --fvk "<ufvk>"
# write mandate.json and ledger.json into ~/.cosigner/demo, fund the address
scripts/pay.sh ~/.cosigner/demo "<allowlisted address>" 100000
scripts/pay.sh ~/.cosigner/demo "<allowlisted address>" 500000 --with-user
```

`zcash-sign` is the Zcash Foundation tool from [frost-zcash-demo](https://github.com/ZcashFoundation/frost-zcash-demo). It builds an Orchard full viewing key around the FROST group key. Send funds to the Orchard-only address it prints. The state directory holds every share and the viewing key, so keep it private and backed up.

`local-dkg.sh` puts all three shares on one machine. That is fine for a demo and wrong for a real wallet, where each share is generated on its own device.

## Build

```sh
cargo test --workspace
pnpm install
pnpm test
```

The policy share is meant to run outside the agent's machine. The `cosigner` binary reads one JSON object on stdin and writes one JSON object on stdout. Commands: `dkg-part1`, `dkg-part2`, `dkg-part3`, `commit`, `authorize`, `aggregate`, `decide`, `evaluate`.

There is no raw `sign` for the policy share. `authorize` takes the PCZT, the mandate, the ledger, and one round of nonces and commitments per pending spend. It reads the sighash and each spend's alpha from the PCZT, so a caller cannot get the policy share to sign a message it did not judge.

Identifiers are fixed. 1 is the agent, 2 is the policy share, 3 is the user.

## License

MIT. See `LICENSE`.
