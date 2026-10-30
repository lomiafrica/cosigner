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
| `cosigner` | FROST round 1 and round 2 for one share. |
| `agent-signer` | The agent share: propose, sign, finalize, broadcast, request. |

`spec/automated-cosigner-profile.md` is the message profile. `spec/vectors/mandate.json` is the decision vectors.

## What this does not do

This repo does not scan the chain and it does not build a PCZT. A wallet engine does that: `zcash_client_backend` with lightwalletd or Zaino, or a wallet that already speaks PCZT. Zipher has no license, so it is not a dependency.

One FROST share cannot derive the outgoing viewing key. Note memos stay inside the ciphertext. If a mandate requires a memo and the memo is not visible, the decision is a refusal.

`agent-signer broadcast` posts a raw transaction only when `ZCASH_BROADCAST_URL` is set. It does not speak lightwalletd.

## Build

```sh
cargo test --workspace
pnpm install
pnpm test
```

The policy share is meant to run outside the agent's machine. The `cosigner` binary reads one JSON object on stdin and writes one JSON object on stdout. Commands: `dkg-part1`, `dkg-part2`, `dkg-part3`, `commit`, `sign`, `aggregate`, `decide`, `evaluate`.

Identifiers are fixed. 1 is the agent, 2 is the policy share, 3 is the user.

## License

MIT. See `LICENSE`.
