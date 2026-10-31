#!/usr/bin/env bash
# One co-signed payment from a zcash-devtool view-only wallet.
#
#   scripts/pay.sh <state-dir> <address> <zatoshis> [--memo TEXT] [--with-user]
#
# zcash-devtool creates and proves the PCZT. The agent share proposes, the
# policy share judges the PCZT bytes and signs only inside the mandate, and
# the agent applies the aggregated signature. zcash-devtool broadcasts.
#
# Over a cap the policy share answers needs_user and does not sign. With
# --with-user the user share co-signs with the agent instead. Without it the
# script stops there, which is what the agent alone would get.
#
# <state-dir> holds agent.json, policy.json, user.json, group.json (from
# scripts/local-dkg.sh), mandate.json, ledger.json, and wallet/ (a
# zcash-devtool wallet built from the group's UFVK). Each run keeps its PCZTs
# and JSON under runs/<time>/.
set -euo pipefail

STATE="${1:?state dir}"
TO="${2:?address}"
VALUE="${3:?zatoshis}"
shift 3
MEMO=""
WITH_USER=0
while [ $# -gt 0 ]; do
  case "$1" in
    --memo) MEMO="${2:?memo}"; shift 2 ;;
    --with-user) WITH_USER=1; shift ;;
    *) echo "unknown flag $1" >&2; exit 64 ;;
  esac
done

BIN="${COSIGNER_BIN:-target/release}"
AGENT="$BIN/agent-signer"
POLICY="$BIN/cosigner"
DEVTOOL="${ZCASH_DEVTOOL:-zcash-devtool}"
WALLET="$STATE/wallet"
RUN="$STATE/runs/$(date -u +%Y%m%dT%H%M%SZ)"
umask 077
mkdir -p "$RUN"

call() {
  local tool="$1" command="$2" input="$3" out
  out="$("$tool" "$command" <"$input")"
  if [ "$(jq -r .ok <<<"$out")" != "true" ]; then
    echo "$command failed: $(jq -r .error <<<"$out")" >&2
    exit 1
  fi
  printf '%s' "$out"
}

key() { jq -r .key_hex "$STATE/$1.json"; }
PUBLIC="$(jq -r .public_hex "$STATE/group.json")"
NOW="$(date +%s)"
TODAY="$(date -u +%Y-%m-%d)"

jq --arg today "$TODAY" \
  'if .day == $today then . else .day = $today | .spent_today_zat = 0 end' \
  "$STATE/ledger.json" >"$RUN/ledger.json"

"$DEVTOOL" wallet -w "$WALLET" sync >"$RUN/sync.log" 2>&1
create=(--address "$TO" --value "$VALUE" --output "$RUN/created.pczt")
[ -n "$MEMO" ] && create+=(--memo "$MEMO")
"$DEVTOOL" pczt -w "$WALLET" create "${create[@]}" 2>"$RUN/create.log"
"$DEVTOOL" pczt -w "$WALLET" prove --output "$RUN/proved.pczt" "$RUN/created.pczt" 2>"$RUN/prove.log"
xxd -p "$RUN/proved.pczt" | tr -d '\n' >"$RUN/proved.hex"

jq -n --rawfile p "$RUN/proved.hex" --slurpfile m "$STATE/mandate.json" \
  --slurpfile l "$RUN/ledger.json" --argjson now "$NOW" \
  '{pczt_hex: $p, mandate: $m[0], ledger: $l[0], now_unix: $now}' >"$RUN/judge-input.json"
call "$AGENT" propose "$RUN/judge-input.json" >"$RUN/proposal.json"
COUNT="$(jq '.spends | length' "$RUN/proposal.json")"
SIGHASH="$(jq -r .sighash_hex "$RUN/proposal.json")"
if [ "$COUNT" -eq 0 ]; then
  echo "no spend is waiting for a signature" >&2
  exit 1
fi

commit() {
  jq -n --arg k "$(key "$2")" --argjson n "$COUNT" '{key_hex: $k, count: $n}' >"$RUN/commit-$2.in"
  call "$1" commit "$RUN/commit-$2.in" >"$RUN/commit-$2.json"
  rm "$RUN/commit-$2.in"
}

pair_commitments() {
  jq -n --slurpfile a "$RUN/commit-agent.json" --slurpfile b "$RUN/commit-$2.json" --arg id "$1" \
    '[range(0; $a[0].rounds | length) as $i
      | {"1": $a[0].rounds[$i].commitment_hex, ($id): $b[0].rounds[$i].commitment_hex}]'
}

commit "$AGENT" agent
commit "$POLICY" policy
pair_commitments 2 policy >"$RUN/commitments.json"

jq --arg k "$(key policy)" --slurpfile c "$RUN/commitments.json" \
  --slurpfile r "$RUN/commit-policy.json" \
  '. + {key_hex: $k, rounds: [range(0; $c[0] | length) as $i
     | {nonces_hex: $r[0].rounds[$i].nonces_hex, commitments: $c[0][$i]}]}' \
  "$RUN/judge-input.json" >"$RUN/authorize.in"
call "$POLICY" authorize "$RUN/authorize.in" >"$RUN/authorized.json"
rm "$RUN/authorize.in"
DECISION="$(jq -r .decision.decision "$RUN/authorized.json")"
echo "policy: $(jq -c .decision "$RUN/authorized.json")"

case "$DECISION" in
  allow)
    SECOND=policy
    SECOND_ID=2
    jq '{shares: .shares}' "$RUN/authorized.json" >"$RUN/second-shares.json"
    ;;
  needs_user)
    if [ "$WITH_USER" -ne 1 ]; then
      echo "stopped: the policy share will not sign this. Rerun with --with-user for the user share." >&2
      exit 3
    fi
    SECOND=user
    SECOND_ID=3
    commit "$AGENT" agent
    commit "$AGENT" user
    pair_commitments 3 user >"$RUN/commitments.json"
    ;;
  *)
    echo "refused" >&2
    exit 3
    ;;
esac

sign_round() {
  local who="$1" i="$2"
  jq -n --arg k "$(key "$who")" --slurpfile r "$RUN/commit-$who.json" \
    --slurpfile c "$RUN/commitments.json" --slurpfile p "$RUN/proposal.json" \
    --arg m "$SIGHASH" --argjson i "$i" \
    '{key_hex: $k, nonces_hex: $r[0].rounds[$i].nonces_hex, commitments: $c[0][$i],
      message_hex: $m, alpha_hex: $p[0].spends[$i].alpha_hex}' >"$RUN/sign.in"
  call "$AGENT" sign "$RUN/sign.in" | jq -r .share_hex
  rm "$RUN/sign.in"
}

signatures="[]"
for ((i = 0; i < COUNT; i++)); do
  agent_share="$(sign_round agent "$i")"
  if [ "$SECOND" = policy ]; then
    second_share="$(jq -r --argjson i "$i" '.shares[$i]' "$RUN/second-shares.json")"
  else
    second_share="$(sign_round user "$i")"
  fi
  jq -n --slurpfile c "$RUN/commitments.json" --slurpfile p "$RUN/proposal.json" \
    --arg a "$agent_share" --arg s "$second_share" --arg id "$SECOND_ID" \
    --arg pub "$PUBLIC" --arg m "$SIGHASH" --argjson i "$i" \
    '{commitments: $c[0][$i], shares: {"1": $a, ($id): $s}, public_hex: $pub,
      message_hex: $m, alpha_hex: $p[0].spends[$i].alpha_hex}' >"$RUN/aggregate-$i.json"
  sig="$(call "$AGENT" aggregate "$RUN/aggregate-$i.json" | jq -r .signature_hex)"
  signatures="$(jq --slurpfile p "$RUN/proposal.json" --arg s "$sig" --argjson i "$i" \
    '. + [{pool: $p[0].spends[$i].pool, index: $p[0].spends[$i].index, signature_hex: $s}]' \
    <<<"$signatures")"
done
rm -f "$RUN"/commit-*.json

jq -n --rawfile p "$RUN/proved.hex" --argjson s "$signatures" \
  '{pczt_hex: $p, signatures: $s}' >"$RUN/apply.json"
call "$AGENT" apply "$RUN/apply.json" | jq -r .pczt_hex | xxd -r -p >"$RUN/signed.pczt"

"$DEVTOOL" pczt -w "$WALLET" send "$RUN/signed.pczt" 2>&1 | tee "$RUN/send.log"

AMOUNT="$(jq -r '.decision.amount_zat' "$RUN/authorized.json")"
if [ "$DECISION" = allow ]; then
  jq --arg h "$SIGHASH" --argjson a "$AMOUNT" \
    '.seen_sighashes += [$h] | .spent_today_zat += $a | .spent_total_zat += $a' \
    "$RUN/ledger.json" >"$STATE/ledger.json"
else
  jq --arg h "$SIGHASH" '.seen_sighashes += [$h]' "$RUN/ledger.json" >"$STATE/ledger.json"
fi
echo "run: $RUN"
