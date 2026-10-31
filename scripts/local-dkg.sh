#!/usr/bin/env bash
# Run the 2-of-3 DKG for all three shares on this machine.
#
# Demo setup only: one machine sees all three shares. A real deployment runs
# each part on the agent, the policy service, and the user's phone.
#
# Usage: scripts/local-dkg.sh <state-dir>
# Writes agent.json, policy.json, user.json (secret, mode 600) and group.json
# (public). Prints only the group ak.
set -euo pipefail

STATE="${1:?state dir}"
BIN="${COSIGNER_BIN:-target/release}"
AGENT="$BIN/agent-signer"
POLICY="$BIN/cosigner"

if [ -e "$STATE/group.json" ]; then
  echo "refusing to overwrite $STATE/group.json" >&2
  exit 1
fi
umask 077
mkdir -p "$STATE"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

tool() {
  case "$1" in
    2) echo "$POLICY" ;;
    *) echo "$AGENT" ;;
  esac
}

run() {
  local out
  out="$("$(tool "$1")" "$2" <<<"$3")"
  if [ "$(jq -r .ok <<<"$out")" != "true" ]; then
    echo "share $1 $2 failed: $(jq -r .error <<<"$out")" >&2
    exit 1
  fi
  printf '%s' "$out"
}

for id in 1 2 3; do
  run "$id" dkg-part1 "{\"identifier\":$id}" >"$WORK/r1-$id.json"
done

round1_except() {
  local me="$1" body="{}"
  for id in 1 2 3; do
    [ "$id" = "$me" ] && continue
    body="$(jq --arg id "$id" --slurpfile p "$WORK/r1-$id.json" '. + {($id): $p[0].package_hex}' <<<"$body")"
  done
  printf '%s' "$body"
}

for id in 1 2 3; do
  input="$(jq -n --slurpfile s "$WORK/r1-$id.json" --argjson p "$(round1_except "$id")" \
    '{secret_hex: $s[0].secret_hex, packages: $p}')"
  run "$id" dkg-part2 "$input" >"$WORK/r2-$id.json"
done

public=""
for id in 1 2 3; do
  round2="{}"
  for sender in 1 2 3; do
    [ "$sender" = "$id" ] && continue
    round2="$(jq --arg s "$sender" --arg me "$id" --slurpfile p "$WORK/r2-$sender.json" \
      '. + {($s): $p[0].packages[$me]}' <<<"$round2")"
  done
  input="$(jq -n --slurpfile s "$WORK/r2-$id.json" --argjson r1 "$(round1_except "$id")" \
    --argjson r2 "$round2" '{secret_hex: $s[0].secret_hex, round1: $r1, round2: $r2}')"
  out="$(run "$id" dkg-part3 "$input")"
  this_public="$(jq -r .public_hex <<<"$out")"
  if [ -n "$public" ] && [ "$public" != "$this_public" ]; then
    echo "shares disagree on the group key" >&2
    exit 1
  fi
  public="$this_public"
  case "$id" in
    1) name=agent ;;
    2) name=policy ;;
    3) name=user ;;
  esac
  jq -n --argjson id "$id" --argjson o "$out" \
    '{identifier: $id, key_hex: $o.key_hex, public_hex: $o.public_hex}' >"$STATE/$name.json"
done

ak="$(run 1 group-key "{\"public_hex\":\"$public\"}" | jq -r .ak_hex)"
jq -n --arg p "$public" --arg ak "$ak" '{public_hex: $p, ak_hex: $ak}' >"$STATE/group.json"
chmod 600 "$STATE"/*.json
echo "$ak"
