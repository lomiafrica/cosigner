//! Local JSON interface for the policy share.
//!
//! The process prints one JSON object on stdout. Secrets are in that object
//! because the caller has to keep them. They are not written to stderr.
//!
//! There is no raw `sign` here. The policy share signs only through
//! `authorize`, which reads the message and randomizers from the PCZT.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};

use cosigner::{
    aggregate, authorize_pczt, commit, commitments_from_hex, dkg_part1, dkg_part2, dkg_part3,
    identifier, key_from_hex, nonces_from_hex, public_from_hex, randomizer_from_alpha,
    round1_package_from_hex, round1_secret_from_hex, round2_package_from_hex,
    round2_secret_from_hex, share_from_hex, to_hex, Authorized, Round,
};
use mandate::{evaluate, Ledger, Mandate};
use pczt_inspect::PendingSpend;
use serde_json::{json, Value};

fn read_stdin() -> Result<Value, String> {
    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .map_err(|_| "stdin".to_string())?;
    if raw.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&raw).map_err(|_| "json".to_string())
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {key}"))
}

fn packages<T, F>(
    value: &Value,
    key: &str,
    parse: F,
) -> Result<BTreeMap<cosigner::Identifier, T>, String>
where
    F: Fn(&str) -> Result<T, String>,
{
    let object = value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing {key}"))?;
    let mut out = BTreeMap::new();
    for (id, body) in object {
        let id: u16 = id.parse().map_err(|_| "identifier".to_string())?;
        let body = body.as_str().ok_or_else(|| "package".to_string())?;
        out.insert(identifier(id)?, parse(body)?);
    }
    Ok(out)
}

fn ok(value: Value) -> Result<(), String> {
    writeln!(io::stdout(), "{value}").map_err(|_| "stdout".to_string())?;
    Ok(())
}

const MAX_ROUNDS: u64 = 16;

fn policy_inputs(input: &Value) -> Result<(Mandate, Ledger, u64), String> {
    let mandate: Mandate =
        serde_json::from_value(input.get("mandate").cloned().unwrap_or(Value::Null))
            .map_err(|_| "mandate".to_string())?;
    let ledger: Ledger =
        serde_json::from_value(input.get("ledger").cloned().unwrap_or(Value::Null))
            .map_err(|_| "ledger".to_string())?;
    let now = input.get("now_unix").and_then(Value::as_u64).unwrap_or(0);
    Ok((mandate, ledger, now))
}

fn spends_json(spends: &[PendingSpend]) -> Value {
    spends
        .iter()
        .map(|spend| {
            json!({
                "pool": spend.pool.name(),
                "index": spend.index,
                "alpha_hex": spend.alpha_hex,
            })
        })
        .collect()
}

fn run(command: &str, input: &Value) -> Result<(), String> {
    let mut rng = rand::rngs::OsRng;
    match command {
        "dkg-part1" => {
            let id = input
                .get("identifier")
                .and_then(Value::as_u64)
                .ok_or_else(|| "missing identifier".to_string())? as u16;
            let (secret, package) = dkg_part1(id, &mut rng)?;
            ok(json!({
                "ok": true,
                "secret_hex": to_hex(secret.serialize())?,
                "package_hex": to_hex(package.serialize())?,
            }))
        }
        "dkg-part2" => {
            let secret = round1_secret_from_hex(field(input, "secret_hex")?)?;
            let others = packages(input, "packages", round1_package_from_hex)?;
            let (secret, outbound) = dkg_part2(secret, &others)?;
            let mut packages_out = serde_json::Map::new();
            for (id, package) in outbound {
                packages_out.insert(
                    cosigner::participant_id(&id)?.to_string(),
                    json!(to_hex(package.serialize())?),
                );
            }
            ok(json!({
                "ok": true,
                "secret_hex": to_hex(secret.serialize())?,
                "packages": packages_out,
            }))
        }
        "dkg-part3" => {
            let secret = round2_secret_from_hex(field(input, "secret_hex")?)?;
            let round1 = packages(input, "round1", round1_package_from_hex)?;
            let round2 = packages(input, "round2", round2_package_from_hex)?;
            let (key, public) = dkg_part3(&secret, &round1, &round2)?;
            ok(json!({
                "ok": true,
                "key_hex": to_hex(key.serialize())?,
                "public_hex": to_hex(public.serialize())?,
            }))
        }
        "commit" => {
            let key = key_from_hex(field(input, "key_hex")?)?;
            let count = input.get("count").and_then(Value::as_u64).unwrap_or(1);
            if count == 0 || count > MAX_ROUNDS {
                return Err("count".to_string());
            }
            let mut rounds = Vec::new();
            for _ in 0..count {
                let (nonces, commitment) = commit(&key, &mut rng)?;
                rounds.push(json!({
                    "nonces_hex": to_hex(nonces.serialize())?,
                    "commitment_hex": to_hex(commitment.serialize())?,
                }));
            }
            ok(json!({ "ok": true, "rounds": rounds }))
        }
        "authorize" => {
            let key = key_from_hex(field(input, "key_hex")?)?;
            let pczt =
                hex::decode(field(input, "pczt_hex")?).map_err(|_| "pczt hex".to_string())?;
            let (mandate, ledger, now) = policy_inputs(input)?;
            let rounds = input
                .get("rounds")
                .and_then(Value::as_array)
                .ok_or_else(|| "missing rounds".to_string())?
                .iter()
                .map(|round| {
                    Ok(Round {
                        nonces: nonces_from_hex(field(round, "nonces_hex")?)?,
                        commitments: packages(round, "commitments", commitments_from_hex)?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let seen: BTreeSet<String> = input
                .get("seen_commitment_ids")
                .and_then(Value::as_array)
                .map(|ids| {
                    ids.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let result = authorize_pczt(&key, &pczt, &mandate, &ledger, now, &rounds, &seen)?;
            let shares = match &result.authorized {
                Authorized::Signed { shares, .. } => shares.clone(),
                _ => Vec::new(),
            };
            ok(json!({
                "ok": true,
                "decision": result.decision,
                "sighash_hex": result.payment.sighash_hex,
                "spends": spends_json(&result.spends),
                "shares": shares,
                "commitment_ids": result.commitment_ids,
            }))
        }
        "aggregate" => {
            let commitments = packages(input, "commitments", commitments_from_hex)?;
            let shares = packages(input, "shares", share_from_hex)?;
            let public = public_from_hex(field(input, "public_hex")?)?;
            let message =
                hex::decode(field(input, "message_hex")?).map_err(|_| "message hex".to_string())?;
            let alpha =
                hex::decode(field(input, "alpha_hex")?).map_err(|_| "alpha hex".to_string())?;
            let alpha: [u8; 32] = alpha.try_into().map_err(|_| "alpha".to_string())?;
            let signature = aggregate(
                &commitments,
                &shares,
                &public,
                &message,
                randomizer_from_alpha(&alpha)?,
            )?;
            ok(json!({
                "ok": true,
                "signature_hex": hex::encode(signature),
            }))
        }
        "decide" => {
            let pczt =
                hex::decode(field(input, "pczt_hex")?).map_err(|_| "pczt hex".to_string())?;
            let (mandate, ledger, now) = policy_inputs(input)?;
            let (payment, decision) = cosigner::decide_pczt(&pczt, &mandate, &ledger, now)?;
            let spends = pczt_inspect::pending_spends(&pczt).map_err(|err| err.to_string())?;
            ok(json!({
                "ok": true,
                "decision": decision,
                "sighash_hex": payment.sighash_hex,
                "spends": spends_json(&spends),
            }))
        }
        "evaluate" => {
            let payment =
                serde_json::from_value(input.get("payment").cloned().unwrap_or(Value::Null))
                    .map_err(|_| "payment".to_string())?;
            let mandate: Mandate =
                serde_json::from_value(input.get("mandate").cloned().unwrap_or(Value::Null))
                    .map_err(|_| "mandate".to_string())?;
            let ledger: Ledger =
                serde_json::from_value(input.get("ledger").cloned().unwrap_or(Value::Null))
                    .map_err(|_| "ledger".to_string())?;
            let now = input.get("now_unix").and_then(Value::as_u64).unwrap_or(0);
            let decision =
                evaluate(&payment, &mandate, &ledger, now).map_err(|err| err.to_string())?;
            ok(json!({ "ok": true, "decision": decision }))
        }
        _ => Err("unknown command".to_string()),
    }
}

fn main() {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "decide".to_string());
    let input = match read_stdin() {
        Ok(value) => value,
        Err(err) => {
            let _ = writeln!(io::stdout(), "{}", json!({"ok": false, "error": err}));
            std::process::exit(1);
        }
    };
    if let Err(err) = run(&command, &input) {
        let _ = writeln!(io::stdout(), "{}", json!({"ok": false, "error": err}));
        std::process::exit(1);
    }
}
