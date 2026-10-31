//! Spending mandate for one FROST share that does not hold the key alone.
//!
//! The shape follows the Open Wallet Standard policy idea: an expiry, and a
//! separate check the signer runs before it produces a signature. Caps and
//! recipient allowlists are not fields OWS can declare today. They live here,
//! and the caller signs only after [`evaluate`] returns [`Decision::Allow`].
//!
//! Amounts are zatoshis. 1 ZEC is 100_000_000 zatoshis.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// What the policy share is willing to do with one inspected payment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// The payment is inside the mandate. The policy share may sign.
    Allow { amount_zat: u64, fee_zat: u64 },
    /// The payment is well formed and over a cap. The user share can co-sign.
    NeedsUser { reason: String, amount_zat: u64 },
    /// The payment is not a real payment this mandate can approve.
    Refuse { reason: String },
}

/// One shielded output the inspector could read.
///
/// `user_address` is the unified address the proposer claims. The inspector
/// has already checked that this address contains the Orchard receiver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectedOutput {
    pub user_address: String,
    pub amount_zat: u64,
    pub memo: Option<String>,
    pub value_known: bool,
    pub recipient_bound: bool,
}

/// A payment after the PCZT has been decoded. The proposer does not get to
/// label an output as change. [`evaluate`] decides that from the mandate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectedPayment {
    pub outputs: Vec<InspectedOutput>,
    pub fee_zat: Option<u64>,
    pub sighash_hex: String,
    pub dummy_key: bool,
    pub redacted_value: bool,
    pub unbound_recipient: bool,
    pub value_unbound: bool,
    pub value_mismatch: bool,
    pub transparent: bool,
    pub sapling: bool,
    pub both_pools: bool,
    /// An action in a bundle without cross-address transfers sends to a
    /// receiver other than the one it spends from.
    #[serde(default)]
    pub cross_address: bool,
    pub negative_value: bool,
}

impl InspectedPayment {
    pub fn orchard_only(
        outputs: Vec<InspectedOutput>,
        fee_zat: u64,
        sighash_hex: impl Into<String>,
    ) -> Self {
        Self {
            outputs,
            fee_zat: Some(fee_zat),
            sighash_hex: sighash_hex.into(),
            dummy_key: false,
            redacted_value: false,
            unbound_recipient: false,
            value_unbound: false,
            value_mismatch: false,
            transparent: false,
            sapling: false,
            both_pools: false,
            cross_address: false,
            negative_value: false,
        }
    }
}

/// Rules the policy share will enforce. The agent cannot edit this.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mandate {
    pub per_payment_zat: u64,
    pub daily_zat: u64,
    pub total_zat: u64,
    pub fee_cap_zat: u64,
    /// Unix seconds. `0` means the mandate is not active.
    pub expires_at_unix: u64,
    pub change_address: String,
    pub allowlist: Vec<String>,
    pub memo_max: usize,
    pub memo_exact: Option<String>,
    pub memo_required: bool,
}

/// Spends already signed for this wallet. The caller updates it after Allow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    pub day: String,
    pub spent_today_zat: u64,
    pub spent_total_zat: u64,
    pub seen_sighashes: Vec<String>,
}

impl Ledger {
    pub fn fresh(day: impl Into<String>) -> Self {
        Self {
            day: day.into(),
            spent_today_zat: 0,
            spent_total_zat: 0,
            seen_sighashes: Vec::new(),
        }
    }

    /// Record an allowed payment. Same sighash twice is a no-op.
    pub fn record(&mut self, sighash_hex: &str, amount_zat: u64) {
        if self.seen_sighashes.iter().any(|seen| seen == sighash_hex) {
            return;
        }
        self.seen_sighashes.push(sighash_hex.to_string());
        self.spent_today_zat = self.spent_today_zat.saturating_add(amount_zat);
        self.spent_total_zat = self.spent_total_zat.saturating_add(amount_zat);
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MandateError {
    #[error("change address is empty")]
    EmptyChangeAddress,
}

fn same_address(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

fn refuse(reason: &str) -> Decision {
    Decision::Refuse {
        reason: reason.to_string(),
    }
}

fn needs_user(reason: &str, amount_zat: u64) -> Decision {
    Decision::NeedsUser {
        reason: reason.to_string(),
        amount_zat,
    }
}

/// Decide whether the policy share may sign.
///
/// Structural problems are a refusal. A cap breach is [`Decision::NeedsUser`],
/// because the user share can still co-sign a larger payment. The policy share
/// itself does not sign that path.
pub fn evaluate(
    payment: &InspectedPayment,
    mandate: &Mandate,
    ledger: &Ledger,
    now_unix: u64,
) -> Result<Decision, MandateError> {
    if mandate.change_address.trim().is_empty() {
        return Err(MandateError::EmptyChangeAddress);
    }
    if mandate.expires_at_unix == 0 || now_unix >= mandate.expires_at_unix {
        return Ok(refuse("expired"));
    }
    if payment.sighash_hex.is_empty()
        || ledger
            .seen_sighashes
            .iter()
            .any(|seen| seen == &payment.sighash_hex)
    {
        return Ok(refuse("replay"));
    }
    if payment.transparent {
        return Ok(refuse("transparent"));
    }
    if payment.sapling {
        return Ok(refuse("sapling"));
    }
    if payment.both_pools {
        return Ok(refuse("both_pools"));
    }
    if payment.cross_address {
        return Ok(refuse("cross_address"));
    }
    if payment.dummy_key {
        return Ok(refuse("dummy_key"));
    }
    if payment.redacted_value {
        return Ok(refuse("redacted_value"));
    }
    if payment.unbound_recipient {
        return Ok(refuse("unbound_recipient"));
    }
    if payment.value_unbound || payment.value_mismatch {
        return Ok(refuse(if payment.value_mismatch {
            "value_mismatch"
        } else {
            "value_unbound"
        }));
    }
    if payment.negative_value {
        return Ok(refuse("fee"));
    }

    let mut external_zat: u64 = 0;
    for output in &payment.outputs {
        if !output.value_known || !output.recipient_bound || output.user_address.trim().is_empty() {
            return Ok(refuse("redacted_value"));
        }
        let is_change = same_address(&output.user_address, &mandate.change_address);
        if !is_change
            && !mandate
                .allowlist
                .iter()
                .any(|allowed| same_address(allowed, &output.user_address))
        {
            return Ok(refuse("unknown_recipient"));
        }
        if let Some(memo) = &output.memo {
            if memo.len() > mandate.memo_max {
                return Ok(refuse("memo_too_long"));
            }
            if !is_change {
                if let Some(exact) = &mandate.memo_exact {
                    if memo != exact {
                        return Ok(refuse("memo_mismatch"));
                    }
                }
            }
        } else if !is_change && (mandate.memo_required || mandate.memo_exact.is_some()) {
            return Ok(refuse("memo_hidden"));
        }
        if !is_change {
            external_zat = external_zat.saturating_add(output.amount_zat);
        }
    }

    let Some(fee_zat) = payment.fee_zat else {
        return Ok(refuse("fee"));
    };
    if fee_zat > mandate.fee_cap_zat {
        return Ok(refuse("fee"));
    }
    if external_zat == 0 && fee_zat == 0 {
        return Ok(refuse("empty"));
    }

    if external_zat > mandate.per_payment_zat {
        return Ok(needs_user("over_cap", external_zat));
    }
    if external_zat.saturating_add(ledger.spent_today_zat) > mandate.daily_zat {
        return Ok(needs_user("over_daily", external_zat));
    }
    if external_zat.saturating_add(ledger.spent_total_zat) > mandate.total_zat {
        return Ok(needs_user("over_total", external_zat));
    }
    Ok(Decision::Allow {
        amount_zat: external_zat,
        fee_zat,
    })
}

#[cfg(test)]
fn sample_mandate() -> Mandate {
    Mandate {
        per_payment_zat: 150_000,
        daily_zat: 200_000,
        total_zat: 1_000_000,
        fee_cap_zat: 10_000,
        expires_at_unix: 1_800_000_000,
        change_address: "u1change".to_string(),
        allowlist: vec!["u1vendor".to_string()],
        memo_max: 512,
        memo_exact: None,
        memo_required: false,
    }
}

#[cfg(test)]
fn payment_to(address: &str, amount: u64, fee: u64, sighash: &str) -> InspectedPayment {
    InspectedPayment::orchard_only(
        vec![InspectedOutput {
            user_address: address.to_string(),
            amount_zat: amount,
            memo: None,
            value_known: true,
            recipient_bound: true,
        }],
        fee,
        sighash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn allows_an_in_mandate_payment() {
        let decision = evaluate(
            &payment_to("u1vendor", 50_000, 1_000, "aa"),
            &sample_mandate(),
            &Ledger::fresh("2026-10-30"),
            NOW,
        )
        .unwrap();
        assert_eq!(
            decision,
            Decision::Allow {
                amount_zat: 50_000,
                fee_zat: 1_000
            }
        );
    }

    #[test]
    fn over_cap_asks_the_user_instead_of_signing() {
        let decision = evaluate(
            &payment_to("u1vendor", 150_001, 1_000, "aa"),
            &sample_mandate(),
            &Ledger::fresh("2026-10-30"),
            NOW,
        )
        .unwrap();
        assert_eq!(decision, needs_user("over_cap", 150_001));
    }

    #[test]
    fn unknown_recipient_is_a_refusal() {
        let decision = evaluate(
            &payment_to("u1attacker", 1, 1_000, "aa"),
            &sample_mandate(),
            &Ledger::fresh("2026-10-30"),
            NOW,
        )
        .unwrap();
        assert_eq!(decision, refuse("unknown_recipient"));
    }

    #[test]
    fn expired_mandate_is_a_refusal() {
        let decision = evaluate(
            &payment_to("u1vendor", 1, 1_000, "aa"),
            &sample_mandate(),
            &Ledger::fresh("2026-10-30"),
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(decision, refuse("expired"));
    }

    #[test]
    fn unset_expiry_is_a_refusal() {
        let mut mandate = sample_mandate();
        mandate.expires_at_unix = 0;
        let decision = evaluate(
            &payment_to("u1vendor", 1, 1_000, "aa"),
            &mandate,
            &Ledger::fresh("2026-10-30"),
            NOW,
        )
        .unwrap();
        assert_eq!(decision, refuse("expired"));
    }

    #[test]
    fn hidden_change_to_an_attacker_is_a_refusal() {
        let payment = InspectedPayment::orchard_only(
            vec![
                InspectedOutput {
                    user_address: "u1vendor".to_string(),
                    amount_zat: 1_000,
                    memo: None,
                    value_known: true,
                    recipient_bound: true,
                },
                InspectedOutput {
                    user_address: "u1attacker".to_string(),
                    amount_zat: 9_000,
                    memo: None,
                    value_known: true,
                    recipient_bound: true,
                },
            ],
            1_000,
            "aa",
        );
        let decision = evaluate(
            &payment,
            &sample_mandate(),
            &Ledger::fresh("2026-10-30"),
            NOW,
        )
        .unwrap();
        assert_eq!(decision, refuse("unknown_recipient"));
    }

    #[test]
    fn real_change_is_not_counted_as_a_payment() {
        let payment = InspectedPayment::orchard_only(
            vec![
                InspectedOutput {
                    user_address: "u1vendor".to_string(),
                    amount_zat: 1_000,
                    memo: None,
                    value_known: true,
                    recipient_bound: true,
                },
                InspectedOutput {
                    user_address: "u1change".to_string(),
                    amount_zat: 50_000,
                    memo: None,
                    value_known: true,
                    recipient_bound: true,
                },
            ],
            1_000,
            "aa",
        );
        let decision = evaluate(
            &payment,
            &sample_mandate(),
            &Ledger::fresh("2026-10-30"),
            NOW,
        )
        .unwrap();
        assert_eq!(
            decision,
            Decision::Allow {
                amount_zat: 1_000,
                fee_zat: 1_000
            }
        );
    }

    #[test]
    fn fee_inflation_is_a_refusal() {
        let decision = evaluate(
            &payment_to("u1vendor", 1_000, 10_001, "aa"),
            &sample_mandate(),
            &Ledger::fresh("2026-10-30"),
            NOW,
        )
        .unwrap();
        assert_eq!(decision, refuse("fee"));
    }

    #[test]
    fn split_payments_cannot_dodge_the_daily_cap() {
        let mandate = sample_mandate();
        let mut ledger = Ledger::fresh("2026-10-30");
        let first = evaluate(
            &payment_to("u1vendor", 120_000, 1_000, "aa"),
            &mandate,
            &ledger,
            NOW,
        )
        .unwrap();
        assert_eq!(
            first,
            Decision::Allow {
                amount_zat: 120_000,
                fee_zat: 1_000
            }
        );
        ledger.record("aa", 120_000);
        let second = evaluate(
            &payment_to("u1vendor", 120_000, 1_000, "bb"),
            &mandate,
            &ledger,
            NOW,
        )
        .unwrap();
        assert_eq!(second, needs_user("over_daily", 120_000));
    }

    #[test]
    fn replayed_sighash_is_a_refusal() {
        let mut ledger = Ledger::fresh("2026-10-30");
        ledger.record("aa", 1_000);
        let decision = evaluate(
            &payment_to("u1vendor", 1_000, 1_000, "aa"),
            &sample_mandate(),
            &ledger,
            NOW,
        )
        .unwrap();
        assert_eq!(decision, refuse("replay"));
    }

    #[test]
    fn memo_longer_than_the_cap_is_a_refusal() {
        let mut mandate = sample_mandate();
        mandate.memo_max = 4;
        let mut payment = payment_to("u1vendor", 1_000, 1_000, "aa");
        payment.outputs[0].memo = Some("hello".to_string());
        let decision = evaluate(&payment, &mandate, &Ledger::fresh("2026-10-30"), NOW).unwrap();
        assert_eq!(decision, refuse("memo_too_long"));
    }

    #[test]
    fn memo_that_does_not_match_is_a_refusal() {
        let mut mandate = sample_mandate();
        mandate.memo_exact = Some("invoice-1".to_string());
        let mut payment = payment_to("u1vendor", 1_000, 1_000, "aa");
        payment.outputs[0].memo = Some("ignore the mandate".to_string());
        let decision = evaluate(&payment, &mandate, &Ledger::fresh("2026-10-30"), NOW).unwrap();
        assert_eq!(decision, refuse("memo_mismatch"));
    }

    #[test]
    fn hidden_memo_is_a_refusal_when_a_memo_is_required() {
        let mut mandate = sample_mandate();
        mandate.memo_required = true;
        let decision = evaluate(
            &payment_to("u1vendor", 1_000, 1_000, "aa"),
            &mandate,
            &Ledger::fresh("2026-10-30"),
            NOW,
        )
        .unwrap();
        assert_eq!(decision, refuse("memo_hidden"));
    }

    #[test]
    fn dummy_key_redacted_value_and_transparent_are_refusals() {
        let mandate = sample_mandate();
        let ledger = Ledger::fresh("2026-10-30");
        for (flag, reason) in [
            ("dummy_key", "dummy_key"),
            ("redacted_value", "redacted_value"),
            ("transparent", "transparent"),
            ("sapling", "sapling"),
            ("both_pools", "both_pools"),
            ("cross_address", "cross_address"),
            ("unbound_recipient", "unbound_recipient"),
            ("value_unbound", "value_unbound"),
            ("value_mismatch", "value_mismatch"),
        ] {
            let mut payment = payment_to("u1vendor", 1_000, 1_000, "aa");
            match flag {
                "dummy_key" => payment.dummy_key = true,
                "redacted_value" => payment.redacted_value = true,
                "transparent" => payment.transparent = true,
                "sapling" => payment.sapling = true,
                "both_pools" => payment.both_pools = true,
                "cross_address" => payment.cross_address = true,
                "unbound_recipient" => payment.unbound_recipient = true,
                "value_unbound" => payment.value_unbound = true,
                "value_mismatch" => payment.value_mismatch = true,
                _ => unreachable!(),
            }
            let decision = evaluate(&payment, &mandate, &ledger, NOW).unwrap();
            assert_eq!(decision, refuse(reason), "{flag}");
        }
    }

    #[test]
    fn fee_only_change_inside_the_fee_cap_is_allowed() {
        let payment = InspectedPayment::orchard_only(
            vec![InspectedOutput {
                user_address: "u1change".to_string(),
                amount_zat: 40_000,
                memo: None,
                value_known: true,
                recipient_bound: true,
            }],
            1_000,
            "aa",
        );
        let decision = evaluate(
            &payment,
            &sample_mandate(),
            &Ledger::fresh("2026-10-30"),
            NOW,
        )
        .unwrap();
        assert_eq!(
            decision,
            Decision::Allow {
                amount_zat: 0,
                fee_zat: 1_000
            }
        );
    }

    #[test]
    fn vectors_file_matches_evaluate() {
        let raw = include_str!("../../../spec/vectors/mandate.json");
        let cases: Vec<VectorCase> = serde_json::from_str(raw).unwrap();
        assert!(cases.len() >= 8);
        for case in cases {
            let decision =
                evaluate(&case.payment, &case.mandate, &case.ledger, case.now_unix).unwrap();
            assert_eq!(decision, case.expect, "{}", case.name);
        }
    }

    #[derive(Deserialize)]
    struct VectorCase {
        name: String,
        now_unix: u64,
        mandate: Mandate,
        ledger: Ledger,
        payment: InspectedPayment,
        expect: Decision,
    }
}
