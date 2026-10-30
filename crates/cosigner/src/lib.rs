//! FROST 2-of-3 for a shielded Orchard spend.
//!
//! Identifiers are fixed: 1 is the agent, 2 is the policy share, 3 is the user.
//! Two shares can sign. The policy share signs only after the mandate allows
//! the payment. A cap breach is [`Authorized::NeedsUser`]: the user share can
//! co-sign, and this crate will not produce a policy signature for that path.
//!
//! Orchard spend authorization is re-randomized FROST. The randomizer is the
//! PCZT spend `alpha`, via [`Randomizer::from_scalar`]. The seed-based helper
//! would not match that scalar.
//!
//! Group keys are finished with even Y. RedDSA and the draft FROST backup
//! negate an odd Y. Skipping that step exports a share that will not verify
//! about half the time.

use std::collections::{BTreeMap, BTreeSet};

use frost_rerandomized::frost_core::{self as frost, Ciphersuite, Field, Group};
use frost_rerandomized::{RandomizedParams, Randomizer};
use mandate::{evaluate, Decision, InspectedPayment, Ledger, Mandate};
use rand::{CryptoRng, RngCore};
use reddsa::frost::redpallas::keys::EvenY;
use reddsa::frost::redpallas::PallasBlake2b512;

pub type Suite = PallasBlake2b512;
pub type Identifier = frost::Identifier<Suite>;
pub type KeyPackage = frost::keys::KeyPackage<Suite>;
pub type PublicKeyPackage = frost::keys::PublicKeyPackage<Suite>;
pub type SigningNonces = frost::round1::SigningNonces<Suite>;
pub type SigningCommitments = frost::round1::SigningCommitments<Suite>;
pub type SignatureShare = frost::round2::SignatureShare<Suite>;
pub type Round1Secret = frost::keys::dkg::round1::SecretPackage<Suite>;
pub type Round1Package = frost::keys::dkg::round1::Package<Suite>;
pub type Round2Secret = frost::keys::dkg::round2::SecretPackage<Suite>;
pub type Round2Package = frost::keys::dkg::round2::Package<Suite>;

pub const AGENT_ID: u16 = 1;
pub const POLICY_ID: u16 = 2;
pub const USER_ID: u16 = 3;
pub const MIN_SIGNERS: u16 = 2;
pub const MAX_SIGNERS: u16 = 3;

fn show<E: core::fmt::Display>(err: E) -> String {
    let text = err.to_string();
    if text.len() > 160 {
        "frost".to_string()
    } else {
        text
    }
}

pub fn identifier(value: u16) -> Result<Identifier, String> {
    Identifier::try_from(value).map_err(show)
}

pub fn participant_id(id: &Identifier) -> Result<u16, String> {
    for candidate in [AGENT_ID, POLICY_ID, USER_ID] {
        if identifier(candidate)? == *id {
            return Ok(candidate);
        }
    }
    Err("identifier".to_string())
}

pub fn to_hex<E: core::fmt::Display>(value: Result<Vec<u8>, E>) -> Result<String, String> {
    Ok(hex::encode(value.map_err(show)?))
}

pub fn key_from_hex(text: &str) -> Result<KeyPackage, String> {
    let bytes = hex::decode(text).map_err(|_| "key hex".to_string())?;
    KeyPackage::deserialize(&bytes).map_err(show)
}

pub fn public_from_hex(text: &str) -> Result<PublicKeyPackage, String> {
    let bytes = hex::decode(text).map_err(|_| "public hex".to_string())?;
    PublicKeyPackage::deserialize(&bytes).map_err(show)
}

pub fn round1_secret_from_hex(text: &str) -> Result<Round1Secret, String> {
    let bytes = hex::decode(text).map_err(|_| "round1 secret hex".to_string())?;
    Round1Secret::deserialize(&bytes).map_err(show)
}

pub fn round1_package_from_hex(text: &str) -> Result<Round1Package, String> {
    let bytes = hex::decode(text).map_err(|_| "round1 package hex".to_string())?;
    Round1Package::deserialize(&bytes).map_err(show)
}

pub fn round2_secret_from_hex(text: &str) -> Result<Round2Secret, String> {
    let bytes = hex::decode(text).map_err(|_| "round2 secret hex".to_string())?;
    Round2Secret::deserialize(&bytes).map_err(show)
}

pub fn round2_package_from_hex(text: &str) -> Result<Round2Package, String> {
    let bytes = hex::decode(text).map_err(|_| "round2 package hex".to_string())?;
    Round2Package::deserialize(&bytes).map_err(show)
}

pub fn nonces_from_hex(text: &str) -> Result<SigningNonces, String> {
    let bytes = hex::decode(text).map_err(|_| "nonce hex".to_string())?;
    SigningNonces::deserialize(&bytes).map_err(show)
}

pub fn commitments_from_hex(text: &str) -> Result<SigningCommitments, String> {
    let bytes = hex::decode(text).map_err(|_| "commitment hex".to_string())?;
    SigningCommitments::deserialize(&bytes).map_err(show)
}

pub fn share_from_hex(text: &str) -> Result<SignatureShare, String> {
    let bytes = hex::decode(text).map_err(|_| "share hex".to_string())?;
    SignatureShare::deserialize(&bytes).map_err(show)
}

/// Make the group verifying key even, and negate this share the same way.
pub fn finish_even_y(key: KeyPackage, public: PublicKeyPackage) -> (KeyPackage, PublicKeyPackage) {
    if public.has_even_y() {
        (key, public)
    } else {
        (
            key.into_even_y(Some(false)),
            public.into_even_y(Some(false)),
        )
    }
}

pub struct DealtGroup {
    pub keys: BTreeMap<Identifier, KeyPackage>,
    pub public: PublicKeyPackage,
}

/// Trusted dealer. Tests only. The dealer sees every share, so production
/// setup uses [`dkg_part1`], [`dkg_part2`], and [`dkg_part3`].
pub fn dealer_2_of_3(rng: &mut (impl RngCore + CryptoRng)) -> Result<DealtGroup, String> {
    let (shares, public) = frost::keys::generate_with_dealer::<Suite, _>(
        MAX_SIGNERS,
        MIN_SIGNERS,
        frost::keys::IdentifierList::Default,
        rng,
    )
    .map_err(show)?;
    let mut keys = BTreeMap::new();
    for (id, share) in shares {
        keys.insert(id, KeyPackage::try_from(share).map_err(show)?);
    }
    let public_even = if public.has_even_y() {
        public
    } else {
        let rewritten = keys
            .into_iter()
            .map(|(id, key)| (id, key.into_even_y(Some(false))))
            .collect();
        keys = rewritten;
        public.into_even_y(Some(false))
    };
    if !public_even.has_even_y() {
        return Err("group key Y is odd".to_string());
    }
    Ok(DealtGroup {
        keys,
        public: public_even,
    })
}

pub fn dkg_part1(
    id: u16,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Round1Secret, Round1Package), String> {
    frost::keys::dkg::part1(identifier(id)?, MAX_SIGNERS, MIN_SIGNERS, rng).map_err(show)
}

pub fn dkg_part2(
    secret: Round1Secret,
    others: &BTreeMap<Identifier, Round1Package>,
) -> Result<(Round2Secret, BTreeMap<Identifier, Round2Package>), String> {
    frost::keys::dkg::part2(secret, others).map_err(show)
}

pub fn dkg_part3(
    secret: &Round2Secret,
    round1: &BTreeMap<Identifier, Round1Package>,
    round2: &BTreeMap<Identifier, Round2Package>,
) -> Result<(KeyPackage, PublicKeyPackage), String> {
    let (key, public) = frost::keys::dkg::part3(secret, round1, round2).map_err(show)?;
    let (key, public) = finish_even_y(key, public);
    if !public.has_even_y() {
        return Err("group key Y is odd".to_string());
    }
    Ok((key, public))
}

pub fn commit(
    key: &KeyPackage,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(SigningNonces, SigningCommitments), String> {
    Ok(frost::round1::commit(key.signing_share(), rng))
}

pub fn randomizer_from_alpha(alpha: &[u8; 32]) -> Result<Randomizer<Suite>, String> {
    type ScalarField = <<Suite as Ciphersuite>::Group as Group>::Field;
    let buf = <ScalarField as Field>::Serialization::try_from(alpha.to_vec())
        .map_err(|_| "alpha".to_string())?;
    let scalar = ScalarField::deserialize(&buf).map_err(|_| "alpha".to_string())?;
    Ok(Randomizer::from_scalar(scalar))
}

/// Sign one share. `sign` is deprecated upstream in favor of a seed, and we
/// keep it because Orchard alpha is the randomizer scalar itself.
#[allow(deprecated)]
pub fn sign_share(
    key: &KeyPackage,
    nonces: &SigningNonces,
    commitments: &BTreeMap<Identifier, SigningCommitments>,
    message: &[u8],
    randomizer: Randomizer<Suite>,
) -> Result<SignatureShare, String> {
    let package = frost::SigningPackage::new(commitments.clone(), message);
    frost_rerandomized::sign(&package, nonces, key, randomizer).map_err(show)
}

pub fn aggregate(
    commitments: &BTreeMap<Identifier, SigningCommitments>,
    shares: &BTreeMap<Identifier, SignatureShare>,
    public: &PublicKeyPackage,
    message: &[u8],
    randomizer: Randomizer<Suite>,
) -> Result<[u8; 64], String> {
    let package = frost::SigningPackage::new(commitments.clone(), message);
    let params = RandomizedParams::from_randomizer(public.verifying_key(), randomizer);
    let signature =
        frost_rerandomized::aggregate(&package, shares, public, &params).map_err(show)?;
    params
        .randomized_verifying_key()
        .verify(message, &signature)
        .map_err(show)?;
    let bytes = signature.serialize().map_err(show)?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "signature length".to_string())?;
    Ok(bytes)
}

/// Commitments and sighashes this share has already used. Nonces are one-time.
#[derive(Clone, Debug, Default)]
pub struct ReplayGuard {
    pub commitments: BTreeSet<String>,
    pub sighashes: BTreeSet<String>,
}

impl ReplayGuard {
    pub fn begin(&self, sighash_hex: &str, commitment_id: &str) -> Result<(), String> {
        if sighash_hex.is_empty() || commitment_id.is_empty() {
            return Err("replay".to_string());
        }
        if self.sighashes.contains(sighash_hex) || self.commitments.contains(commitment_id) {
            return Err("replay".to_string());
        }
        Ok(())
    }

    pub fn commit(&mut self, sighash_hex: &str, commitment_id: &str) {
        self.sighashes.insert(sighash_hex.to_string());
        self.commitments.insert(commitment_id.to_string());
    }
}

pub fn commitment_id(
    commitments: &BTreeMap<Identifier, SigningCommitments>,
) -> Result<String, String> {
    let mut raw = Vec::new();
    for (id, commitment) in commitments {
        raw.extend(id.serialize());
        raw.extend(commitment.serialize().map_err(show)?);
    }
    Ok(hex::encode(raw))
}

/// What the policy share returns. `Signed` is the only arm that carries a share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authorized {
    Signed {
        share_hex: String,
        amount_zat: u64,
        fee_zat: u64,
    },
    NeedsUser {
        reason: String,
        amount_zat: u64,
    },
    Refused {
        reason: String,
    },
}

/// Run `sign` only when the mandate allows the payment.
pub fn authorize<F>(decision: &Decision, sign: F) -> Result<Authorized, String>
where
    F: FnOnce() -> Result<String, String>,
{
    match decision {
        Decision::Allow {
            amount_zat,
            fee_zat,
        } => Ok(Authorized::Signed {
            share_hex: sign()?,
            amount_zat: *amount_zat,
            fee_zat: *fee_zat,
        }),
        Decision::NeedsUser { reason, amount_zat } => Ok(Authorized::NeedsUser {
            reason: reason.clone(),
            amount_zat: *amount_zat,
        }),
        Decision::Refuse { reason } => Ok(Authorized::Refused {
            reason: reason.clone(),
        }),
    }
}

pub fn decide_pczt(
    pczt: &[u8],
    mandate: &Mandate,
    ledger: &Ledger,
    now_unix: u64,
) -> Result<(InspectedPayment, Decision), String> {
    let payment = pczt_inspect::inspect(pczt).map_err(|err| err.to_string())?;
    let decision = evaluate(&payment, mandate, ledger, now_unix).map_err(|err| err.to_string())?;
    Ok((payment, decision))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mandate::{InspectedOutput, InspectedPayment, Ledger, Mandate};
    use rand::rngs::OsRng;

    fn sign_message(message: &[u8]) -> [u8; 64] {
        let mut rng = OsRng;
        let dealt = dealer_2_of_3(&mut rng).unwrap();
        assert!(dealt.public.has_even_y());
        let ids: Vec<_> = dealt.keys.keys().copied().take(2).collect();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for id in &ids {
            let (nonce, commitment) = commit(dealt.keys.get(id).unwrap(), &mut rng).unwrap();
            nonces.insert(*id, nonce);
            commitments.insert(*id, commitment);
        }
        let scalar = <<Suite as Ciphersuite>::Group as Group>::Field::random(&mut rng);
        let randomizer = Randomizer::from_scalar(scalar);
        let mut shares = BTreeMap::new();
        for id in &ids {
            let share = sign_share(
                dealt.keys.get(id).unwrap(),
                nonces.get(id).unwrap(),
                &commitments,
                message,
                randomizer,
            )
            .unwrap();
            shares.insert(*id, share);
        }
        aggregate(&commitments, &shares, &dealt.public, message, randomizer).unwrap()
    }

    #[test]
    fn two_of_three_rerandomized_signature_verifies() {
        let message = b"orchard spend";
        let signature = sign_message(message);
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn dkg_then_two_shares_verify() {
        let mut rng = OsRng;
        let ids = [AGENT_ID, POLICY_ID, USER_ID];
        let mut secrets = BTreeMap::new();
        let mut round1 = BTreeMap::new();
        for id in ids {
            let (secret, package) = dkg_part1(id, &mut rng).unwrap();
            let identifier = identifier(id).unwrap();
            secrets.insert(identifier, secret);
            round1.insert(identifier, package);
        }
        let mut round2_secrets = BTreeMap::new();
        let mut outbound = BTreeMap::new();
        for id in ids {
            let identifier = identifier(id).unwrap();
            let secret = secrets.remove(&identifier).unwrap();
            let others = round1
                .iter()
                .filter(|(other, _)| *other != &identifier)
                .map(|(other, package)| (*other, package.clone()))
                .collect();
            let (round2_secret, packages) = dkg_part2(secret, &others).unwrap();
            round2_secrets.insert(identifier, round2_secret);
            outbound.insert(identifier, packages);
        }
        let mut keys = BTreeMap::new();
        let mut public: Option<PublicKeyPackage> = None;
        for id in ids {
            let me = identifier(id).unwrap();
            let incoming_round1 = round1
                .iter()
                .filter(|(other, _)| *other != &me)
                .map(|(other, package)| (*other, package.clone()))
                .collect();
            let mut incoming_round2 = BTreeMap::new();
            for (sender, packages) in &outbound {
                if sender == &me {
                    continue;
                }
                incoming_round2.insert(*sender, packages.get(&me).unwrap().clone());
            }
            let (key, group) = dkg_part3(
                round2_secrets.get(&me).unwrap(),
                &incoming_round1,
                &incoming_round2,
            )
            .unwrap();
            if let Some(first) = &public {
                assert_eq!(
                    to_hex(first.serialize()).unwrap(),
                    to_hex(group.serialize()).unwrap()
                );
            }
            public = Some(group);
            keys.insert(me, key);
        }
        let public = public.unwrap();
        assert!(public.has_even_y());
        let message = b"dkg";
        let chosen: Vec<_> = keys.keys().copied().take(2).collect();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for id in &chosen {
            let (nonce, commitment) = commit(keys.get(id).unwrap(), &mut rng).unwrap();
            nonces.insert(*id, nonce);
            commitments.insert(*id, commitment);
        }
        let randomizer = Randomizer::from_scalar(
            <<Suite as Ciphersuite>::Group as Group>::Field::random(&mut rng),
        );
        let mut shares = BTreeMap::new();
        for id in &chosen {
            shares.insert(
                *id,
                sign_share(
                    keys.get(id).unwrap(),
                    nonces.get(id).unwrap(),
                    &commitments,
                    message,
                    randomizer,
                )
                .unwrap(),
            );
        }
        let signature = aggregate(&commitments, &shares, &public, message, randomizer).unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn a_second_use_of_the_same_commitment_is_replay() {
        let mut guard = ReplayGuard::default();
        guard.begin("aa", "commitment-1").unwrap();
        guard.commit("aa", "commitment-1");
        assert_eq!(guard.begin("bb", "commitment-1"), Err("replay".to_string()));
        assert_eq!(guard.begin("aa", "commitment-2"), Err("replay".to_string()));
    }

    #[test]
    fn over_cap_does_not_ask_the_signer() {
        let mut called = false;
        let decision = Decision::NeedsUser {
            reason: "over_cap".to_string(),
            amount_zat: 5,
        };
        let authorized = authorize(&decision, || {
            called = true;
            Ok("share".to_string())
        })
        .unwrap();
        assert!(!called);
        assert_eq!(
            authorized,
            Authorized::NeedsUser {
                reason: "over_cap".to_string(),
                amount_zat: 5
            }
        );
    }

    #[test]
    fn a_refusal_does_not_ask_the_signer() {
        let mut called = false;
        let decision = Decision::Refuse {
            reason: "unknown_recipient".to_string(),
        };
        let authorized = authorize(&decision, || {
            called = true;
            Ok("share".to_string())
        })
        .unwrap();
        assert!(!called);
        assert_eq!(
            authorized,
            Authorized::Refused {
                reason: "unknown_recipient".to_string()
            }
        );
    }

    #[test]
    fn allow_asks_the_signer_once() {
        let decision = Decision::Allow {
            amount_zat: 10,
            fee_zat: 1,
        };
        let authorized = authorize(&decision, || Ok("aa".to_string())).unwrap();
        assert_eq!(
            authorized,
            Authorized::Signed {
                share_hex: "aa".to_string(),
                amount_zat: 10,
                fee_zat: 1
            }
        );
    }

    #[test]
    fn key_packages_round_trip_through_hex() {
        let dealt = dealer_2_of_3(&mut OsRng).unwrap();
        let (id, key) = dealt.keys.iter().next().unwrap();
        let restored = key_from_hex(&to_hex(key.serialize()).unwrap()).unwrap();
        assert_eq!(
            to_hex(restored.serialize()).unwrap(),
            to_hex(key.serialize()).unwrap()
        );
        let public = public_from_hex(&to_hex(dealt.public.serialize()).unwrap()).unwrap();
        assert_eq!(
            to_hex(public.serialize()).unwrap(),
            to_hex(dealt.public.serialize()).unwrap()
        );
        let _ = id;
    }

    #[test]
    fn hidden_change_still_refuses_before_any_signature() {
        let payment = InspectedPayment::orchard_only(
            vec![
                InspectedOutput {
                    user_address: "u1vendor".to_string(),
                    amount_zat: 1,
                    memo: None,
                    value_known: true,
                    recipient_bound: true,
                },
                InspectedOutput {
                    user_address: "u1attacker".to_string(),
                    amount_zat: 9,
                    memo: None,
                    value_known: true,
                    recipient_bound: true,
                },
            ],
            1,
            "sighash",
        );
        let mandate = Mandate {
            per_payment_zat: 100,
            daily_zat: 100,
            total_zat: 100,
            fee_cap_zat: 10,
            expires_at_unix: 1_800_000_000,
            change_address: "u1change".to_string(),
            allowlist: vec!["u1vendor".to_string()],
            memo_max: 512,
            memo_exact: None,
            memo_required: false,
        };
        let decision = evaluate(
            &payment,
            &mandate,
            &Ledger::fresh("2026-10-30"),
            1_700_000_000,
        )
        .unwrap();
        let mut called = false;
        let authorized = authorize(&decision, || {
            called = true;
            Ok("nope".to_string())
        })
        .unwrap();
        assert!(!called);
        assert!(matches!(authorized, Authorized::Refused { .. }));
    }
}
