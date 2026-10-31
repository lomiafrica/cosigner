//! Read a PCZT from the bytes, not from the proposer's summary.
//!
//! One FROST share does not have the full spending key, so it cannot derive
//! the outgoing viewing key and it cannot open note ciphertexts. Values that
//! are missing, or that do not match the value commitment, are refused.
//! Change is not decided here. The mandate compares addresses itself.
//!
//! Every output address is reported as an Orchard-only unified address built
//! from the note's own receiver. Wallets leave `user_address` empty on change
//! and on zero-value padding, so the receiver is the one thing every output
//! has. [`bind_mandate`] rewrites the mandate's addresses the same way.
//!
//! Memo plaintext stays inside the ciphertext. [`mandate::InspectedOutput::memo`]
//! is `None` unless a future PCZT field exposes it. A mandate that requires a
//! memo therefore refuses, which is the safe result.

use std::fmt::Write as _;

use group::ff::PrimeField;
use mandate::{InspectedOutput, InspectedPayment, Mandate};
use thiserror::Error;
use zcash_address::unified::{self, Container, Encoding, Receiver};
use zcash_address::{TryFromAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

#[derive(Debug, Error)]
pub enum InspectError {
    #[error("pczt parse: {0}")]
    Parse(String),
    #[error("orchard bundle: {0}")]
    Orchard(String),
    #[error("sighash: {0}")]
    Sighash(String),
}

struct OrchardReceivers(Vec<[u8; 43]>);

impl TryFromAddress for OrchardReceivers {
    type Error = &'static str;

    fn try_from_unified(
        _net: NetworkType,
        data: zcash_address::unified::Address,
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        let bytes = data
            .items()
            .into_iter()
            .filter_map(|item| match item {
                Receiver::Orchard(raw) => Some(raw),
                _ => None,
            })
            .collect();
        Ok(Self(bytes))
    }
}

fn orchard_receivers(address: &str) -> Vec<[u8; 43]> {
    ZcashAddress::try_from_encoded(address.trim())
        .ok()
        .and_then(|parsed| parsed.convert::<OrchardReceivers>().ok())
        .map(|found| found.0)
        .unwrap_or_default()
}

/// True when `user_address` is a unified address that contains `recipient`.
pub fn unified_contains_orchard(user_address: &str, recipient: &[u8; 43]) -> bool {
    orchard_receivers(user_address)
        .iter()
        .any(|raw| raw == recipient)
}

/// The Orchard-only unified address for one raw receiver.
pub fn orchard_address(network: NetworkType, recipient: &[u8; 43]) -> Option<String> {
    let items = vec![unified::Uitem::Data(Receiver::Orchard(*recipient))];
    unified::Address::try_from_items(unified::Revision::R0, items)
        .ok()
        .map(|address| address.encode(&network))
}

/// Rewrite the change address and allowlist as Orchard-only addresses on
/// `network`, so they compare with what [`inspect`] reports. An entry with no
/// Orchard receiver is kept as written and can never match an output.
pub fn bind_mandate(mandate: &Mandate, network: NetworkType) -> Mandate {
    let bind = |address: &String| -> String {
        orchard_receivers(address)
            .first()
            .and_then(|raw| orchard_address(network, raw))
            .unwrap_or_else(|| address.clone())
    };
    Mandate {
        change_address: bind(&mandate.change_address),
        allowlist: mandate.allowlist.iter().map(bind).collect(),
        ..mandate.clone()
    }
}

/// The network a PCZT was built for, from its SLIP 44 coin type.
/// Testnet and regtest share coin type 1 and both read as testnet.
pub fn network(bytes: &[u8]) -> Result<NetworkType, InspectError> {
    let pczt = pczt::parse(bytes).map_err(|err| InspectError::Parse(err.to_string()))?;
    Ok(network_of(&pczt))
}

fn network_of(pczt: &pczt::Pczt) -> NetworkType {
    if *pczt.global().coin_type() == 133 {
        NetworkType::Main
    } else {
        NetworkType::Test
    }
}

/// Which bundle a spend sits in. Ironwood actions are Orchard-shaped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    Orchard,
    Ironwood,
}

impl Pool {
    pub fn name(self) -> &'static str {
        match self {
            Pool::Orchard => "orchard",
            Pool::Ironwood => "ironwood",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "orchard" => Some(Pool::Orchard),
            "ironwood" => Some(Pool::Ironwood),
            _ => None,
        }
    }
}

/// A real spend still waiting for its spend authorization signature.
/// Padding spends are signed by the IO Finalizer and are not listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSpend {
    pub pool: Pool,
    pub index: usize,
    pub alpha_hex: String,
}

#[derive(Default)]
struct PoolRead {
    outputs: Vec<InspectedOutput>,
    carries_value: bool,
    dummy_key: bool,
    redacted_value: bool,
    unbound_recipient: bool,
    value_unbound: bool,
    value_mismatch: bool,
    cross_address: bool,
    fee_zat: Option<u64>,
    negative_value: bool,
    pending: Vec<(usize, String)>,
}

impl From<pczt::roles::low_level_signer::OrchardParseError> for InspectError {
    fn from(err: pczt::roles::low_level_signer::OrchardParseError) -> Self {
        InspectError::Orchard(format!("{err:?}"))
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn note_zat(value: &Option<orchard::value::NoteValue>) -> Option<u64> {
    value.as_ref().map(orchard::value::NoteValue::inner)
}

fn read_pool(bundle: &orchard::pczt::Bundle, network: NetworkType) -> PoolRead {
    let mut read = PoolRead {
        cross_address: bundle.verify_cross_address_restriction().is_err(),
        ..PoolRead::default()
    };
    let mut net: i128 = 0;
    for (index, action) in bundle.actions().iter().enumerate() {
        let spend = action.spend();
        let output = action.output();
        if spend.dummy_sk().is_some() {
            read.dummy_key = true;
        }
        if spend.spend_auth_sig().is_none() {
            if let Some(alpha) = spend.alpha().as_ref() {
                read.pending
                    .push((index, hex_bytes(alpha.to_repr().as_ref())));
            }
        }
        let spend_value = match note_zat(spend.value()) {
            Some(value) => value,
            None => {
                read.redacted_value = true;
                0
            }
        };
        let output_value = match note_zat(output.value()) {
            Some(value) => value,
            None => {
                read.redacted_value = true;
                0
            }
        };
        if spend_value > 0 || output_value > 0 {
            read.carries_value = true;
        }
        net += i128::from(spend_value);
        net -= i128::from(output_value);

        match (
            output.recipient().as_ref(),
            output.user_address().as_ref(),
            note_zat(output.value()),
        ) {
            (Some(_), None, Some(0)) => {}
            (Some(recipient), user_address, Some(value)) => {
                let raw = recipient.to_raw_address_bytes();
                let bound = user_address
                    .map(|claimed| unified_contains_orchard(claimed, &raw))
                    .unwrap_or(true);
                match orchard_address(network, &raw) {
                    Some(address) if bound => read.outputs.push(InspectedOutput {
                        user_address: address,
                        amount_zat: value,
                        memo: None,
                        value_known: true,
                        recipient_bound: true,
                    }),
                    _ => read.unbound_recipient = true,
                }
            }
            (None, _, Some(_)) => read.unbound_recipient = true,
            _ => read.redacted_value = true,
        }

        match (
            action.rcv().as_ref(),
            note_zat(spend.value()),
            note_zat(output.value()),
        ) {
            (Some(rcv), Some(spent), Some(created)) => {
                let action_net = i128::from(spent) - i128::from(created);
                match expected_cv(action_net, rcv.to_bytes()) {
                    Some(expected) if expected == action.cv_net().to_bytes() => {}
                    Some(_) => read.value_mismatch = true,
                    None => read.value_unbound = true,
                }
            }
            _ => read.value_unbound = true,
        }
    }

    let (magnitude, sign) = bundle.value_sum().magnitude_sign();
    let declared: i128 = match sign {
        orchard::value::Sign::Positive => i128::from(magnitude),
        orchard::value::Sign::Negative => -i128::from(magnitude),
    };
    if !read.redacted_value && declared != net {
        read.value_mismatch = true;
    }
    if matches!(sign, orchard::value::Sign::Negative) {
        read.negative_value = true;
        read.fee_zat = None;
    } else {
        read.fee_zat = Some(magnitude);
    }
    read
}

/// Orchard value-commitment bases from protocol section 5.4.8.4.
/// The `orchard` crate keeps these private unless a circuit feature is on.
const VALUE_COMMITMENT_PERSONALIZATION: &str = "z.cash:Orchard-cv";
const VALUE_COMMITMENT_V_BYTES: [u8; 1] = *b"v";
const VALUE_COMMITMENT_R_BYTES: [u8; 1] = *b"r";

fn expected_cv(net: i128, rcv_bytes: [u8; 32]) -> Option<[u8; 32]> {
    use group::GroupEncoding;
    use pasta_curves::arithmetic::CurveExt;
    use pasta_curves::pallas;

    let rcv = pallas::Scalar::from_repr(rcv_bytes);
    if !bool::from(rcv.is_some()) {
        return None;
    }
    let rcv = rcv.unwrap();
    let hasher = pallas::Point::hash_to_curve(VALUE_COMMITMENT_PERSONALIZATION);
    let value_base = hasher(&VALUE_COMMITMENT_V_BYTES);
    let random_base = hasher(&VALUE_COMMITMENT_R_BYTES);
    let abs = u64::try_from(net.unsigned_abs()).ok()?;
    let mut scalar = pallas::Scalar::from(abs);
    if net < 0 {
        scalar = -scalar;
    }
    let point = value_base * scalar + random_base * rcv;
    Some(point.to_bytes())
}

/// Decode `bytes` into a payment the mandate can judge.
///
/// Orchard and Ironwood are both read. A PCZT that moves value in both is
/// flagged. Transparent or Sapling value is flagged. The sighash is the
/// shielded sighash from the PCZT signer role.
pub fn inspect(bytes: &[u8]) -> Result<InspectedPayment, InspectError> {
    let pczt = pczt::parse(bytes).map_err(|err| InspectError::Parse(err.to_string()))?;
    let network = network_of(&pczt);
    let transparent =
        !pczt.transparent().inputs().is_empty() || !pczt.transparent().outputs().is_empty();
    let sapling = !pczt.sapling().spends().is_empty()
        || !pczt.sapling().outputs().is_empty()
        || *pczt.sapling().value_sum() != 0;

    let (orchard, ironwood) = read_pools(&pczt, network)?;

    let both_pools = orchard.carries_value && ironwood.carries_value;
    let cross_address = orchard.cross_address || ironwood.cross_address;
    let primary = if orchard.carries_value || !orchard.outputs.is_empty() {
        orchard
    } else {
        ironwood
    };
    let sighash = pczt::roles::signer::Signer::new(pczt)
        .map_err(|err| InspectError::Sighash(format!("{err:?}")))?
        .shielded_sighash();

    Ok(InspectedPayment {
        outputs: primary.outputs,
        fee_zat: primary.fee_zat,
        sighash_hex: hex_bytes(&sighash),
        dummy_key: primary.dummy_key,
        redacted_value: primary.redacted_value,
        unbound_recipient: primary.unbound_recipient,
        value_unbound: primary.value_unbound,
        value_mismatch: primary.value_mismatch,
        transparent,
        sapling,
        both_pools,
        cross_address,
        negative_value: primary.negative_value,
    })
}

fn read_pools(
    pczt: &pczt::Pczt,
    network: NetworkType,
) -> Result<(PoolRead, PoolRead), InspectError> {
    let mut orchard = PoolRead::default();
    let mut ironwood = PoolRead::default();
    if !pczt.orchard().actions().is_empty() {
        pczt::roles::low_level_signer::Signer::new(pczt.clone())
            .sign_orchard_with(|_pczt, bundle, _flags| {
                orchard = read_pool(bundle, network);
                Ok::<(), InspectError>(())
            })
            .map_err(|err| InspectError::Orchard(err.to_string()))?;
    }
    if !pczt.ironwood().actions().is_empty() {
        pczt::roles::low_level_signer::Signer::new(pczt.clone())
            .sign_ironwood_with(|_pczt, bundle, _flags| {
                ironwood = read_pool(bundle, network);
                Ok::<(), InspectError>(())
            })
            .map_err(|err| InspectError::Orchard(err.to_string()))?;
    }
    Ok((orchard, ironwood))
}

/// Real spends still waiting for a signature, with the alpha FROST signs
/// under. Each one is its own FROST round with its own nonces.
pub fn pending_spends(bytes: &[u8]) -> Result<Vec<PendingSpend>, InspectError> {
    let pczt = pczt::parse(bytes).map_err(|err| InspectError::Parse(err.to_string()))?;
    let (orchard, ironwood) = read_pools(&pczt, network_of(&pczt))?;
    let tag = |pool: Pool, read: PoolRead| {
        read.pending
            .into_iter()
            .map(move |(index, alpha_hex)| PendingSpend {
                pool,
                index,
                alpha_hex,
            })
    };
    Ok(tag(Pool::Orchard, orchard)
        .chain(tag(Pool::Ironwood, ironwood))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_garbage_string_is_not_an_orchard_receiver() {
        assert!(!unified_contains_orchard("not-an-address", &[7; 43]));
    }

    #[test]
    fn ironwood_fixture_sighash_matches_the_published_vector() {
        let bytes = include_bytes!("../tests/ironwood_v6.pczt");
        assert_eq!(&bytes[..4], b"PCZT");
        let payment = inspect(bytes).expect("ironwood v6 pczt");
        assert_eq!(
            payment.sighash_hex,
            "7d48149e6ae74a301bc74c7e1a5af48c52c0d20550a086899db07555e73f53a5"
        );
    }

    #[test]
    fn ironwood_fixture_has_one_pending_spend_and_bound_outputs() {
        let bytes = include_bytes!("../tests/ironwood_v6.pczt");
        let spends = pending_spends(bytes).unwrap();
        assert_eq!(spends.len(), 1);
        assert_eq!(spends[0].pool, Pool::Ironwood);
        assert_eq!(spends[0].alpha_hex.len(), 64);
        let payment = inspect(bytes).unwrap();
        assert!(!payment.unbound_recipient && !payment.cross_address);
        assert!(payment
            .outputs
            .iter()
            .all(|output| output.user_address.starts_with("utest1")));
    }

    #[test]
    fn mandate_addresses_bind_to_their_orchard_receiver() {
        let raw = [7u8; 43];
        let mut found = false;
        for byte in 0..=255u8 {
            let mut candidate = raw;
            candidate[42] = byte;
            if let Some(address) = orchard_address(NetworkType::Main, &candidate) {
                assert!(unified_contains_orchard(&address, &candidate));
                found = true;
                break;
            }
        }
        assert!(found);
        let mandate = Mandate {
            per_payment_zat: 1,
            daily_zat: 1,
            total_zat: 1,
            fee_cap_zat: 1,
            expires_at_unix: 1,
            change_address: "not-an-address".to_string(),
            allowlist: vec!["also-not".to_string()],
            memo_max: 0,
            memo_exact: None,
            memo_required: false,
        };
        let bound = bind_mandate(&mandate, NetworkType::Main);
        assert_eq!(bound.change_address, "not-an-address");
        assert_eq!(bound.allowlist, vec!["also-not".to_string()]);
    }
}
