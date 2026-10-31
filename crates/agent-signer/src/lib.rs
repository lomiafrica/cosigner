//! Commands the agent share can run. The agent can propose a payment and can
//! hold one FROST share. It cannot spend alone.

use mandate::{Decision, InspectedPayment, Ledger, Mandate};
use orchard::keys::{FullViewingKey, Scope};
use orchard::primitives::redpallas::{Signature, SpendAuth};
use pczt::roles::low_level_signer::{OrchardParseError, Signer};
use pczt_inspect::Pool;
use zcash_address::unified::{Container, Encoding, Fvk, Ufvk};

/// The FROST group verifying key as an Orchard `ak`. Group keys are finished
/// with even Y, which is what Orchard's encoding requires.
pub fn group_ak(public_hex: &str) -> Result<String, String> {
    let public = cosigner::public_from_hex(public_hex)?;
    let ak = public
        .verifying_key()
        .serialize()
        .map_err(|_| "group key".to_string())?;
    Ok(hex::encode(ak))
}

/// The Orchard-only address that a wallet built on `ufvk` sends change to:
/// the internal scope at diversifier index 0.
pub fn change_address(ufvk: &str) -> Result<String, String> {
    let (network, _, ufvk) = Ufvk::decode(ufvk.trim()).map_err(|_| "ufvk".to_string())?;
    let orchard = ufvk
        .items()
        .into_iter()
        .find_map(|item| match item {
            Fvk::Orchard(bytes) => FullViewingKey::from_bytes(&bytes),
            _ => None,
        })
        .ok_or_else(|| "ufvk has no orchard key".to_string())?;
    let internal = orchard.address_at(0u32, Scope::Internal);
    pczt_inspect::orchard_address(network, &internal.to_raw_address_bytes())
        .ok_or_else(|| "address".to_string())
}

/// One aggregated spend authorization signature for one pending spend.
pub struct SpendSignature {
    pub pool: Pool,
    pub index: usize,
    pub signature: [u8; 64],
}

#[derive(Debug)]
enum ApplyError {
    Parse(OrchardParseError),
    Index(usize),
    Rejected(usize),
}

impl From<OrchardParseError> for ApplyError {
    fn from(err: OrchardParseError) -> Self {
        ApplyError::Parse(err)
    }
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::Parse(err) => write!(f, "parse {err:?}"),
            ApplyError::Index(index) => write!(f, "no action {index}"),
            ApplyError::Rejected(index) => write!(f, "action {index} rejected the signature"),
        }
    }
}

fn apply_to_bundle(
    bundle: &mut orchard::pczt::Bundle,
    sighash: [u8; 32],
    signatures: &[&SpendSignature],
) -> Result<(), ApplyError> {
    let actions = bundle.actions_mut();
    for signed in signatures {
        let action = actions
            .get_mut(signed.index)
            .ok_or(ApplyError::Index(signed.index))?;
        action
            .apply_signature(sighash, Signature::<SpendAuth>::from(signed.signature))
            .map_err(|_| ApplyError::Rejected(signed.index))?;
    }
    Ok(())
}

/// Write aggregated FROST signatures into the PCZT. Each one is checked
/// against that spend's `rk` before it is stored, so a wrong signature fails
/// here and not at broadcast.
pub fn apply_signatures(pczt: &[u8], signatures: &[SpendSignature]) -> Result<Vec<u8>, String> {
    let sighash: [u8; 32] = hex::decode(
        pczt_inspect::inspect(pczt)
            .map_err(|err| err.to_string())?
            .sighash_hex,
    )
    .ok()
    .and_then(|bytes| bytes.try_into().ok())
    .ok_or_else(|| "sighash".to_string())?;
    let parsed = pczt::parse(pczt).map_err(|err| format!("pczt parse: {err:?}"))?;
    let mut signer = Signer::new(parsed);
    for pool in [Pool::Orchard, Pool::Ironwood] {
        let mine: Vec<&SpendSignature> = signatures.iter().filter(|s| s.pool == pool).collect();
        if mine.is_empty() {
            continue;
        }
        signer = match pool {
            Pool::Orchard => {
                signer.sign_orchard_with(|_, bundle, _| apply_to_bundle(bundle, sighash, &mine))
            }
            Pool::Ironwood => {
                signer.sign_ironwood_with(|_, bundle, _| apply_to_bundle(bundle, sighash, &mine))
            }
        }
        .map_err(|err| format!("{} signature: {err}", pool.name()))?;
    }
    signer
        .finish()
        .serialize()
        .map_err(|err| format!("pczt encode: {err:?}"))
}

/// ZIP-321 request URI. The memo is the unpadded base64url of `resource_id`.
pub fn request_uri(
    address: &str,
    amount: &str,
    resource_id: &str,
    message: Option<&str>,
) -> Result<String, String> {
    let address = address.trim();
    if address.is_empty() || address.contains('/') {
        return Err("address".to_string());
    }
    let lower = address.to_ascii_lowercase();
    if lower.starts_with("t1") || lower.starts_with("t3") || lower.starts_with("tm") {
        return Err("transparent".to_string());
    }
    if !(lower.starts_with("u1")
        || lower.starts_with("utest")
        || lower.starts_with("uregtest")
        || lower.starts_with("zs")
        || lower.starts_with("ztestsapling")
        || lower.starts_with("zregtestsapling"))
    {
        return Err("address".to_string());
    }
    if !amount_ok(amount) {
        return Err("amount".to_string());
    }
    if resource_id.len() > 512 {
        return Err("memo".to_string());
    }
    let memo = base64url(resource_id.as_bytes());
    let mut uri = format!("zcash:{address}?amount={amount}&memo={memo}");
    if let Some(message) = message.map(str::trim).filter(|value| !value.is_empty()) {
        uri.push_str("&message=");
        uri.push_str(&encode_query(message));
    }
    Ok(uri)
}

fn amount_ok(amount: &str) -> bool {
    let mut parts = amount.split('.');
    let Some(whole) = parts.next() else {
        return false;
    };
    let frac = parts.next().unwrap_or("");
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !frac.bytes().all(|byte| byte.is_ascii_digit())
        || frac.len() > 8
    {
        return false;
    }
    let whole: u128 = whole.parse().unwrap_or(u128::MAX);
    let frac_digits: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse().unwrap_or(u128::MAX)
    };
    let scale = 10u128.pow((8 - frac.len()) as u32);
    let zat = whole
        .saturating_mul(100_000_000)
        .saturating_add(frac_digits.saturating_mul(scale));
    zat <= 2_100_000_000_000_000
}

fn base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let n = ((bytes[index] as u32) << 16)
            | ((bytes[index + 1] as u32) << 8)
            | bytes[index + 2] as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        index += 3;
    }
    if index < bytes.len() {
        let mut n = (bytes[index] as u32) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        if index + 1 < bytes.len() {
            n |= (bytes[index + 1] as u32) << 8;
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
        }
    }
    out
}

fn encode_query(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub fn propose(
    pczt: &[u8],
    mandate: &Mandate,
    ledger: &Ledger,
    now_unix: u64,
) -> Result<(InspectedPayment, Decision), String> {
    cosigner::decide_pczt(pczt, mandate, ledger, now_unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_uri_is_a_zip321_payment() {
        let uri = request_uri("u1vendor", "0.001", "invoice-1", Some("hello")).unwrap();
        assert!(uri.starts_with("zcash:u1vendor?amount=0.001&memo="));
        assert!(!uri.contains("zcash://"));
        assert!(uri.contains("&message=hello"));
        assert!(request_uri("t1abc", "1", "x", None).is_err());
    }

    #[test]
    fn a_signature_that_does_not_verify_is_not_applied() {
        let bytes = include_bytes!("../../pczt-inspect/tests/ironwood_v6.pczt");
        let spend = &pczt_inspect::pending_spends(bytes).unwrap()[0];
        let wrong = SpendSignature {
            pool: spend.pool,
            index: spend.index,
            signature: [1; 64],
        };
        let err = apply_signatures(bytes, &[wrong]).unwrap_err();
        assert!(err.contains("rejected"), "{err}");
        let missing = SpendSignature {
            pool: spend.pool,
            index: 999,
            signature: [1; 64],
        };
        assert!(apply_signatures(bytes, &[missing])
            .unwrap_err()
            .contains("no action"));
    }
}
