//! Commands the agent share can run. The agent can propose a payment and can
//! hold one FROST share. It cannot spend alone.

use mandate::{Decision, InspectedPayment, Ledger, Mandate};

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
}
