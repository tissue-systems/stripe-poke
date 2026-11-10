//! Stripe webhook signature verification.
//!
//! Scheme: `Stripe-Signature: t=<unix>,v1=<hex hmac>` where the MAC is
//! HMAC-SHA256(webhook_secret, "{t}.{raw_body}"). The raw body must be the
//! exact bytes Stripe sent, never a re-serialized JSON object.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq)]
pub enum VerifyError {
    MalformedHeader,
    StaleTimestamp,
    BadSignature,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VerifyError::MalformedHeader => "malformed Stripe-Signature header",
            VerifyError::StaleTimestamp => "signature timestamp outside tolerance",
            VerifyError::BadSignature => "no v1 signature matches",
        })
    }
}

impl std::error::Error for VerifyError {}

/// Verify a Stripe webhook signature. `now` is passed in for testability.
pub fn verify_signature(
    secret: &str,
    header: &str,
    raw_body: &[u8],
    now: i64,
    tolerance_secs: i64,
) -> Result<(), VerifyError> {
    let mut t: Option<i64> = None;
    let mut v1s: Vec<Vec<u8>> = Vec::new();

    for part in header.split(',') {
        let part = part.trim();
        if let Some(ts) = part.strip_prefix("t=") {
            t = ts.parse().ok();
        } else if let Some(sig) = part.strip_prefix("v1=") {
            if let Ok(bytes) = hex::decode(sig) {
                v1s.push(bytes);
            }
        }
        // other schemes (v0=...) are ignored
    }

    let t = t.ok_or(VerifyError::MalformedHeader)?;
    if v1s.is_empty() {
        return Err(VerifyError::MalformedHeader);
    }
    // abs_diff, not (now - t).abs(): an attacker-supplied t near i64::MIN
    // would overflow the subtraction (panic under debug assertions).
    if now.abs_diff(t) > tolerance_secs.unsigned_abs() {
        return Err(VerifyError::StaleTimestamp);
    }

    // signed_payload = "{t}.{raw_body}"
    let mut signed = t.to_string().into_bytes();
    signed.push(b'.');
    signed.extend_from_slice(raw_body);

    // Multiple v1 entries are legitimate during secret rotation; accept if ANY
    // matches. verify_slice is constant-time.
    for candidate in v1s {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
        mac.update(&signed);
        if mac.verify_slice(&candidate).is_ok() {
            return Ok(());
        }
    }
    Err(VerifyError::BadSignature)
}

/// Signer counterpart of `verify_signature` — used by unit and integration
/// tests to construct valid `Stripe-Signature` headers.
pub fn sign(secret: &str, raw_body: &[u8], t: i64) -> String {
    let mut signed = t.to_string().into_bytes();
    signed.push(b'.');
    signed.extend_from_slice(raw_body);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(&signed);
    format!("t={t},v1={}", hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_test_secret";
    const BODY: &[u8] = br#"{"id":"evt_1","type":"invoice.paid"}"#;

    #[test]
    fn accepts_valid_signature() {
        let h = sign(SECRET, BODY, 1_700_000_000);
        assert_eq!(
            verify_signature(SECRET, &h, BODY, 1_700_000_000, 300),
            Ok(())
        );
        // within tolerance
        assert_eq!(
            verify_signature(SECRET, &h, BODY, 1_700_000_299, 300),
            Ok(())
        );
    }

    #[test]
    fn rejects_wrong_secret() {
        let h = sign("whsec_other", BODY, 1_700_000_000);
        assert_eq!(
            verify_signature(SECRET, &h, BODY, 1_700_000_000, 300),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn rejects_tampered_body() {
        let h = sign(SECRET, BODY, 1_700_000_000);
        assert_eq!(
            verify_signature(SECRET, &h, br#"{"id":"evt_2"}"#, 1_700_000_000, 300),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn rejects_stale_timestamp_both_directions() {
        let h = sign(SECRET, BODY, 1_700_000_000);
        assert_eq!(
            verify_signature(SECRET, &h, BODY, 1_700_000_301, 300),
            Err(VerifyError::StaleTimestamp)
        );
        assert_eq!(
            verify_signature(SECRET, &h, BODY, 1_699_999_699, 300),
            Err(VerifyError::StaleTimestamp)
        );
    }

    #[test]
    fn rejects_malformed_headers() {
        for h in [
            "",
            "t=abc,v1=00",
            "v1=00",
            "t=1700000000",
            "t=1700000000,v1=zz",
        ] {
            assert_eq!(
                verify_signature(SECRET, h, BODY, 1_700_000_000, 300),
                Err(VerifyError::MalformedHeader),
                "header: {h}"
            );
        }
    }

    #[test]
    fn accepts_any_valid_v1_during_rotation() {
        let good = sign(SECRET, BODY, 1_700_000_000);
        let sig = good.split("v1=").nth(1).unwrap();
        // old-secret signature first, current second
        let h = format!("t=1700000000,v1={},v1={}", "ab".repeat(32), sig);
        assert_eq!(
            verify_signature(SECRET, &h, BODY, 1_700_000_000, 300),
            Ok(())
        );
    }
}
