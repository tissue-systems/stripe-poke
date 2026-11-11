//! Stripe webhook signature verification.
//!
//! Scheme: `Stripe-Signature: t=<unix>,v1=<hex hmac>` where the MAC is
//! HMAC-SHA256(webhook_secret, "{t}.{raw_body}"). The raw body must be the
//! exact bytes Stripe sent, never a re-serialized JSON object.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Why a `Stripe-Signature` header was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// No `t=` timestamp, or no `v1=` entry that decodes as hex.
    MalformedHeader,
    /// The timestamp is further from `now` than the tolerance allows.
    StaleTimestamp,
    /// No `v1=` entry matches the body signed with this secret.
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

/// Check a `Stripe-Signature` header against the raw request body.
///
/// `now` is the current Unix time, taken as an argument so tests can pin it.
/// Stripe's own libraries use a `tolerance_secs` of 300.
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
        // Other schemes (v0= in test mode) are skipped.
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

    // While a secret is being rolled, Stripe sends one v1 entry per secret,
    // so any match will do. verify_slice compares in constant time.
    let mac = mac(secret, t, raw_body);
    if v1s
        .iter()
        .any(|candidate| mac.clone().verify_slice(candidate).is_ok())
    {
        Ok(())
    } else {
        Err(VerifyError::BadSignature)
    }
}

/// Build a valid `Stripe-Signature` header for `raw_body` at time `t`. Meant
/// for tests: Stripe signs real deliveries itself.
pub fn sign(secret: &str, raw_body: &[u8], t: i64) -> String {
    let tag = mac(secret, t, raw_body).finalize().into_bytes();
    format!("t={t},v1={}", hex::encode(tag))
}

/// HMAC-SHA256 over Stripe's signed payload, `"{t}.{raw_body}"`.
fn mac(secret: &str, t: i64, raw_body: &[u8]) -> HmacSha256 {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC takes a key of any length");
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    mac
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
        // A signature from the secret being retired first, the live one second.
        let h = format!("t=1700000000,v1={},v1={}", "ab".repeat(32), sig);
        assert_eq!(
            verify_signature(SECRET, &h, BODY, 1_700_000_000, 300),
            Ok(())
        );
    }
}
