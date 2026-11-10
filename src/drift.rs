//! Comparing a re-derived payload with the last one delivered.
//!
//! A sweep re-derives every customer's state on a timer. Re-sending all of it
//! each time is noisy, and every payload carries a fresh timestamp, so a plain
//! string compare always reports a change. [`same_ignoring`] compares the two
//! as JSON with the timestamp field taken out.
//!
//! On the timestamp itself: take it when the Stripe fetch *starts*, not when
//! the result is derived. If the receiver keeps the highest timestamp it has
//! seen, a slow fetch stamped late can beat a faster, fresher one that began
//! after it, and the stale state wins. Stamping at fetch start keeps the
//! stamps in the same order as the data they describe.

/// True if `a` and `b` are the same JSON object once `field` is removed from
/// both. Anything that isn't a JSON object compares as different, which errs
/// toward re-sending.
pub fn same_ignoring(a: &str, b: &str, field: &str) -> bool {
    let strip = |s: &str| -> Option<serde_json::Value> {
        let mut v: serde_json::Value = serde_json::from_str(s).ok()?;
        v.as_object_mut()?.remove(field);
        Some(v)
    };
    match (strip(a), strip(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::same_ignoring;

    #[test]
    fn the_ignored_field_alone_is_not_drift() {
        assert!(same_ignoring(
            r#"{"plan":"pro","as_of":1}"#,
            r#"{"plan":"pro","as_of":2}"#,
            "as_of"
        ));
        assert!(!same_ignoring(
            r#"{"plan":"pro","as_of":1}"#,
            r#"{"plan":"free","as_of":2}"#,
            "as_of"
        ));
    }

    #[test]
    fn key_order_does_not_matter() {
        assert!(same_ignoring(r#"{"a":1,"b":2}"#, r#"{"b":2,"a":1}"#, "t"));
    }

    #[test]
    fn non_objects_always_differ() {
        assert!(!same_ignoring("[1]", "[1]", "t"));
        assert!(!same_ignoring("not json", "not json", "t"));
    }
}
