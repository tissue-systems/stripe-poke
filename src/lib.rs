//! Keep your own system in step with Stripe by treating each webhook as a
//! poke rather than as data.
//!
//! A Stripe webhook can arrive late, twice, out of order, or with a body
//! that no longer matches what Stripe holds. So this crate never applies the
//! payload. A verified event only tells you *which* customer changed. You
//! re-fetch that customer from Stripe, derive the state your system needs,
//! and hand it to a durable outbox that delivers it until your side accepts
//! it. A periodic sweep runs the same refresh for every customer, which heals
//! anything a lost webhook or a lost queue row left behind.
//!
//! The pieces, in the order a request meets them:
//!
//! - [`signature`]: `Stripe-Signature` verification over the raw body.
//! - [`webhook::Receiver::receive`]: verify, parse, skip ids already handled, run your
//!   handler, and record the id only once the handler succeeded.
//! - [`outbox`]: one queued payload per key, newest wins, enqueued before the
//!   first delivery attempt and acked only if it was not replaced meanwhile.
//! - [`drift::same_ignoring`]: tells a sweep whether a re-derived payload
//!   differs from the last one delivered, ignoring the timestamp field.
//! - [`sqlite`] (default feature): SQLite implementations of the
//!   [`webhook::Ledger`] and [`outbox::Outbox`] traits.
//!
//! The crate does no HTTP and starts no tasks. You call it from your own
//! handler, implement [`outbox::Sink`] with your own client, and run
//! [`outbox::retry_due`] and your sweep on whatever timer you already have.

pub mod drift;
pub mod outbox;
pub mod signature;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod webhook;

/// Seconds since the Unix epoch. A clock set before 1970 reads as 0, which
/// fails closed for signature checks: every Stripe timestamp is then outside
/// the tolerance window.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
