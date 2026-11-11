//! A desired-state outbox: one queued payload per key, delivered until the
//! other side accepts it.
//!
//! Each payload is the whole state for its key, not a change to apply, so
//! only the newest one matters. Enqueueing a key that is already queued
//! replaces its payload and resets its attempts.
//!
//! The payload is enqueued before the first attempt, so a crash between the
//! two leaves a queued row rather than a lost update. [`enqueue_and_deliver`]
//! does it in that order and returns an error if the enqueue fails, so your
//! webhook can answer 500 instead of claiming the work is stored.
//!
//! [`Outbox::ack`] removes a row only if it still holds the payload that was
//! delivered. If a newer state was enqueued while an older one was in
//! flight, the older one's success leaves the newer row alone.
//!
//! [`Outbox::last_acked`] keeps the last payload the other side accepted, so
//! a sweep can compare a re-derived payload with it and re-send only when
//! something changed (see [`crate::drift`]).
//!
//! The receiving side should still guard against stale writes, for example
//! by keeping the highest timestamp it has seen per key. Retries and sweeps
//! mean a payload can arrive after a newer one.

use std::future::Future;

/// First retry delay after a failed delivery.
pub const BACKOFF_BASE_SECS: i64 = 30;
/// Longest delay between retries.
pub const BACKOFF_CAP_SECS: i64 = 900;

/// Delay before the next attempt for a row that has failed `attempts` times
/// so far: 30 s, then 60 s, 120 s and so on, up to 15 minutes.
pub fn backoff_secs(attempts: i64) -> i64 {
    let doublings = attempts.clamp(0, 5) as u32;
    (BACKOFF_BASE_SECS << doublings).min(BACKOFF_CAP_SECS)
}

/// A row waiting for delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    pub key: String,
    pub payload: String,
    pub attempts: i64,
}

/// Storage for the outbox. See [`crate::sqlite::SqliteOutbox`].
pub trait Outbox {
    type Error;
    /// Queue `payload` for `key`, replacing any queued payload and resetting
    /// its attempts. Due immediately.
    fn enqueue(&self, key: &str, payload: &str, now: i64) -> Result<(), Self::Error>;
    /// Rows whose next attempt is due at `now`.
    fn due(&self, now: i64) -> Result<Vec<Queued>, Self::Error>;
    /// Delivery of `payload` succeeded: drop the row if it still holds this
    /// payload, and remember it as the last acked state for `key`.
    fn ack(&self, key: &str, payload: &str, now: i64) -> Result<(), Self::Error>;
    /// Delivery failed: count the attempt and push the next one out by
    /// [`backoff_secs`].
    fn defer(&self, key: &str, now: i64) -> Result<(), Self::Error>;
    /// How many rows are queued.
    fn depth(&self) -> Result<i64, Self::Error>;
    /// The last payload acked for `key`.
    fn last_acked(&self, key: &str) -> Result<Option<String>, Self::Error>;
}

/// The other side: whatever accepts a payload. Return `Ok` only once the
/// receiver has durably taken it.
pub trait Sink {
    type Error;
    /// Send `payload` for `key`.
    fn deliver(
        &self,
        key: &str,
        payload: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// How one delivery attempt went. `SE` is the sink's error, `OE` the
/// outbox's. A bookkeeping error after the attempt is reported, not raised:
/// the worst it causes is one extra delivery of the same payload.
#[derive(Debug)]
pub enum Delivery<SE, OE> {
    /// The sink took it. `ack_error` is set if removing the row failed, in
    /// which case the payload is sent again on the next retry.
    Delivered { ack_error: Option<OE> },
    /// The sink refused it. `defer_error` is set if counting the attempt
    /// failed, in which case the row is retried without backing off.
    Failed { error: SE, defer_error: Option<OE> },
}

impl<SE, OE> Delivery<SE, OE> {
    /// True for [`Delivery::Delivered`].
    pub fn is_delivered(&self) -> bool {
        matches!(self, Delivery::Delivered { .. })
    }
}

/// Try one delivery of a payload that is already queued, then ack or defer
/// it. Call [`enqueue_and_deliver`] for a new payload.
pub async fn deliver<O, S>(
    outbox: &O,
    sink: &S,
    key: &str,
    payload: &str,
) -> Delivery<S::Error, O::Error>
where
    O: Outbox,
    S: Sink,
{
    let result = sink.deliver(key, payload).await;
    let now = crate::unix_now();
    match result {
        Ok(()) => Delivery::Delivered {
            ack_error: outbox.ack(key, payload, now).err(),
        },
        Err(error) => Delivery::Failed {
            error,
            defer_error: outbox.defer(key, now).err(),
        },
    }
}

/// Enqueue, then try once. An enqueue error comes back as `Err` and nothing
/// is sent. A failed attempt is not an error: the row stays queued for
/// [`retry_due`].
pub async fn enqueue_and_deliver<O, S>(
    outbox: &O,
    sink: &S,
    key: &str,
    payload: &str,
    now: i64,
) -> Result<Delivery<S::Error, O::Error>, O::Error>
where
    O: Outbox,
    S: Sink,
{
    outbox.enqueue(key, payload, now)?;
    Ok(deliver(outbox, sink, key, payload).await)
}

/// One pass over the rows due at `now`, in no particular order. Returns each
/// row with how its attempt went. Run it on a timer. Every 30 seconds
/// matches the first backoff step.
pub async fn retry_due<O, S>(
    outbox: &O,
    sink: &S,
    now: i64,
) -> Result<Vec<(Queued, Delivery<S::Error, O::Error>)>, O::Error>
where
    O: Outbox,
    S: Sink,
{
    let mut out = Vec::new();
    for row in outbox.due(now)? {
        let d = deliver(outbox, sink, &row.key, &row.payload).await;
        out.push((row, d));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let steps: Vec<i64> = (0..8).map(backoff_secs).collect();
        assert_eq!(steps, [30, 60, 120, 240, 480, 900, 900, 900]);
        assert_eq!(backoff_secs(-1), 30);
        assert_eq!(backoff_secs(i64::MAX), 900);
    }
}
