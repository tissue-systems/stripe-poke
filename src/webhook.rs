//! Receiving a Stripe webhook as a poke.
//!
//! [`Receiver::receive`] runs the steps in the one order that loses nothing:
//!
//! 1. Verify the signature over the raw body. Nothing is parsed before this.
//! 2. Parse the envelope.
//! 3. *Check* the ledger for the event id. A hit answers "duplicate".
//! 4. Run your handler, which should re-fetch from Stripe rather than trust
//!    the payload.
//! 5. *Record* the id, and only if the handler succeeded.
//!
//! Recording at step 3 instead is the tempting mistake. Stripe retries an
//! event when you answer 5xx, but a handler that failed after its id was
//! recorded turns that retry into a "duplicate", and the change is lost until
//! something else notices. Checking first and recording last does mean two
//! concurrent deliveries of one id can both run the handler. That's fine as
//! long as the handler is a poke: fetch the truth, derive, deliver. Running it
//! twice gives the same answer.

use crate::signature::{verify_signature, VerifyError};
use serde::Deserialize;
use std::future::Future;

/// The parts of a Stripe event envelope this crate reads. `data.object` is
/// left as raw JSON; read only identifiers out of it.
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: EventData,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EventData {
    pub object: serde_json::Value,
}

impl Event {
    pub fn object(&self) -> &serde_json::Value {
        &self.data.object
    }

    /// The Stripe customer this event is about, if it names one. Most objects
    /// carry it in `customer`; `customer.*` events are the customer object
    /// itself, so the id is `object.id` there.
    pub fn customer_id(&self) -> Option<&str> {
        let obj = &self.data.object;
        if let Some(c) = obj.get("customer").and_then(|c| c.as_str()) {
            return Some(c);
        }
        if self.event_type.starts_with("customer.")
            && obj.get("object").and_then(|o| o.as_str()) == Some("customer")
        {
            return obj.get("id").and_then(|i| i.as_str());
        }
        None
    }
}

/// Where handled event ids are kept. See [`crate::sqlite::SqliteLedger`].
pub trait Ledger {
    type Error;
    /// True if this id was already handled to completion.
    fn seen(&self, id: &str) -> Result<bool, Self::Error>;
    /// Record a handled id. Returns true if it was not there before.
    fn record(&self, id: &str, event_type: &str) -> Result<bool, Self::Error>;
}

/// What a successful handler did with the event. Both are recorded in the
/// ledger, so a redelivery of either answers "duplicate".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handled {
    /// The handler refreshed something.
    Processed,
    /// Nothing to do for this event (no customer in it, a type you don't act
    /// on). Recorded anyway so replays stop early.
    Ignored,
}

/// How [`Receiver::receive`] ended. `E` is your handler's error, `LE` the ledger's.
#[derive(Debug)]
pub enum Outcome<E, LE> {
    /// The signature didn't check out. Answer 400: Stripe treats a 4xx as
    /// "don't retry", which is right for a forgery.
    Invalid(VerifyError),
    /// Verified, but not an event envelope.
    Unparseable,
    /// Already handled. Answer 200 so Stripe stops sending it.
    Duplicate,
    /// The ledger couldn't be read, so we can't tell whether this is a
    /// duplicate. Answer 500 and let Stripe retry.
    LedgerUnavailable(LE),
    /// The handler succeeded. `record_error` is set if writing the id
    /// failed afterwards; the work is done, so answer 200 anyway. The cost
    /// is one redundant redelivery, which the handler absorbs.
    Done {
        handled: Handled,
        record_error: Option<LE>,
    },
    /// The handler failed and the id was not recorded. Answer 5xx so Stripe
    /// redelivers.
    Failed(E),
}

impl<E, LE> Outcome<E, LE> {
    /// The HTTP status to answer Stripe with.
    pub fn status(&self) -> u16 {
        match self {
            Outcome::Invalid(_) | Outcome::Unparseable => 400,
            Outcome::Duplicate | Outcome::Done { .. } => 200,
            Outcome::LedgerUnavailable(_) | Outcome::Failed(_) => 500,
        }
    }
}

/// The settings [`Receiver::receive`] needs besides the request itself.
#[derive(Debug, Clone, Copy)]
pub struct Receiver<'a, L> {
    /// The endpoint's signing secret (`whsec_…`).
    pub secret: &'a str,
    /// How far `t=` may be from now. Stripe's own libraries use 300 seconds.
    pub tolerance_secs: i64,
    pub ledger: &'a L,
}

impl<'a, L: Ledger> Receiver<'a, L> {
    /// Run one delivery through the steps in the module docs. `header` is the
    /// `Stripe-Signature` value ("" if absent), `body` the raw request bytes,
    /// `now` the current Unix time.
    pub async fn receive<F, Fut, E>(
        &self,
        header: &str,
        body: &[u8],
        now: i64,
        handler: F,
    ) -> Outcome<E, L::Error>
    where
        F: FnOnce(Event) -> Fut,
        Fut: Future<Output = Result<Handled, E>>,
    {
        if let Err(e) = verify_signature(self.secret, header, body, now, self.tolerance_secs) {
            return Outcome::Invalid(e);
        }
        let Ok(event) = serde_json::from_slice::<Event>(body) else {
            return Outcome::Unparseable;
        };
        match self.ledger.seen(&event.id) {
            Ok(false) => {}
            Ok(true) => return Outcome::Duplicate,
            Err(e) => return Outcome::LedgerUnavailable(e),
        }
        let id = event.id.clone();
        let event_type = event.event_type.clone();
        match handler(event).await {
            Ok(handled) => Outcome::Done {
                handled,
                record_error: self.ledger.record(&id, &event_type).err(),
            },
            Err(e) => Outcome::Failed(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(json: serde_json::Value) -> Event {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn customer_from_object_field() {
        let e = event(serde_json::json!({
            "id": "evt_1", "type": "invoice.paid",
            "data": {"object": {"object": "invoice", "id": "in_1", "customer": "cus_1"}}
        }));
        assert_eq!(e.customer_id(), Some("cus_1"));
    }

    #[test]
    fn customer_events_use_the_object_id() {
        let e = event(serde_json::json!({
            "id": "evt_1", "type": "customer.deleted",
            "data": {"object": {"object": "customer", "id": "cus_9"}}
        }));
        assert_eq!(e.customer_id(), Some("cus_9"));
    }

    #[test]
    fn an_object_id_is_not_a_customer_outside_customer_events() {
        let e = event(serde_json::json!({
            "id": "evt_1", "type": "product.updated",
            "data": {"object": {"object": "product", "id": "prod_1"}}
        }));
        assert_eq!(e.customer_id(), None);
    }
}
