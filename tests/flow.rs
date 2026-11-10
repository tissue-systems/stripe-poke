//! End-to-end behaviour of the receive → handle → deliver path, against the
//! SQLite stores and an in-memory sink.

use rusqlite::Connection;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use stripe_poke::outbox::{self, Outbox, Sink};
use stripe_poke::signature::{sign, VerifyError};
use stripe_poke::sqlite::{OutboxNames, SharedConnection, SqliteLedger, SqliteOutbox};
use stripe_poke::webhook::{Event, Handled, Ledger, Outcome, Receiver};

const SECRET: &str = "whsec_test";

fn db() -> SharedConnection {
    Arc::new(Mutex::new(Connection::open_in_memory().unwrap()))
}

fn body(id: &str, customer: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "type": "customer.subscription.updated",
        "data": {"object": {"object": "subscription", "id": "sub_1", "customer": customer}}
    }))
    .unwrap()
}

/// A handler for deliveries that must stop before reaching it.
async fn must_not_run(event: Event) -> Result<Handled, ()> {
    panic!("handler ran for {}", event.id)
}

/// Records what it was sent; can be told to refuse.
#[derive(Default)]
struct Recorder {
    down: AtomicBool,
    sent: Mutex<Vec<(String, String)>>,
}

impl Sink for Recorder {
    type Error = &'static str;
    async fn deliver(&self, key: &str, payload: &str) -> Result<(), &'static str> {
        if self.down.load(Ordering::SeqCst) {
            return Err("receiver down");
        }
        self.sent.lock().unwrap().push((key.into(), payload.into()));
        Ok(())
    }
}

#[tokio::test]
async fn a_failed_handler_is_retried_whole_on_redelivery() {
    let conn = db();
    let ledger = SqliteLedger::open(conn, "stripe_events").unwrap();
    let rx = Receiver {
        secret: SECRET,
        tolerance_secs: 300,
        ledger: &ledger,
    };
    let now = stripe_poke::unix_now();
    let raw = body("evt_1", "cus_1");
    let header = sign(SECRET, &raw, now);
    let count = AtomicUsize::new(0);
    let runs = &count;

    // First delivery: the handler fails (say Stripe was unreachable).
    let first = rx
        .receive(&header, &raw, now, |_| async {
            runs.fetch_add(1, Ordering::SeqCst);
            Err::<Handled, _>("stripe unreachable")
        })
        .await;
    assert!(matches!(first, Outcome::Failed("stripe unreachable")));
    assert_eq!(first.status(), 500);
    assert!(
        !ledger.seen("evt_1").unwrap(),
        "a failed event must not be recorded"
    );

    // Stripe redelivers. It must run again, not short-circuit as a duplicate.
    let second = rx
        .receive(&header, &raw, now, |e| async move {
            runs.fetch_add(1, Ordering::SeqCst);
            assert_eq!(e.customer_id(), Some("cus_1"));
            Ok::<_, ()>(Handled::Processed)
        })
        .await;
    assert!(matches!(
        second,
        Outcome::Done {
            handled: Handled::Processed,
            record_error: None
        }
    ));
    assert_eq!(runs.load(Ordering::SeqCst), 2);
    assert!(ledger.seen("evt_1").unwrap());

    // A third delivery is a duplicate and never reaches the handler.
    let third = rx.receive(&header, &raw, now, must_not_run).await;
    assert!(matches!(third, Outcome::Duplicate));
    assert_eq!(third.status(), 200);
}

#[tokio::test]
async fn bad_signatures_never_reach_the_ledger_or_the_handler() {
    let ledger = SqliteLedger::open(db(), "stripe_events").unwrap();
    let rx = Receiver {
        secret: SECRET,
        tolerance_secs: 300,
        ledger: &ledger,
    };
    let now = stripe_poke::unix_now();
    let raw = body("evt_1", "cus_1");

    let forged = sign("whsec_other", &raw, now);
    let stale = sign(SECRET, &raw, now - 3600);
    for (header, want) in [
        (forged.as_str(), VerifyError::BadSignature),
        (stale.as_str(), VerifyError::StaleTimestamp),
        ("", VerifyError::MalformedHeader),
    ] {
        let out = rx.receive(header, &raw, now, must_not_run).await;
        assert_eq!(out.status(), 400);
        assert!(
            matches!(out, Outcome::Invalid(ref e) if *e == want),
            "{header:?}"
        );
    }
    assert!(!ledger.seen("evt_1").unwrap());
}

#[tokio::test]
async fn a_signed_body_that_is_not_an_event_is_unparseable() {
    let ledger = SqliteLedger::open(db(), "stripe_events").unwrap();
    let rx = Receiver {
        secret: SECRET,
        tolerance_secs: 300,
        ledger: &ledger,
    };
    let now = stripe_poke::unix_now();
    let raw = br#"{"hello":"world"}"#;
    let out = rx
        .receive(&sign(SECRET, raw, now), raw, now, |_| async {
            Ok::<_, ()>(Handled::Processed)
        })
        .await;
    assert!(matches!(out, Outcome::Unparseable));
}

#[tokio::test]
async fn ignored_events_are_recorded_too() {
    let ledger = SqliteLedger::open(db(), "stripe_events").unwrap();
    let rx = Receiver {
        secret: SECRET,
        tolerance_secs: 300,
        ledger: &ledger,
    };
    let now = stripe_poke::unix_now();
    let raw = body("evt_9", "cus_1");
    let out = rx
        .receive(&sign(SECRET, &raw, now), &raw, now, |_| async {
            Ok::<_, ()>(Handled::Ignored)
        })
        .await;
    assert!(matches!(
        out,
        Outcome::Done {
            handled: Handled::Ignored,
            record_error: None
        }
    ));
    assert!(ledger.seen("evt_9").unwrap());
}

#[tokio::test]
async fn nothing_is_lost_while_the_receiver_is_down() {
    let ob = SqliteOutbox::open(db(), &OutboxNames::default()).unwrap();
    let sink = Recorder::default();
    sink.down.store(true, Ordering::SeqCst);

    let d = outbox::enqueue_and_deliver(&ob, &sink, "acct_1", r#"{"plan":"pro"}"#, 1000)
        .await
        .unwrap();
    assert!(!d.is_delivered());
    assert_eq!(ob.depth().unwrap(), 1, "the failed payload stays queued");
    assert_eq!(ob.last_acked("acct_1").unwrap(), None);

    sink.down.store(false, Ordering::SeqCst);
    let far = stripe_poke::unix_now() + 3600;
    let results = outbox::retry_due(&ob, &sink, far).await.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].1.is_delivered());
    assert_eq!(ob.depth().unwrap(), 0);
    assert_eq!(
        ob.last_acked("acct_1").unwrap().as_deref(),
        Some(r#"{"plan":"pro"}"#)
    );
    assert_eq!(
        sink.sent.lock().unwrap().as_slice(),
        [("acct_1".into(), r#"{"plan":"pro"}"#.into())]
    );
}

#[test]
fn queue_lifecycle_and_backoff() {
    let ob = SqliteOutbox::open(db(), &OutboxNames::default()).unwrap();
    ob.enqueue("acct_1", r#"{"plan":"pro"}"#, 1000).unwrap();
    assert_eq!(ob.depth().unwrap(), 1);
    assert_eq!(ob.due(1000).unwrap()[0].attempts, 0);

    // Each failure pushes the next attempt out: 30 s, then 60 s.
    ob.defer("acct_1", 1000).unwrap();
    assert!(ob.due(1029).unwrap().is_empty());
    assert_eq!(ob.due(1030).unwrap().len(), 1);
    ob.defer("acct_1", 1030).unwrap();
    assert!(ob.due(1089).unwrap().is_empty());
    assert_eq!(ob.due(1090).unwrap()[0].attempts, 2);

    // A newer payload replaces the queued one and resets the attempts.
    ob.enqueue("acct_1", r#"{"plan":"free"}"#, 2000).unwrap();
    let due = ob.due(2000).unwrap();
    assert_eq!(
        (due[0].attempts, due[0].payload.as_str()),
        (0, r#"{"plan":"free"}"#)
    );

    // Deferring a key that isn't queued is a no-op.
    ob.defer("acct_none", 2000).unwrap();
    assert_eq!(ob.depth().unwrap(), 1);
}

#[test]
fn ack_does_not_clobber_a_newer_enqueue() {
    let ob = SqliteOutbox::open(db(), &OutboxNames::default()).unwrap();
    ob.enqueue("acct_1", "v1", 1000).unwrap();
    // v2 lands while v1 is in flight...
    ob.enqueue("acct_1", "v2", 1001).unwrap();
    // ...then v1's delivery succeeds. v2 must still be queued.
    ob.ack("acct_1", "v1", 1002).unwrap();
    assert_eq!(ob.depth().unwrap(), 1);
    assert_eq!(ob.due(2000).unwrap()[0].payload, "v2");
    assert_eq!(ob.last_acked("acct_1").unwrap().as_deref(), Some("v1"));
}

#[test]
fn ledger_records_each_id_once() {
    let ledger = SqliteLedger::open(db(), "stripe_events").unwrap();
    assert!(!ledger.seen("evt_1").unwrap());
    assert!(ledger.record("evt_1", "invoice.paid").unwrap());
    assert!(!ledger.record("evt_1", "invoice.paid").unwrap());
    assert!(ledger.seen("evt_1").unwrap());
    assert!(!ledger.seen("evt_2").unwrap());
}

#[test]
fn an_existing_schema_is_adopted_by_name() {
    let conn = db();
    conn.lock()
        .unwrap()
        .execute_batch(
            "CREATE TABLE push_queue (account_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
               attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL DEFAULT 0,
               updated_at INTEGER NOT NULL);
             INSERT INTO push_queue VALUES ('acct_old', 'p', 3, 0, 1);
             CREATE TABLE pushed_state (account_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
               pushed_at INTEGER NOT NULL);",
        )
        .unwrap();
    let ob = SqliteOutbox::open(
        conn,
        &OutboxNames {
            queue_table: "push_queue",
            acked_table: "pushed_state",
            key_column: "account_id",
            acked_at_column: "pushed_at",
        },
    )
    .unwrap();
    let due = ob.due(10).unwrap();
    assert_eq!((due[0].key.as_str(), due[0].attempts), ("acct_old", 3));
    ob.ack("acct_old", "p", 11).unwrap();
    assert_eq!(ob.last_acked("acct_old").unwrap().as_deref(), Some("p"));
}

#[test]
fn names_must_be_plain_identifiers() {
    for bad in ["", "1table", "t; DROP TABLE x", "a-b", "t\"q"] {
        assert!(SqliteLedger::open(db(), bad).is_err(), "{bad:?}");
        let names = OutboxNames {
            queue_table: bad,
            ..OutboxNames::default()
        };
        assert!(SqliteOutbox::open(db(), &names).is_err(), "{bad:?}");
    }
}
