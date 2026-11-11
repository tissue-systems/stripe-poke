# stripe-poke

Plumbing for handling Stripe webhooks as pokes. The business logic stays in
your code.

## What a poke is

Most webhook handlers read the event body and apply it: a
`customer.subscription.updated` event says the plan is Pro, so you set Pro.
That only works if events arrive once and in order, and Stripe promises
neither. It retries for up to three days, it can send the same event twice,
and two events about one customer can arrive in either order. Picture a
customer who upgrades and then cancels a minute later. If the upgrade event
is retried and lands after the cancellation, a handler that applies bodies
gives the cancelled customer Pro again.

A poke handler uses the event as a doorbell. It reads one thing out of the
body, which customer it's about, and ignores the rest. Then it asks Stripe
for that customer's subscriptions as they are right now, works out what the
customer should have, and sends that whole state on to whatever needs it.
The late upgrade event in the example still rings the bell, but the fetch
comes back cancelled, so nothing goes wrong.

The handler then gives the same answer however many times it runs and in
whatever order the events come. That gets you three things:

- Duplicates and concurrent deliveries do no harm. Running the handler twice
  sends the same state twice.
- A missed webhook isn't permanent. A timer that runs the same refresh for
  every customer fixes anything a lost event left wrong, and it's the same
  code path, so there's nothing extra to test.
- What you send downstream is a full desired state ("account 42 is on Pro,
  20 seats"), not a change ("add 5 seats"). A queue of desired states only
  needs the newest entry per account, and re-sending one is safe.

The cost is one extra Stripe API call per event.

## Where it goes wrong

The code is small. The order of operations is what's easy to get wrong, and
this crate fixes it in place.

Check the event id first and record it last. The id goes into the ledger
only after your handler succeeds. If you record it on arrival and the handler
fails, you answer 500 and Stripe redelivers, but the redelivery finds your own
row and is treated as a duplicate. The event is lost until something else
notices. `webhook::Receiver` checks, runs your handler, and records only on
`Ok`.

Enqueue before the first delivery attempt. If the process dies between the
two, the payload is still queued. If the enqueue itself fails,
`outbox::enqueue_and_deliver` returns `Err` so your webhook can answer 500
instead of claiming the work is stored.

Ack only an unchanged payload. If a newer state is queued while an older one
is in flight, the older one's success mustn't delete the newer row.

Stamp `as_of` when the Stripe fetch starts, not when you finish deriving. If
you stamp late, a slow fetch can beat a faster, fresher one on a receiver that
keeps the highest stamp. `drift::same_ignoring` compares a re-derived payload
with the last acked one, so the timer only re-sends when something changed.

## Modules

- `signature`: `verify_signature` and `sign` for the `Stripe-Signature`
  header (v1 scheme, timestamp tolerance, constant-time compare).
- `webhook`: `Receiver::receive` verifies, parses, skips ids already handled,
  runs your handler and records the id. It returns an `Outcome` that knows
  the HTTP status to answer with.
- `outbox`: the desired-state queue, one payload per key, newest wins.
  Retries back off from 30 seconds, doubling up to 15 minutes. You implement
  `Sink` for the receiving end.
- `drift`: a JSON compare that ignores one field.
- `sqlite`: `SqliteLedger` and `SqliteOutbox` on a shared `rusqlite`
  connection, with table and column names you choose. Behind the `sqlite`
  feature, which is on by default.

It doesn't do HTTP and doesn't spawn anything. You bring the web framework,
the HTTP client for your `Sink`, and the timer that calls `outbox::retry_due`.

## Example

```rust
let rx = Receiver { secret: &webhook_secret, tolerance_secs: 300, ledger: &ledger };
let outcome = rx
    .receive(sig_header, &raw_body, stripe_poke::unix_now(), |event| async move {
        let Some(customer) = event.customer_id() else { return Ok(Handled::Ignored) };
        let as_of = stripe_poke::unix_now();
        let state = derive(fetch_from_stripe(customer).await?, as_of);
        outbox::enqueue_and_deliver(&outbox, &sink, &state.key, &state.json, as_of).await?;
        Ok(Handled::Processed)
    })
    .await;
// outcome.status() is the code to answer Stripe with.
```

The crate docs have a version of this that compiles.

Your receiving side should still keep the highest `as_of` it has seen per
key and drop anything older. Retries and the timer mean a payload can arrive
after a newer one, and the queue can't prevent that.

## Status

Extracted from atp, the Tissue Cloud billing gateway, which depends on it.

## License

MIT or Apache-2.0, at your option.
