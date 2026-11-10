# stripe-poke

The plumbing for treating Stripe webhooks as pokes, without the business logic.

A poke means you don't apply what the webhook body says. You check the
signature, pull the customer id out, fetch the current state from Stripe, work
out what that customer should have, and send the whole result to whatever
needs to know. Stripe doesn't promise ordering, and a stale or replayed event
can't set state if you never read state from it.

The code is small. The ordering is what's easy to get wrong:

- **Check the event id first, record it last.** The id goes into the ledger
  only after your handler succeeds. If you record it on arrival and the
  handler fails, you answer 500, Stripe redelivers, and the redelivery hits
  your own row and gets "duplicate". The event is gone until something else
  notices. `webhook::Receiver` does the check, runs your handler, and records
  only on `Ok`.
- **Enqueue before the first delivery attempt.** If the process dies between
  the two, the payload is still queued. If the enqueue itself fails,
  `outbox::enqueue_and_deliver` returns `Err` so your webhook can answer 500.
  Otherwise it would claim work is stored when it isn't.
- **Ack only an unchanged payload.** If a newer state is queued while an
  older one is in flight, the older one's success mustn't delete the newer
  row.
- **Stamp `as_of` when the Stripe fetch starts**, not when you finish
  deriving. If you stamp late, a slow fetch can beat a faster, fresher one
  on a receiver that keeps the highest stamp. `drift::same_ignoring` compares
  a re-derived payload with the last acked one so a periodic sweep re-sends
  only on real drift.

## What's in it

| Module | |
|---|---|
| `signature` | `verify_signature` / `sign` for the `Stripe-Signature` header (v1 scheme, timestamp tolerance, constant-time compare) |
| `webhook` | `Receiver::receive`: verify → parse → seen? → your handler → record. Returns an `Outcome` with the HTTP status to answer |
| `outbox` | Desired-state queue, one payload per key, latest wins. Backoff 30 s doubling to 15 min. `Sink` is the other end |
| `drift` | JSON compare that ignores one field |
| `sqlite` | `SqliteLedger` and `SqliteOutbox` on a shared `rusqlite` connection, with table and column names you choose (feature `sqlite`, on by default) |

It doesn't do HTTP and doesn't spawn anything. You bring the web framework,
the HTTP client for your `Sink`, and the timer that calls `outbox::retry_due`.

## Using it

```rust
let rx = Receiver { secret: &webhook_secret, tolerance_secs: 300, ledger: &ledger };
let outcome = rx
    .receive(sig_header, &raw_body, stripe_poke::unix_now(), |event| async move {
        let Some(customer) = event.customer_id() else { return Ok(Handled::Ignored) };
        let state = derive(fetch_from_stripe(customer).await?);
        outbox::enqueue_and_deliver(&outbox, &sink, &state.key, &state.json, now).await?;
        Ok(Handled::Processed)
    })
    .await;
// outcome.status() is the code to answer Stripe with.
```

Your receiving side should still keep the highest `as_of` it has seen per
key and drop anything older. Retries and sweeps mean a payload can arrive
after a newer one, and the queue can't prevent that.

## Status

Extracted from atp, the Tissue Cloud billing gateway, which depends on it.
Not on crates.io yet.

## License

MIT or Apache-2.0, at your option.
