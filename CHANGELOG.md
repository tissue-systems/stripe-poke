# Changelog

## 0.1.2

Docs only. `Outcome::Invalid` said Stripe doesn't retry a 4xx. It does:
Stripe retries any answer that isn't a 2xx.

## 0.1.1

First release on crates.io. Same behaviour as 0.1.0. The README explains
what a poke is, the crate docs have an example that runs as a test, and
`VerifyError` derives `Clone`, `Copy` and `Eq`.

## 0.1.0

First version, extracted from atp, the Tissue Cloud billing gateway.
Signature check, webhook receiver with check-first record-last ordering,
desired-state outbox with backoff, drift compare, and SQLite stores.
