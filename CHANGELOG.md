# Changelog

## Unreleased

rusqlite 0.41, which needs Rust 1.89, so `rust-version` goes from 1.88 to 1.89.
rusqlite's types are in the public API of the `sqlite` module, so this goes
out as 0.2.0.

## 0.1.2

Docs only, released from the `0.1.x` branch. `Outcome::Invalid` said Stripe
doesn't retry a 4xx. It does: Stripe retries any answer that isn't a 2xx.

## 0.1.1

First release on crates.io. Same behaviour as 0.1.0. The README explains
what a poke is, the crate docs have an example that runs as a test, and
`VerifyError` derives `Clone`, `Copy` and `Eq`.

## 0.1.0

First version, extracted from atp, the Tissue Cloud billing gateway.
Signature check, webhook receiver with check-first record-last ordering,
desired-state outbox with backoff, drift compare, and SQLite stores.
