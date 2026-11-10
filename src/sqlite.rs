//! SQLite implementations of [`Ledger`] and [`Outbox`].
//!
//! Both take a shared `Arc<Mutex<Connection>>`, so they can live in the same
//! database file as the rest of your state and share its connection. Each
//! creates its tables if they're missing. The names are configurable, so a
//! schema you already have can be adopted as long as it has these columns.
//!
//! Calls are blocking. That's normal for SQLite on a local disk, but if your
//! runtime cares, call them from a blocking-friendly context.

use crate::outbox::{backoff_secs, Outbox, Queued};
use crate::webhook::Ledger;
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// A connection shared between these stores and your own code.
pub type SharedConnection = Arc<Mutex<Connection>>;

fn lock(conn: &SharedConnection) -> MutexGuard<'_, Connection> {
    // Every write here is a single statement, so a panic elsewhere while the
    // lock was held can't have left one half-applied.
    conn.lock().unwrap_or_else(PoisonError::into_inner)
}

fn ident(name: &str) -> rusqlite::Result<&str> {
    let mut chars = name.chars();
    let ok = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(name)
    } else {
        Err(rusqlite::Error::InvalidParameterName(format!(
            "{name:?} is not a plain SQL identifier"
        )))
    }
}

/// Handled event ids, one row each:
/// `(id TEXT PRIMARY KEY, type TEXT, processed_at TEXT)`.
pub struct SqliteLedger {
    conn: SharedConnection,
    sql_seen: String,
    sql_record: String,
}

impl SqliteLedger {
    /// Use (and create if missing) the ledger table `table`.
    pub fn open(conn: SharedConnection, table: &str) -> rusqlite::Result<SqliteLedger> {
        let t = ident(table)?;
        lock(&conn).execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {t} (
               id           TEXT PRIMARY KEY,
               type         TEXT NOT NULL,
               processed_at TEXT NOT NULL DEFAULT (datetime('now'))
             );"
        ))?;
        Ok(SqliteLedger {
            sql_seen: format!("SELECT id FROM {t} WHERE id = ?1"),
            sql_record: format!("INSERT OR IGNORE INTO {t} (id, type) VALUES (?1, ?2)"),
            conn,
        })
    }
}

impl Ledger for SqliteLedger {
    type Error = rusqlite::Error;

    fn seen(&self, id: &str) -> rusqlite::Result<bool> {
        let hit: Option<String> = lock(&self.conn)
            .query_row(&self.sql_seen, params![id], |r| r.get(0))
            .optional()?;
        Ok(hit.is_some())
    }

    fn record(&self, id: &str, event_type: &str) -> rusqlite::Result<bool> {
        let changed = lock(&self.conn).execute(&self.sql_record, params![id, event_type])?;
        Ok(changed == 1)
    }
}

/// Table and column names for [`SqliteOutbox`].
#[derive(Debug, Clone)]
pub struct OutboxNames<'a> {
    /// The queue: `(key PRIMARY KEY, payload, attempts, next_attempt_at, updated_at)`.
    pub queue_table: &'a str,
    /// Last acked payload per key: `(key PRIMARY KEY, payload, acked_at)`.
    pub acked_table: &'a str,
    /// Name of the key column in both tables.
    pub key_column: &'a str,
    /// Name of the timestamp column in the acked table.
    pub acked_at_column: &'a str,
}

impl Default for OutboxNames<'_> {
    fn default() -> Self {
        OutboxNames {
            queue_table: "poke_outbox",
            acked_table: "poke_acked",
            key_column: "key",
            acked_at_column: "acked_at",
        }
    }
}

struct OutboxSql {
    enqueue: String,
    due: String,
    ack_delete: String,
    ack_record: String,
    attempts: String,
    defer: String,
    depth: String,
    last_acked: String,
}

pub struct SqliteOutbox {
    conn: SharedConnection,
    sql: OutboxSql,
}

impl SqliteOutbox {
    /// Use (and create if missing) the outbox tables named in `names`.
    pub fn open(conn: SharedConnection, names: &OutboxNames<'_>) -> rusqlite::Result<SqliteOutbox> {
        let q = ident(names.queue_table)?;
        let a = ident(names.acked_table)?;
        let k = ident(names.key_column)?;
        let at = ident(names.acked_at_column)?;
        lock(&conn).execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {q} (
               {k}             TEXT PRIMARY KEY,
               payload         TEXT NOT NULL,
               attempts        INTEGER NOT NULL DEFAULT 0,
               next_attempt_at INTEGER NOT NULL DEFAULT 0,
               updated_at      INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS {a} (
               {k}     TEXT PRIMARY KEY,
               payload TEXT NOT NULL,
               {at}    INTEGER NOT NULL
             );"
        ))?;
        let sql = OutboxSql {
            enqueue: format!(
                "INSERT INTO {q} ({k}, payload, attempts, next_attempt_at, updated_at)
                 VALUES (?1, ?2, 0, ?3, ?3)
                 ON CONFLICT({k}) DO UPDATE SET
                   payload = excluded.payload, attempts = 0,
                   next_attempt_at = excluded.next_attempt_at, updated_at = excluded.updated_at"
            ),
            due: format!("SELECT {k}, payload, attempts FROM {q} WHERE next_attempt_at <= ?1"),
            ack_delete: format!("DELETE FROM {q} WHERE {k} = ?1 AND payload = ?2"),
            ack_record: format!(
                "INSERT INTO {a} ({k}, payload, {at}) VALUES (?1, ?2, ?3)
                 ON CONFLICT({k}) DO UPDATE SET payload = excluded.payload, {at} = excluded.{at}"
            ),
            attempts: format!("SELECT attempts FROM {q} WHERE {k} = ?1"),
            defer: format!(
                "UPDATE {q} SET attempts = attempts + 1, next_attempt_at = ?2 + ?3 WHERE {k} = ?1"
            ),
            depth: format!("SELECT COUNT(*) FROM {q}"),
            last_acked: format!("SELECT payload FROM {a} WHERE {k} = ?1"),
        };
        Ok(SqliteOutbox { conn, sql })
    }
}

impl Outbox for SqliteOutbox {
    type Error = rusqlite::Error;

    fn enqueue(&self, key: &str, payload: &str, now: i64) -> rusqlite::Result<()> {
        lock(&self.conn).execute(&self.sql.enqueue, params![key, payload, now])?;
        Ok(())
    }

    fn due(&self, now: i64) -> rusqlite::Result<Vec<Queued>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(&self.sql.due)?;
        let rows = stmt
            .query_map(params![now], |r| {
                Ok(Queued {
                    key: r.get(0)?,
                    payload: r.get(1)?,
                    attempts: r.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn ack(&self, key: &str, payload: &str, now: i64) -> rusqlite::Result<()> {
        let conn = lock(&self.conn);
        conn.execute(&self.sql.ack_delete, params![key, payload])?;
        conn.execute(&self.sql.ack_record, params![key, payload, now])?;
        Ok(())
    }

    fn defer(&self, key: &str, now: i64) -> rusqlite::Result<()> {
        let conn = lock(&self.conn);
        // The delay depends on the row's own attempt count, so read it under
        // the same lock as the update.
        let attempts: Option<i64> = conn
            .query_row(&self.sql.attempts, params![key], |r| r.get(0))
            .optional()?;
        if let Some(attempts) = attempts {
            conn.execute(&self.sql.defer, params![key, now, backoff_secs(attempts)])?;
        }
        Ok(())
    }

    fn depth(&self) -> rusqlite::Result<i64> {
        lock(&self.conn).query_row(&self.sql.depth, [], |r| r.get(0))
    }

    fn last_acked(&self, key: &str) -> rusqlite::Result<Option<String>> {
        lock(&self.conn)
            .query_row(&self.sql.last_acked, params![key], |r| r.get(0))
            .optional()
    }
}
