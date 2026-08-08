// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! SQLite persistence for faucet rate limiting and distribution tracking.
//!
//! All database methods are synchronous (rusqlite is blocking). The handler
//! layer wraps them in `tokio::task::spawn_blocking` to avoid blocking
//! async worker threads.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::FaucetError;

/// Tracks faucet distributions with per-IP and per-address rate limits.
pub struct FaucetDb {
    conn: Mutex<Connection>,
}

// Safety: Connection is Send (rusqlite guarantees this with --features bundled),
// and we protect it with a Mutex which provides Sync.
unsafe impl Send for FaucetDb {}
unsafe impl Sync for FaucetDb {}

impl FaucetDb {
    /// Open (or create) the faucet database at the given path.
    pub fn open(path: &Path) -> Result<Self, FaucetError> {
        let conn = Connection::open(path).map_err(|e| FaucetError::Database(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS distributions (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 address     TEXT    NOT NULL,
                 ip          TEXT    NOT NULL,
                 amount      INTEGER NOT NULL,
                 tx_id       TEXT,
                 created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
             );
             CREATE INDEX IF NOT EXISTS idx_dist_ip   ON distributions(ip, created_at);
             CREATE INDEX IF NOT EXISTS idx_dist_addr ON distributions(address, created_at);",
        )
        .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> Result<Self, FaucetError> {
        let conn =
            Connection::open_in_memory().map_err(|e| FaucetError::Database(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE distributions (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 address     TEXT    NOT NULL,
                 ip          TEXT    NOT NULL,
                 amount      INTEGER NOT NULL,
                 tx_id       TEXT,
                 created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
             );
             CREATE INDEX idx_dist_ip   ON distributions(ip, created_at);
             CREATE INDEX idx_dist_addr ON distributions(address, created_at);",
        )
        .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Check whether an IP has already received funds within the cooldown window.
    pub fn ip_recent_distribution(
        &self,
        ip: &str,
        cooldown_secs: u64,
    ) -> Result<bool, FaucetError> {
        let conn = self.conn.lock().unwrap();
        let count: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM distributions WHERE ip = ?1 AND created_at > (strftime('%s','now') - ?2)",
                params![ip, cooldown_secs],
                |row| row.get(0),
            )
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(count > 0)
    }

    /// Check whether an address has already received funds within the cooldown window.
    pub fn address_recent_distribution(
        &self,
        address: &str,
        cooldown_secs: u64,
    ) -> Result<bool, FaucetError> {
        let conn = self.conn.lock().unwrap();
        let count: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM distributions WHERE address = ?1 AND created_at > (strftime('%s','now') - ?2)",
                params![address, cooldown_secs],
                |row| row.get(0),
            )
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(count > 0)
    }

    /// Record a successful distribution.
    /// H14: atomically check every limit and RESERVE an allocation.
    ///
    /// The cooldown checks, the daily-cap check and the insert used to be three
    /// separate connection calls with the transfer in between, so concurrent
    /// requests could all pass the checks before any of them recorded anything
    /// and each would be paid. `BEGIN IMMEDIATE` takes the write lock up front,
    /// so the read-decide-write sequence is serialised against other faucet
    /// workers; the row is inserted BEFORE submission, with `tx_id` filled in
    /// afterwards by [`Self::confirm_distribution`].
    ///
    /// Returns the reservation id, or `Ok(None)` if a limit refused it.
    pub fn reserve_distribution(
        &self,
        address: &str,
        ip: &str,
        amount: u64,
        ip_cooldown_secs: u64,
        address_cooldown_secs: u64,
        daily_cap: u64,
    ) -> Result<Option<i64>, FaucetError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| FaucetError::Database(e.to_string()))?;

        let ip_recent: u64 = tx
            .query_row(
                "SELECT COUNT(*) FROM distributions \
                 WHERE ip = ?1 AND created_at > strftime('%s','now') - ?2",
                params![ip, ip_cooldown_secs as i64],
                |r| r.get(0),
            )
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        if ip_recent > 0 {
            return Ok(None);
        }

        let addr_recent: u64 = tx
            .query_row(
                "SELECT COUNT(*) FROM distributions \
                 WHERE address = ?1 AND created_at > strftime('%s','now') - ?2",
                params![address, address_cooldown_secs as i64],
                |r| r.get(0),
            )
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        if addr_recent > 0 {
            return Ok(None);
        }

        let today: u64 = tx
            .query_row(
                "SELECT COALESCE(SUM(amount), 0) FROM distributions \
                 WHERE created_at >= strftime('%s', 'now', 'start of day')",
                [],
                |r| r.get(0),
            )
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        if today.saturating_add(amount) > daily_cap {
            return Ok(None);
        }

        // Reserve BEFORE submitting: a crash between here and confirmation
        // leaves a row with no tx_id, which is a visible, reconcilable state —
        // strictly better than paying out with no record at all.
        tx.execute(
            "INSERT INTO distributions (address, ip, amount, tx_id) VALUES (?1, ?2, ?3, NULL)",
            params![address, ip, amount],
        )
        .map_err(|e| FaucetError::Database(e.to_string()))?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(Some(id))
    }

    /// H14: attach the transaction id to a reservation after submission.
    pub fn confirm_distribution(&self, id: i64, tx_id: &str) -> Result<(), FaucetError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE distributions SET tx_id = ?2 WHERE id = ?1",
            params![id, tx_id],
        )
        .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(())
    }

    /// H14: drop a reservation whose submission definitively failed before any
    /// transaction was broadcast. Never call this on an UNKNOWN outcome — that
    /// would free the limit while a payment may still land.
    pub fn release_distribution(&self, id: i64) -> Result<(), FaucetError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM distributions WHERE id = ?1 AND tx_id IS NULL",
            params![id],
        )
        .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(())
    }

    pub fn record_distribution(
        &self,
        address: &str,
        ip: &str,
        amount: u64,
        tx_id: Option<&str>,
    ) -> Result<(), FaucetError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO distributions (address, ip, amount, tx_id) VALUES (?1, ?2, ?3, ?4)",
            params![address, ip, amount, tx_id],
        )
        .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(())
    }

    /// H14/L13: reservations that were never confirmed — submission returned an
    /// UNKNOWN outcome (timeout, lost response), so a payment may or may not
    /// have landed.
    ///
    /// These are deliberately NOT auto-released: freeing the limit while a
    /// transfer might still confirm is exactly how a faucet pays twice.
    /// Reconciliation looks each one up by request identity and either confirms
    /// it with the real tx_id or releases it once the chain proves nothing was
    /// sent.
    pub fn unresolved_reservations(
        &self,
        older_than_secs: u64,
    ) -> Result<Vec<(i64, String, String, u64)>, FaucetError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, address, ip, amount FROM distributions \
                 WHERE tx_id IS NULL \
                   AND created_at < strftime('%s','now') - ?1 \
                 ORDER BY id",
            )
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        let rows = stmt
            .query_map(params![older_than_secs as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| FaucetError::Database(e.to_string()))?);
        }
        Ok(out)
    }

    /// Total amount distributed across all time.
    pub fn total_distributed(&self) -> Result<u64, FaucetError> {
        let conn = self.conn.lock().unwrap();
        let total: u64 = conn
            .query_row(
                "SELECT COALESCE(SUM(amount), 0) FROM distributions",
                [],
                |row| row.get(0),
            )
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(total)
    }

    /// Total amount distributed today (since midnight UTC).
    pub fn today_distributed(&self) -> Result<u64, FaucetError> {
        let conn = self.conn.lock().unwrap();
        let total: u64 = conn
            .query_row(
                "SELECT COALESCE(SUM(amount), 0) FROM distributions WHERE created_at > strftime('%s', date('now'))",
                [],
                |row| row.get(0),
            )
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(total)
    }

    /// Clear all distribution records (resets rate limits).
    pub fn clear_distributions(&self) -> Result<usize, FaucetError> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn
            .execute("DELETE FROM distributions", [])
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(deleted)
    }

    /// Count of total distributions.
    pub fn distribution_count(&self) -> Result<u64, FaucetError> {
        let conn = self.conn.lock().unwrap();
        let count: u64 = conn
            .query_row("SELECT COUNT(*) FROM distributions", [], |row| row.get(0))
            .map_err(|e| FaucetError::Database(e.to_string()))?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_memory() {
        let db = FaucetDb::open_memory().unwrap();
        assert_eq!(db.total_distributed().unwrap(), 0);
        assert_eq!(db.distribution_count().unwrap(), 0);
    }

    #[test]
    fn test_record_and_query() {
        let db = FaucetDb::open_memory().unwrap();
        db.record_distribution("addr1", "1.2.3.4", 100_000_000, Some("tx_abc"))
            .unwrap();
        assert_eq!(db.total_distributed().unwrap(), 100_000_000);
        assert_eq!(db.distribution_count().unwrap(), 1);
        assert!(db.ip_recent_distribution("1.2.3.4", 86400).unwrap());
        assert!(!db.ip_recent_distribution("5.6.7.8", 86400).unwrap());
        assert!(db.address_recent_distribution("addr1", 604800).unwrap());
        assert!(!db.address_recent_distribution("addr2", 604800).unwrap());
    }

    #[test]
    fn test_today_distributed() {
        let db = FaucetDb::open_memory().unwrap();
        db.record_distribution("addr1", "1.2.3.4", 500_000, None)
            .unwrap();
        db.record_distribution("addr2", "5.6.7.8", 300_000, None)
            .unwrap();
        assert_eq!(db.today_distributed().unwrap(), 800_000);
    }

    #[test]
    fn test_multiple_distributions() {
        let db = FaucetDb::open_memory().unwrap();
        for i in 0..5 {
            db.record_distribution(&format!("addr{i}"), &format!("10.0.0.{i}"), 100_000, None)
                .unwrap();
        }
        assert_eq!(db.total_distributed().unwrap(), 500_000);
        assert_eq!(db.distribution_count().unwrap(), 5);
    }
}
