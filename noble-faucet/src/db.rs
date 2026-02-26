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
        db.record_distribution("addr1", "1.2.3.4", 1_000_000, Some("tx_abc"))
            .unwrap();
        assert_eq!(db.total_distributed().unwrap(), 1_000_000);
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
