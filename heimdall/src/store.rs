//! Flow store: sqlite-backed record of every relay tunnel.
//!
//! Schema is intentionally tiny — one row per flow with metadata only.
//! Phase B will extend with a `messages` table for plaintext / pcapng
//! payloads captured via uprobes.
//!
//! The relay calls [`Store::insert_flow_start`] when a tunnel is
//! established and [`Store::finish_flow`] when it closes; both are
//! fire-and-forget from the relay's perspective (errors are logged
//! but never propagated, so a broken store never breaks proxying).
//!
//! A periodic cleanup task drops rows older than
//! `runtime.flowRetentionSecs` (default 3 days).

use std::{
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use tracing::{debug, info, warn};

const SCHEMA: &[&str] = &[
    r#"CREATE TABLE IF NOT EXISTS flows (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        socket_cookie   INTEGER,
        cgroup_id       INTEGER,
        pod_uid         TEXT,
        namespace       TEXT,
        pod_name        TEXT,
        connection_name TEXT NOT NULL,
        dst_host        TEXT,
        dst_ip          TEXT NOT NULL,
        dst_port        INTEGER NOT NULL,
        ts_start_us     INTEGER NOT NULL,
        ts_end_us       INTEGER,
        bytes_up        INTEGER NOT NULL DEFAULT 0,
        bytes_down      INTEGER NOT NULL DEFAULT 0,
        upstream_addr   TEXT,
        atyp            TEXT,
        error           TEXT
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts_start_us DESC)",
    "CREATE INDEX IF NOT EXISTS idx_flows_pod ON flows(pod_uid)",
    "CREATE INDEX IF NOT EXISTS idx_flows_connection ON flows(connection_name)",
    "CREATE INDEX IF NOT EXISTS idx_flows_dst_host ON flows(dst_host)",
    // ── Phase B: TLS plaintext messages, captured at libssl boundary.
    //
    // flow_id is nullable: tap events arrive before / after a flow's
    // recorded lifetime, or for processes outside the relay's cgroup
    // (e.g. host openssl). cgroup_id is always present (eBPF stamps it)
    // and lets us filter even when correlation fails.
    r#"CREATE TABLE IF NOT EXISTS messages (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        flow_id       INTEGER,
        ts_us         INTEGER NOT NULL,
        cgroup_id     INTEGER NOT NULL,
        tgid          INTEGER NOT NULL,
        dir           INTEGER NOT NULL,
        total_len     INTEGER NOT NULL,
        captured_len  INTEGER NOT NULL,
        body          BLOB NOT NULL
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_messages_flow ON messages(flow_id, ts_us)",
    "CREATE INDEX IF NOT EXISTS idx_messages_cgroup_ts ON messages(cgroup_id, ts_us)",
    "CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts_us DESC)",
];

#[derive(Debug, Clone)]
pub struct FlowStart {
    pub socket_cookie: Option<u64>,
    pub cgroup_id: Option<u64>,
    pub pod_uid: Option<String>,
    pub namespace: Option<String>,
    pub pod_name: Option<String>,
    pub connection_name: String,
    pub dst_host: Option<String>,
    pub dst_ip: String,
    pub dst_port: u16,
    pub upstream_addr: Option<String>,
    /// "ip" (ATYP=0x01) or "domain" (ATYP=0x03) — only meaningful for socks5
    pub atyp: Option<&'static str>,
}

#[derive(Debug, Clone, Default)]
pub struct FlowFinish {
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub error: Option<String>,
}

/// One row from the `flows` table. Some fields are filled by sqlx and
/// only consumed when serialising to JSON or the table view; the dead-code
/// lint can't see across the FromRow boundary.
#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct Flow {
    pub id: i64,
    pub socket_cookie: Option<i64>,
    pub cgroup_id: Option<i64>,
    pub pod_uid: Option<String>,
    pub namespace: Option<String>,
    pub pod_name: Option<String>,
    pub connection_name: String,
    pub dst_host: Option<String>,
    pub dst_ip: String,
    pub dst_port: i64,
    pub ts_start_us: i64,
    pub ts_end_us: Option<i64>,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub upstream_addr: Option<String>,
    pub atyp: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ListQuery {
    pub limit: u32,
    pub since_us: Option<i64>,
    pub pod_substr: Option<String>,
    pub connection: Option<String>,
    pub host_substr: Option<String>,
}

// ─── Phase B: messages ──────────────────────────────────────────────────

/// One captured plaintext chunk at the libssl boundary (one SSL_write
/// or one SSL_read return). `body` is up to TAP_DATA_LEN bytes; if
/// `total_len > captured_len` the application sent / received more than
/// what we sampled.
#[derive(Debug, Clone)]
pub struct InsertMessage {
    pub flow_id: Option<i64>,
    pub ts_us: i64,
    pub cgroup_id: i64,
    pub tgid: i64,
    /// 0 = send (SSL_write), 1 = recv (SSL_read return).
    pub dir: u32,
    pub total_len: i64,
    pub body: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct Message {
    pub id: i64,
    pub flow_id: Option<i64>,
    pub ts_us: i64,
    pub cgroup_id: i64,
    pub tgid: i64,
    pub dir: i64,
    pub total_len: i64,
    pub captured_len: i64,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct MessageQuery {
    pub limit: u32,
    pub flow_id: Option<i64>,
    pub cgroup_id: Option<i64>,
    pub since_us: Option<i64>,
}

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        let url = format!("sqlite://{}", path.display());
        let opts = SqliteConnectOptions::from_str(&url)
            .with_context(|| format!("parse sqlite URL {url}"))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await
            .context("open sqlite pool")?;
        let store = Self { pool };
        store.migrate().await?;
        debug!(path = %path.display(), "flow store opened");
        Ok(store)
    }

    async fn migrate(&self) -> Result<()> {
        for stmt in SCHEMA {
            sqlx::query(stmt).execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn insert_flow_start(&self, f: FlowStart) -> Result<i64> {
        let r = sqlx::query(
            r#"INSERT INTO flows (
                socket_cookie, cgroup_id, pod_uid, namespace, pod_name,
                connection_name, dst_host, dst_ip, dst_port, ts_start_us,
                upstream_addr, atyp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(f.socket_cookie.map(|v| v as i64))
        .bind(f.cgroup_id.map(|v| v as i64))
        .bind(&f.pod_uid)
        .bind(&f.namespace)
        .bind(&f.pod_name)
        .bind(&f.connection_name)
        .bind(&f.dst_host)
        .bind(&f.dst_ip)
        .bind(f.dst_port as i64)
        .bind(now_micros())
        .bind(&f.upstream_addr)
        .bind(f.atyp)
        .execute(&self.pool)
        .await?;
        Ok(r.last_insert_rowid())
    }

    pub async fn finish_flow(&self, id: i64, f: FlowFinish) -> Result<()> {
        sqlx::query(
            r#"UPDATE flows
               SET ts_end_us = ?, bytes_up = ?, bytes_down = ?, error = ?
               WHERE id = ?"#,
        )
        .bind(now_micros())
        .bind(f.bytes_up)
        .bind(f.bytes_down)
        .bind(&f.error)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list(&self, q: ListQuery) -> Result<Vec<Flow>> {
        let limit = q.limit.max(1).min(10_000) as i64;
        let mut sql = String::from("SELECT * FROM flows WHERE 1=1");
        if q.since_us.is_some() {
            sql.push_str(" AND ts_start_us >= ?");
        }
        if q.pod_substr.is_some() {
            sql.push_str(" AND (pod_name LIKE ? OR namespace LIKE ?)");
        }
        if q.connection.is_some() {
            sql.push_str(" AND connection_name = ?");
        }
        if q.host_substr.is_some() {
            sql.push_str(" AND dst_host LIKE ?");
        }
        sql.push_str(" ORDER BY ts_start_us DESC LIMIT ?");

        let mut query = sqlx::query_as::<_, Flow>(&sql);
        if let Some(t) = q.since_us {
            query = query.bind(t);
        }
        if let Some(p) = &q.pod_substr {
            let like = format!("%{p}%");
            query = query.bind(like.clone()).bind(like);
        }
        if let Some(c) = &q.connection {
            query = query.bind(c);
        }
        if let Some(h) = &q.host_substr {
            query = query.bind(format!("%{h}%"));
        }
        let rows = query.bind(limit).fetch_all(&self.pool).await?;
        Ok(rows)
    }

    pub async fn get(&self, id: i64) -> Result<Option<Flow>> {
        let row = sqlx::query_as::<_, Flow>("SELECT * FROM flows WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    pub async fn cleanup_older_than(&self, secs: i64) -> Result<u64> {
        let cutoff = now_micros() - secs.saturating_mul(1_000_000);
        let mut total = 0u64;
        let r = sqlx::query("DELETE FROM flows WHERE ts_start_us < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        total += r.rows_affected();
        // Messages share the same retention. Delete by ts_us so we still
        // drop messages whose flow_id is NULL (host openssl, etc.).
        let r = sqlx::query("DELETE FROM messages WHERE ts_us < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        total += r.rows_affected();
        Ok(total)
    }

    pub async fn insert_message(&self, m: InsertMessage) -> Result<i64> {
        let captured_len = m.body.len() as i64;
        let r = sqlx::query(
            r#"INSERT INTO messages (
                flow_id, ts_us, cgroup_id, tgid, dir,
                total_len, captured_len, body
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(m.flow_id)
        .bind(m.ts_us)
        .bind(m.cgroup_id)
        .bind(m.tgid)
        .bind(m.dir as i64)
        .bind(m.total_len)
        .bind(captured_len)
        .bind(&m.body)
        .execute(&self.pool)
        .await?;
        Ok(r.last_insert_rowid())
    }

    pub async fn list_messages(&self, q: MessageQuery) -> Result<Vec<Message>> {
        let limit = q.limit.max(1).min(10_000) as i64;
        let mut sql = String::from("SELECT * FROM messages WHERE 1=1");
        if q.flow_id.is_some() {
            sql.push_str(" AND flow_id = ?");
        }
        if q.cgroup_id.is_some() {
            sql.push_str(" AND cgroup_id = ?");
        }
        if q.since_us.is_some() {
            sql.push_str(" AND ts_us >= ?");
        }
        sql.push_str(" ORDER BY ts_us ASC, id ASC LIMIT ?");

        let mut query = sqlx::query_as::<_, Message>(&sql);
        if let Some(f) = q.flow_id {
            query = query.bind(f);
        }
        if let Some(c) = q.cgroup_id {
            query = query.bind(c);
        }
        if let Some(t) = q.since_us {
            query = query.bind(t);
        }
        let rows = query.bind(limit).fetch_all(&self.pool).await?;
        Ok(rows)
    }
}

/// Spawn the periodic retention task. Runs forever; logs on each pass.
pub fn spawn_cleanup(store: Arc<Store>, retention_secs: i64) {
    tokio::spawn(async move {
        let interval_secs = (retention_secs / 12).clamp(60, 6 * 3600) as u64;
        let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
        // First tick fires immediately; let it ride.
        loop {
            tick.tick().await;
            match store.cleanup_older_than(retention_secs).await {
                Ok(0) => {}
                Ok(n) => info!(deleted = n, "store cleanup"),
                Err(e) => warn!(error = %e, "store cleanup failed"),
            }
        }
    });
}

pub fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn open_temp() -> (tempfile::TempDir, Store) {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("flows.db")).await.unwrap();
        (dir, store)
    }

    fn sample(connection_name: &str, dst_host: &str) -> FlowStart {
        FlowStart {
            socket_cookie: Some(0xCAFE),
            cgroup_id: Some(42),
            pod_uid: Some("uid-1".into()),
            namespace: Some("default".into()),
            pod_name: Some("nginx".into()),
            connection_name: connection_name.into(),
            dst_host: Some(dst_host.into()),
            dst_ip: "198.19.0.7".into(),
            dst_port: 443,
            upstream_addr: Some("127.0.0.1:20170".into()),
            atyp: Some("domain"),
        }
    }

    #[tokio::test]
    async fn insert_finish_round_trip() {
        let (_d, s) = open_temp().await;
        let id = s.insert_flow_start(sample("default", "example.com")).await.unwrap();
        s.finish_flow(id, FlowFinish { bytes_up: 100, bytes_down: 4096, error: None })
            .await
            .unwrap();
        let f = s.get(id).await.unwrap().unwrap();
        assert_eq!(f.connection_name, "default");
        assert_eq!(f.bytes_down, 4096);
        assert!(f.ts_end_us.is_some());
    }

    #[tokio::test]
    async fn list_filters() {
        let (_d, s) = open_temp().await;
        s.insert_flow_start(sample("default", "a.example.com")).await.unwrap();
        s.insert_flow_start(sample("corp", "b.example.com")).await.unwrap();
        s.insert_flow_start(sample("corp", "grafana.corp.com")).await.unwrap();

        let all = s.list(ListQuery { limit: 100, ..Default::default() }).await.unwrap();
        assert_eq!(all.len(), 3);

        let corp = s
            .list(ListQuery { limit: 100, connection: Some("corp".into()), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(corp.len(), 2);

        let grafana = s
            .list(ListQuery {
                limit: 100,
                host_substr: Some("grafana".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(grafana.len(), 1);
    }

    #[tokio::test]
    async fn cleanup_drops_old_rows() {
        let (_d, s) = open_temp().await;
        let id = s.insert_flow_start(sample("default", "x.com")).await.unwrap();
        // Backdate the row by one hour.
        sqlx::query("UPDATE flows SET ts_start_us = ts_start_us - 3600000000 WHERE id = ?")
            .bind(id)
            .execute(&s.pool)
            .await
            .unwrap();

        // 1800s retention → should delete the row.
        let n = s.cleanup_older_than(1800).await.unwrap();
        assert_eq!(n, 1);
        assert!(s.get(id).await.unwrap().is_none());
    }
}
