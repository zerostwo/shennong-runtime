use std::{str::FromStr, time::Duration};

use chrono::{DateTime, Utc};
use sqlx::{
    FromRow, Sqlite, SqlitePool, Transaction,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use uuid::Uuid;

use crate::{
    error::{Result, RuntimeError},
    model::{
        ArtifactManifestEntry, IdeKind, JobRecord, JobSpec, JobState, JobView, LogEntry, LogStream,
        SessionRecord, SessionSpec, SessionState, SessionView,
    },
};

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    owner_sub TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    workspace_ref TEXT NOT NULL,
    worker_profile TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    state TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    executor_id TEXT,
    exit_code INTEGER,
    error TEXT,
    log_truncated INTEGER NOT NULL DEFAULT 0,
    log_bytes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner_sub, idempotency_key)
);

CREATE INDEX IF NOT EXISTS jobs_state_idx ON jobs(state);
CREATE INDEX IF NOT EXISTS jobs_owner_idx ON jobs(owner_sub, created_at);

CREATE TABLE IF NOT EXISTS job_logs (
    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    stream TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS job_logs_job_cursor_idx ON job_logs(job_id, cursor);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    kind TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    media_type TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(job_id, relative_path)
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    owner_sub TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    workspace_ref TEXT NOT NULL,
    kind TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    state TEXT NOT NULL,
    executor_id TEXT,
    internal_target TEXT,
    internal_secret TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE(owner_sub, idempotency_key)
);

CREATE INDEX IF NOT EXISTS sessions_state_idx ON sessions(state);
CREATE INDEX IF NOT EXISTS sessions_owner_idx ON sessions(owner_sub, created_at);
"#;

const LATEST_SCHEMA_VERSION: i64 = 2;

#[derive(Clone)]
pub struct Journal {
    pool: SqlitePool,
}

#[derive(FromRow)]
struct JobRow {
    id: String,
    owner_sub: String,
    idempotency_key: String,
    request_hash: String,
    workspace_ref: String,
    worker_profile: String,
    spec_json: String,
    state: String,
    attempt: i64,
    executor_id: Option<String>,
    exit_code: Option<i64>,
    error: Option<String>,
    log_truncated: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct LogRow {
    cursor: i64,
    stream: String,
    message: String,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ArtifactRow {
    id: String,
    relative_path: String,
    kind: String,
    size_bytes: i64,
    sha256: String,
    media_type: Option<String>,
}

#[derive(FromRow)]
struct SessionRow {
    id: String,
    owner_sub: String,
    idempotency_key: String,
    request_hash: String,
    workspace_ref: String,
    kind: String,
    spec_json: String,
    state: String,
    executor_id: Option<String>,
    internal_target: Option<String>,
    internal_secret: Option<String>,
    error: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_activity_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl Journal {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        initialize_schema(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn ping(&self) -> Result<()> {
        let value: i64 = sqlx::query_scalar("SELECT 1").fetch_one(&self.pool).await?;
        if value == 1 {
            Ok(())
        } else {
            Err(RuntimeError::Internal("SQLite health check failed".into()))
        }
    }

    pub async fn insert_job(
        &self,
        owner_sub: &str,
        idempotency_key: &str,
        request_hash: &str,
        spec: &JobSpec,
    ) -> Result<JobRecord> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let spec_json = serde_json::to_string(spec)
            .map_err(|error| RuntimeError::Internal(error.to_string()))?;
        let result = sqlx::query(
            r#"INSERT INTO jobs
               (id, owner_sub, idempotency_key, request_hash, workspace_ref, worker_profile,
                spec_json, state, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)"#,
        )
        .bind(id.to_string())
        .bind(owner_sub)
        .bind(idempotency_key)
        .bind(request_hash)
        .bind(&spec.workspace_ref)
        .bind(&spec.worker_profile)
        .bind(spec_json)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => self.job(id).await,
            Err(sqlx::Error::Database(database_error)) if database_error.is_unique_violation() => {
                Err(RuntimeError::Conflict(
                    "idempotency key already exists".into(),
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn job(&self, id: Uuid) -> Result<JobRecord> {
        let row = sqlx::query_as::<_, JobRow>("SELECT * FROM jobs WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| RuntimeError::NotFound(format!("job {id}")))?;
        job_from_row(row)
    }

    pub async fn job_by_idempotency(
        &self,
        owner_sub: &str,
        key: &str,
    ) -> Result<Option<JobRecord>> {
        let row = sqlx::query_as::<_, JobRow>(
            "SELECT * FROM jobs WHERE owner_sub = ? AND idempotency_key = ?",
        )
        .bind(owner_sub)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(job_from_row).transpose()
    }

    pub async fn active_jobs(&self) -> Result<Vec<JobRecord>> {
        let rows = sqlx::query_as::<_, JobRow>(
            "SELECT * FROM jobs WHERE state NOT IN ('succeeded','failed','cancelled','timed_out','lost')",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(job_from_row).collect()
    }

    pub async fn transition_job(
        &self,
        id: Uuid,
        next: JobState,
        executor_id: Option<&str>,
        exit_code: Option<i64>,
        error: Option<&str>,
    ) -> Result<JobRecord> {
        let mut transaction = self.pool.begin().await?;
        let current: String = sqlx::query_scalar("SELECT state FROM jobs WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| RuntimeError::NotFound(format!("job {id}")))?;
        let current = JobState::from_str(&current)?;
        if !current.can_transition_to(next) {
            return Err(RuntimeError::Conflict(format!(
                "invalid job transition {current} -> {next}"
            )));
        }
        sqlx::query(
            "UPDATE jobs SET state = ?, executor_id = COALESCE(?, executor_id), exit_code = COALESCE(?, exit_code), error = COALESCE(?, error), updated_at = ? WHERE id = ?",
        )
        .bind(next.to_string())
        .bind(executor_id)
        .bind(exit_code)
        .bind(error)
        .bind(Utc::now())
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        self.job(id).await
    }

    pub async fn append_log(
        &self,
        job_id: Uuid,
        stream: LogStream,
        message: &str,
        max_bytes: i64,
    ) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        let used: i64 = sqlx::query_scalar("SELECT log_bytes FROM jobs WHERE id = ?")
            .bind(job_id.to_string())
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| RuntimeError::NotFound(format!("job {job_id}")))?;
        let available = (max_bytes - used).max(0) as usize;
        if available == 0 {
            sqlx::query("UPDATE jobs SET log_truncated = 1, updated_at = ? WHERE id = ?")
                .bind(Utc::now())
                .bind(job_id.to_string())
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            return Ok(());
        }
        let (bounded, truncated) = truncate_utf8(message, available);
        if !bounded.is_empty() {
            sqlx::query(
                "INSERT INTO job_logs (job_id, stream, message, created_at) VALUES (?, ?, ?, ?)",
            )
            .bind(job_id.to_string())
            .bind(stream.to_string())
            .bind(bounded)
            .bind(Utc::now())
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "UPDATE jobs SET log_bytes = log_bytes + ?, log_truncated = CASE WHEN ? THEN 1 ELSE log_truncated END, updated_at = ? WHERE id = ?",
        )
        .bind(bounded.len() as i64)
        .bind(truncated)
        .bind(Utc::now())
        .bind(job_id.to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn logs(&self, job_id: Uuid, after: i64, limit: u32) -> Result<Vec<LogEntry>> {
        let rows = sqlx::query_as::<_, LogRow>(
            "SELECT cursor, stream, message, created_at FROM job_logs WHERE job_id = ? AND cursor > ? ORDER BY cursor ASC LIMIT ?",
        )
        .bind(job_id.to_string())
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(LogEntry {
                    cursor: row.cursor,
                    stream: LogStream::from_str(&row.stream)?,
                    message: row.message,
                    created_at: row.created_at,
                })
            })
            .collect()
    }

    pub async fn replace_artifacts(
        &self,
        job_id: Uuid,
        artifacts: &[ArtifactManifestEntry],
    ) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM artifacts WHERE job_id = ?")
            .bind(job_id.to_string())
            .execute(&mut *transaction)
            .await?;
        for artifact in artifacts {
            sqlx::query(
                r#"INSERT INTO artifacts
                   (id, job_id, relative_path, kind, size_bytes, sha256, media_type, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
            )
            .bind(artifact.id.to_string())
            .bind(job_id.to_string())
            .bind(&artifact.relative_path)
            .bind(artifact_kind_to_string(&artifact.kind))
            .bind(artifact.size_bytes)
            .bind(&artifact.sha256)
            .bind(&artifact.media_type)
            .bind(Utc::now())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn artifacts(&self, job_id: Uuid) -> Result<Vec<ArtifactManifestEntry>> {
        let rows = sqlx::query_as::<_, ArtifactRow>(
            "SELECT id, relative_path, kind, size_bytes, sha256, media_type FROM artifacts WHERE job_id = ? ORDER BY relative_path",
        )
        .bind(job_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(ArtifactManifestEntry {
                    id: Uuid::parse_str(&row.id)
                        .map_err(|error| RuntimeError::Internal(error.to_string()))?,
                    relative_path: row.relative_path,
                    kind: artifact_kind_from_string(&row.kind)?,
                    size_bytes: row.size_bytes,
                    sha256: row.sha256,
                    media_type: row.media_type,
                })
            })
            .collect()
    }

    pub async fn insert_session(
        &self,
        owner_sub: &str,
        idempotency_key: &str,
        request_hash: &str,
        spec: &SessionSpec,
    ) -> Result<SessionRecord> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(spec.max_lifetime_seconds as i64);
        let spec_json = serde_json::to_string(spec)
            .map_err(|error| RuntimeError::Internal(error.to_string()))?;
        let result = sqlx::query(
            r#"INSERT INTO sessions
               (id, owner_sub, idempotency_key, request_hash, workspace_ref, kind, spec_json,
                state, created_at, updated_at, last_activity_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'starting', ?, ?, ?, ?)"#,
        )
        .bind(id.to_string())
        .bind(owner_sub)
        .bind(idempotency_key)
        .bind(request_hash)
        .bind(&spec.workspace_ref)
        .bind(ide_kind_to_string(&spec.kind))
        .bind(spec_json)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => self.session(id).await,
            Err(sqlx::Error::Database(database_error)) if database_error.is_unique_violation() => {
                Err(RuntimeError::Conflict(
                    "idempotency key already exists".into(),
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn session(&self, id: Uuid) -> Result<SessionRecord> {
        let row = sqlx::query_as::<_, SessionRow>("SELECT * FROM sessions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| RuntimeError::NotFound(format!("session {id}")))?;
        session_from_row(row)
    }

    pub async fn session_by_idempotency(
        &self,
        owner_sub: &str,
        key: &str,
    ) -> Result<Option<SessionRecord>> {
        let row = sqlx::query_as::<_, SessionRow>(
            "SELECT * FROM sessions WHERE owner_sub = ? AND idempotency_key = ?",
        )
        .bind(owner_sub)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(session_from_row).transpose()
    }

    pub async fn active_sessions(&self) -> Result<Vec<SessionRecord>> {
        let rows = sqlx::query_as::<_, SessionRow>(
            "SELECT * FROM sessions WHERE state NOT IN ('stopped','failed','expired','lost')",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(session_from_row).collect()
    }

    pub async fn update_session(
        &self,
        id: Uuid,
        state: SessionState,
        executor_id: Option<&str>,
        internal_target: Option<&str>,
        error: Option<&str>,
    ) -> Result<SessionRecord> {
        let mut transaction = self.pool.begin().await?;
        let current: String = sqlx::query_scalar("SELECT state FROM sessions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| RuntimeError::NotFound(format!("session {id}")))?;
        let current = SessionState::from_str(&current)?;
        if !current.can_transition_to(state) {
            return Err(RuntimeError::Conflict(format!(
                "invalid session transition {current} -> {state}"
            )));
        }
        sqlx::query(
            "UPDATE sessions SET state = ?, executor_id = COALESCE(?, executor_id), internal_target = COALESCE(?, internal_target), error = COALESCE(?, error), updated_at = ? WHERE id = ?",
        )
        .bind(state.to_string())
        .bind(executor_id)
        .bind(internal_target)
        .bind(error)
        .bind(Utc::now())
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        self.session(id).await
    }

    pub async fn activate_session(
        &self,
        id: Uuid,
        executor_id: &str,
        internal_target: &str,
        internal_secret: &str,
    ) -> Result<SessionRecord> {
        if internal_secret.len() != 64
            || !internal_secret.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RuntimeError::Internal(
                "generated IDE gateway secret is invalid".into(),
            ));
        }
        let mut transaction = self.pool.begin().await?;
        let current: String = sqlx::query_scalar("SELECT state FROM sessions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| RuntimeError::NotFound(format!("session {id}")))?;
        let current = SessionState::from_str(&current)?;
        if !current.can_transition_to(SessionState::Running) {
            return Err(RuntimeError::Conflict(format!(
                "invalid session transition {current} -> running"
            )));
        }
        sqlx::query(
            "UPDATE sessions SET state = 'running', executor_id = ?, internal_target = ?, internal_secret = ?, updated_at = ?, last_activity_at = ? WHERE id = ?",
        )
        .bind(executor_id)
        .bind(internal_target)
        .bind(internal_secret)
        .bind(Utc::now())
        .bind(Utc::now())
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        self.session(id).await
    }

    pub async fn expire_session_if_idle(
        &self,
        id: Uuid,
        cutoff: DateTime<Utc>,
        reason: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE sessions SET state = 'expired', error = ?, updated_at = ? WHERE id = ? AND state = 'running' AND last_activity_at <= ?",
        )
        .bind(reason)
        .bind(Utc::now())
        .bind(id.to_string())
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn touch_session_activity(&self, id: Uuid) -> Result<()> {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::seconds(1);
        let result = sqlx::query(
            "UPDATE sessions SET last_activity_at = ?, updated_at = ? WHERE id = ? AND state = 'running' AND last_activity_at <= ?",
        )
        .bind(now)
        .bind(now)
        .bind(id.to_string())
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        let state: Option<String> = sqlx::query_scalar("SELECT state FROM sessions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        match state.as_deref() {
            Some("running") => Ok(()),
            Some(_) => Err(RuntimeError::Conflict("IDE session is not running".into())),
            None => Err(RuntimeError::NotFound(format!("session {id}"))),
        }
    }

    pub async fn set_session_activity(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        let result = sqlx::query(
            "UPDATE sessions SET last_activity_at = ?, updated_at = ? WHERE id = ? AND state = 'running'",
        )
        .bind(at)
        .bind(Utc::now())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            let state: Option<String> =
                sqlx::query_scalar("SELECT state FROM sessions WHERE id = ?")
                    .bind(id.to_string())
                    .fetch_optional(&self.pool)
                    .await?;
            return match state {
                Some(_) => Err(RuntimeError::Conflict("IDE session is not running".into())),
                None => Err(RuntimeError::NotFound(format!("session {id}"))),
            };
        }
        Ok(())
    }

    pub async fn executor_ids(&self) -> Result<std::collections::HashSet<String>> {
        let values: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT executor_id FROM jobs WHERE executor_id IS NOT NULL UNION SELECT executor_id FROM sessions WHERE executor_id IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(values.into_iter().flatten().collect())
    }

    pub async fn pending_job_cleanups(&self) -> Result<Vec<(Uuid, String)>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, executor_id FROM jobs WHERE executor_id IS NOT NULL AND state IN ('succeeded','failed','cancelled','timed_out','lost')",
        )
        .fetch_all(&self.pool)
        .await?;
        parse_executor_rows(rows)
    }

    pub async fn pending_session_cleanups(&self) -> Result<Vec<(Uuid, String)>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, executor_id FROM sessions WHERE executor_id IS NOT NULL AND state IN ('stopped','failed','expired','lost')",
        )
        .fetch_all(&self.pool)
        .await?;
        parse_executor_rows(rows)
    }

    pub async fn clear_job_executor(&self, id: Uuid, executor_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE jobs SET executor_id = NULL, updated_at = ? WHERE id = ? AND executor_id = ?",
        )
        .bind(Utc::now())
        .bind(id.to_string())
        .bind(executor_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn clear_session_executor(&self, id: Uuid, executor_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE sessions SET executor_id = NULL, internal_target = NULL, internal_secret = NULL, updated_at = ? WHERE id = ? AND executor_id = ?",
        )
        .bind(Utc::now())
        .bind(id.to_string())
        .bind(executor_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

async fn initialize_schema(pool: &SqlitePool) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *transaction)
        .await?;
    if version > LATEST_SCHEMA_VERSION {
        return Err(RuntimeError::Internal(format!(
            "SQLite schema version {version} is newer than supported version {LATEST_SCHEMA_VERSION}"
        )));
    }

    // CREATE IF NOT EXISTS keeps fresh database creation and legacy upgrades on the
    // same atomic path. Existing tables are left in place for the migrations below.
    sqlx::raw_sql(SCHEMA).execute(&mut *transaction).await?;

    if version < 1 {
        migrate_jobs_log_bytes(&mut transaction).await?;
        sqlx::query("PRAGMA user_version = 1")
            .execute(&mut *transaction)
            .await?;
    }
    if version < 2 {
        migrate_session_security_and_activity(&mut transaction).await?;
        sqlx::query("PRAGMA user_version = 2")
            .execute(&mut *transaction)
            .await?;
    }

    validate_current_schema(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

async fn migrate_jobs_log_bytes(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    if !has_column(transaction, "jobs", "log_bytes").await? {
        sqlx::query("ALTER TABLE jobs ADD COLUMN log_bytes INTEGER NOT NULL DEFAULT 0")
            .execute(&mut **transaction)
            .await?;
        sqlx::query(
            r#"UPDATE jobs
               SET log_bytes = COALESCE(
                   (SELECT SUM(length(CAST(message AS BLOB)))
                    FROM job_logs
                    WHERE job_logs.job_id = jobs.id),
                   0
               )"#,
        )
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn migrate_session_security_and_activity(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<()> {
    if !has_column(transaction, "sessions", "internal_secret").await? {
        sqlx::query("ALTER TABLE sessions ADD COLUMN internal_secret TEXT")
            .execute(&mut **transaction)
            .await?;
    }
    if !has_column(transaction, "sessions", "last_activity_at").await? {
        // SQLite requires a constant default when adding a NOT NULL column to a
        // populated table. Every legacy row is immediately replaced with its last
        // persisted update time, while new writes always provide an explicit value.
        sqlx::query(
            "ALTER TABLE sessions ADD COLUMN last_activity_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'",
        )
        .execute(&mut **transaction)
        .await?;
        sqlx::query("UPDATE sessions SET last_activity_at = updated_at")
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

async fn validate_current_schema(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    for (table, column) in [
        ("jobs", "log_bytes"),
        ("sessions", "last_activity_at"),
        ("sessions", "internal_secret"),
    ] {
        if !has_column(transaction, table, column).await? {
            return Err(RuntimeError::Internal(format!(
                "SQLite schema migration did not create {table}.{column}"
            )));
        }
    }
    Ok(())
}

async fn has_column(
    transaction: &mut Transaction<'_, Sqlite>,
    table: &str,
    column: &str,
) -> Result<bool> {
    let statement = match table {
        "jobs" => "SELECT EXISTS(SELECT 1 FROM pragma_table_info('jobs') WHERE name = ?)",
        "sessions" => "SELECT EXISTS(SELECT 1 FROM pragma_table_info('sessions') WHERE name = ?)",
        _ => {
            return Err(RuntimeError::Internal(format!(
                "unsupported migration table {table}"
            )));
        }
    };
    let exists: bool = sqlx::query_scalar(statement)
        .bind(column)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(exists)
}

fn parse_executor_rows(rows: Vec<(String, String)>) -> Result<Vec<(Uuid, String)>> {
    rows.into_iter()
        .map(|(id, executor_id)| {
            Ok((
                Uuid::parse_str(&id).map_err(|error| RuntimeError::Internal(error.to_string()))?,
                executor_id,
            ))
        })
        .collect()
}

fn job_from_row(row: JobRow) -> Result<JobRecord> {
    let id = Uuid::parse_str(&row.id).map_err(|error| RuntimeError::Internal(error.to_string()))?;
    Ok(JobRecord {
        view: JobView {
            id,
            state: JobState::from_str(&row.state)?,
            workspace_ref: row.workspace_ref,
            worker_profile: row.worker_profile,
            attempt: row.attempt,
            exit_code: row.exit_code,
            error: row.error,
            log_truncated: row.log_truncated,
            created_at: row.created_at,
            updated_at: row.updated_at,
        },
        owner_sub: row.owner_sub,
        idempotency_key: row.idempotency_key,
        request_hash: row.request_hash,
        spec: serde_json::from_str(&row.spec_json)
            .map_err(|error| RuntimeError::Internal(error.to_string()))?,
        executor_id: row.executor_id,
    })
}

fn session_from_row(row: SessionRow) -> Result<SessionRecord> {
    let id = Uuid::parse_str(&row.id).map_err(|error| RuntimeError::Internal(error.to_string()))?;
    let proxy_path = row
        .internal_target
        .as_ref()
        .map(|_| format!("/v1/sessions/{id}/proxy/"));
    Ok(SessionRecord {
        view: SessionView {
            id,
            state: SessionState::from_str(&row.state)?,
            workspace_ref: row.workspace_ref,
            kind: ide_kind_from_string(&row.kind)?,
            proxy_path,
            internal_target: row.internal_target,
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
            error: row.error,
        },
        owner_sub: row.owner_sub,
        idempotency_key: row.idempotency_key,
        request_hash: row.request_hash,
        spec: serde_json::from_str(&row.spec_json)
            .map_err(|error| RuntimeError::Internal(error.to_string()))?,
        executor_id: row.executor_id,
        internal_secret: row.internal_secret,
        last_activity_at: row.last_activity_at,
    })
}

fn truncate_utf8(value: &str, max_bytes: usize) -> (&str, bool) {
    if value.len() <= max_bytes {
        return (value, false);
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (&value[..end], true)
}

fn artifact_kind_to_string(kind: &crate::model::ArtifactKind) -> &'static str {
    use crate::model::ArtifactKind::*;
    match kind {
        Figure => "figure",
        Image => "image",
        Table => "table",
        Report => "report",
        Notebook => "notebook",
        Script => "script",
        DatasetSubset => "dataset_subset",
        Archive => "archive",
        Other => "other",
    }
}

fn artifact_kind_from_string(value: &str) -> Result<crate::model::ArtifactKind> {
    use crate::model::ArtifactKind::*;
    match value {
        "figure" => Ok(Figure),
        "image" => Ok(Image),
        "table" => Ok(Table),
        "report" => Ok(Report),
        "notebook" => Ok(Notebook),
        "script" => Ok(Script),
        "dataset_subset" => Ok(DatasetSubset),
        "archive" => Ok(Archive),
        "other" => Ok(Other),
        other => Err(RuntimeError::Internal(format!(
            "unknown artifact kind {other}"
        ))),
    }
}

fn ide_kind_to_string(kind: &IdeKind) -> &'static str {
    match kind {
        IdeKind::Rstudio => "rstudio",
        IdeKind::Jupyterlab => "jupyterlab",
    }
}

fn ide_kind_from_string(value: &str) -> Result<IdeKind> {
    match value {
        "rstudio" => Ok(IdeKind::Rstudio),
        "jupyterlab" => Ok(IdeKind::Jupyterlab),
        other => Err(RuntimeError::Internal(format!("unknown IDE kind {other}"))),
    }
}
