use shennong_runtime::journal::Journal;
use sqlx::SqlitePool;

const OLD_SCHEMA: &str = r#"
CREATE TABLE jobs (
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
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner_sub, idempotency_key)
);

CREATE TABLE job_logs (
    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    stream TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE sessions (
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
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE(owner_sub, idempotency_key)
);
"#;

const JOB_ID: &str = "7f294da2-fd3a-4d67-ab31-6773b0196542";
const SESSION_ID: &str = "d3259bd4-6a9d-4945-91bb-69184065f97d";
const CREATED_AT: &str = "2026-07-16T01:02:03Z";
const UPDATED_AT: &str = "2026-07-16T04:05:06Z";
const EXPIRES_AT: &str = "2026-07-16T10:05:06Z";

#[tokio::test]
async fn upgrades_unversioned_database_and_backfills_runtime_columns() {
    let (_directory, database_url) = database_url();
    let pool = create_old_database(&database_url).await;
    sqlx::query(
        "INSERT INTO job_logs (job_id, stream, message, created_at) VALUES (?, 'stdout', ?, ?)",
    )
    .bind(JOB_ID)
    .bind("plain")
    .bind(CREATED_AT)
    .execute(&pool)
    .await
    .expect("insert ASCII log");
    sqlx::query(
        "INSERT INTO job_logs (job_id, stream, message, created_at) VALUES (?, 'stderr', ?, ?)",
    )
    .bind(JOB_ID)
    .bind("你好")
    .bind(UPDATED_AT)
    .execute(&pool)
    .await
    .expect("insert UTF-8 log");
    pool.close().await;

    let journal = Journal::connect(&database_url)
        .await
        .expect("upgrade old database");
    drop(journal);

    let upgraded = SqlitePool::connect(&database_url)
        .await
        .expect("inspect upgraded database");
    assert_eq!(schema_version(&upgraded).await, 3);

    let log_bytes: i64 = sqlx::query_scalar("SELECT log_bytes FROM jobs WHERE id = ?")
        .bind(JOB_ID)
        .fetch_one(&upgraded)
        .await
        .expect("migrated log_bytes");
    assert_eq!(log_bytes, ("plain".len() + "你好".len()) as i64);

    let last_activity: String =
        sqlx::query_scalar("SELECT last_activity_at FROM sessions WHERE id = ?")
            .bind(SESSION_ID)
            .fetch_one(&upgraded)
            .await
            .expect("migrated last activity");
    assert_eq!(last_activity, UPDATED_AT);
    let internal_secret: Option<String> =
        sqlx::query_scalar("SELECT internal_secret FROM sessions WHERE id = ?")
            .bind(SESSION_ID)
            .fetch_one(&upgraded)
            .await
            .expect("migrated internal secret");
    assert_eq!(internal_secret, None);
    let last_activity_not_null: i64 = sqlx::query_scalar(
        "SELECT \"notnull\" FROM pragma_table_info('sessions') WHERE name = 'last_activity_at'",
    )
    .fetch_one(&upgraded)
    .await
    .expect("last activity constraint");
    assert_eq!(last_activity_not_null, 1);
    assert!(column_exists(&upgraded, "artifacts", "role").await);
    upgraded.close().await;

    // A second startup must not re-run a data migration or duplicate columns.
    let journal = Journal::connect(&database_url)
        .await
        .expect("repeat schema initialization");
    drop(journal);
    let reopened = SqlitePool::connect(&database_url)
        .await
        .expect("inspect reopened database");
    assert_eq!(schema_version(&reopened).await, 3);
    let log_bytes_after_reopen: i64 = sqlx::query_scalar("SELECT log_bytes FROM jobs WHERE id = ?")
        .bind(JOB_ID)
        .fetch_one(&reopened)
        .await
        .expect("preserved log_bytes");
    assert_eq!(log_bytes_after_reopen, log_bytes);
}

#[tokio::test]
async fn upgrades_v1_database_without_rewriting_completed_job_migration() {
    let (_directory, database_url) = database_url();
    let pool = create_old_database(&database_url).await;
    sqlx::query("ALTER TABLE jobs ADD COLUMN log_bytes INTEGER NOT NULL DEFAULT 0")
        .execute(&pool)
        .await
        .expect("prepare version 1 jobs schema");
    sqlx::query("UPDATE jobs SET log_bytes = 123 WHERE id = ?")
        .bind(JOB_ID)
        .execute(&pool)
        .await
        .expect("prepare version 1 log count");
    sqlx::query("PRAGMA user_version = 1")
        .execute(&pool)
        .await
        .expect("mark version 1");
    pool.close().await;

    let journal = Journal::connect(&database_url)
        .await
        .expect("upgrade version 1 database");
    drop(journal);
    let upgraded = SqlitePool::connect(&database_url)
        .await
        .expect("inspect version 3 database");

    assert_eq!(schema_version(&upgraded).await, 3);
    let log_bytes: i64 = sqlx::query_scalar("SELECT log_bytes FROM jobs WHERE id = ?")
        .bind(JOB_ID)
        .fetch_one(&upgraded)
        .await
        .expect("preserved version 1 data");
    assert_eq!(log_bytes, 123);
    let last_activity: String =
        sqlx::query_scalar("SELECT last_activity_at FROM sessions WHERE id = ?")
            .bind(SESSION_ID)
            .fetch_one(&upgraded)
            .await
            .expect("version 3 session activity");
    assert_eq!(last_activity, UPDATED_AT);
    assert!(column_exists(&upgraded, "sessions", "internal_secret").await);
    assert!(column_exists(&upgraded, "artifacts", "role").await);
}

#[tokio::test]
async fn fresh_database_keeps_canonical_schema_and_records_latest_version() {
    let (_directory, database_url) = database_url();
    let journal = Journal::connect(&database_url)
        .await
        .expect("initialize fresh database");
    drop(journal);
    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("inspect fresh database");

    assert_eq!(schema_version(&pool).await, 3);
    assert!(column_exists(&pool, "jobs", "log_bytes").await);
    assert!(column_exists(&pool, "sessions", "last_activity_at").await);
    assert!(column_exists(&pool, "sessions", "internal_secret").await);
    assert!(column_exists(&pool, "artifacts", "role").await);
    let default_value: Option<String> = sqlx::query_scalar(
        "SELECT dflt_value FROM pragma_table_info('sessions') WHERE name = 'last_activity_at'",
    )
    .fetch_one(&pool)
    .await
    .expect("fresh last_activity_at definition");
    assert_eq!(default_value, None);
}

#[tokio::test]
async fn refuses_a_database_schema_newer_than_this_runtime() {
    let (_directory, database_url) = database_url();
    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("create future database");
    sqlx::query("PRAGMA user_version = 99")
        .execute(&pool)
        .await
        .expect("mark future schema");
    pool.close().await;
    let error = Journal::connect(&database_url)
        .await
        .err()
        .expect("future schema must fail closed");
    assert!(error.to_string().contains("newer"));
}

fn database_url() -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = directory.path().join("runtime.db");
    let database_url = format!("sqlite://{}?mode=rwc", database.display());
    (directory, database_url)
}

async fn create_old_database(database_url: &str) -> SqlitePool {
    let pool = SqlitePool::connect(database_url)
        .await
        .expect("create old database");
    sqlx::raw_sql(OLD_SCHEMA)
        .execute(&pool)
        .await
        .expect("create old schema");
    sqlx::query(
        r#"INSERT INTO jobs
           (id, owner_sub, idempotency_key, request_hash, workspace_ref, worker_profile,
            spec_json, state, created_at, updated_at)
           VALUES (?, 'legacy-user', 'legacy-job-key', 'job-hash', 'ws_legacy',
                   'cpu-small', '{}', 'succeeded', ?, ?)"#,
    )
    .bind(JOB_ID)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&pool)
    .await
    .expect("insert old job");
    sqlx::query(
        r#"INSERT INTO sessions
           (id, owner_sub, idempotency_key, request_hash, workspace_ref, kind, spec_json,
            state, executor_id, internal_target, created_at, updated_at, expires_at)
           VALUES (?, 'legacy-user', 'legacy-session-key', 'session-hash', 'ws_legacy',
                   'jupyterlab', '{}', 'running', 'legacy-container', 'http://127.0.0.1:8888',
                   ?, ?, ?)"#,
    )
    .bind(SESSION_ID)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .bind(EXPIRES_AT)
    .execute(&pool)
    .await
    .expect("insert old session");
    pool
}

async fn schema_version(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(pool)
        .await
        .expect("schema version")
}

async fn column_exists(pool: &SqlitePool, table: &str, column: &str) -> bool {
    let statement = match table {
        "jobs" => "SELECT EXISTS(SELECT 1 FROM pragma_table_info('jobs') WHERE name = ?)",
        "sessions" => "SELECT EXISTS(SELECT 1 FROM pragma_table_info('sessions') WHERE name = ?)",
        "artifacts" => "SELECT EXISTS(SELECT 1 FROM pragma_table_info('artifacts') WHERE name = ?)",
        _ => panic!("unsupported test table {table}"),
    };
    sqlx::query_scalar(statement)
        .bind(column)
        .fetch_one(pool)
        .await
        .expect("column lookup")
}
