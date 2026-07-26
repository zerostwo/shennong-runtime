use std::sync::Arc;

use shennong_runtime::{
    AppState, RuntimeConfig,
    model::{
        ArtifactRule, IdeKind, JobSpec, JobState, NetworkPolicy, ResourceLimits, SessionSpec,
        SessionState,
    },
};

const IDE_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn startup_marks_unpersisted_executor_job_lost() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = directory.path().join("runtime.db");
    let database_url = format!("sqlite://{}?mode=rwc", database.display());
    let state = Arc::new(
        AppState::build(RuntimeConfig::for_test(database_url.clone()))
            .await
            .expect("initial state"),
    );
    let spec = JobSpec {
        api_version: "shennong.dev/v1".into(),
        workspace_ref: "ws_reconcile123".into(),
        worker_profile: "cpu-small".into(),
        argv: vec!["python3".into(), "analysis.py".into()],
        resources: ResourceLimits {
            cpus: 1.0,
            memory_bytes: 512 * 1024 * 1024,
            pids: 64,
            timeout_seconds: 30,
            tmpfs_bytes: 64 * 1024 * 1024,
            max_log_bytes: 64 * 1024,
            max_artifact_bytes: 1024 * 1024,
            max_workspace_bytes: 64 * 1024 * 1024,
        },
        network: NetworkPolicy::InternetOnly,
        workspace_files: vec![],
        artifact_rules: Vec::<ArtifactRule>::new(),
        compatibility_lock: None,
    };
    let job = state
        .journal
        .insert_job("user_test", "idem-reconcile-0001", "hash", &spec)
        .await
        .expect("insert job");
    state
        .journal
        .transition_job(job.view.id, JobState::Preparing, None, None, None)
        .await
        .expect("preparing state");
    drop(state);

    let restarted = Arc::new(
        AppState::build(RuntimeConfig::for_test(database_url))
            .await
            .expect("restarted state"),
    );
    restarted.reconcile().await.expect("reconcile");
    let recovered = restarted
        .journal
        .job(job.view.id)
        .await
        .expect("recovered job");
    assert_eq!(recovered.view.state, JobState::Lost);
    assert!(
        recovered
            .view
            .error
            .expect("lost reason")
            .contains("executor handle")
    );
}

#[tokio::test]
async fn restart_recovers_session_secret_and_missing_secret_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = directory.path().join("runtime.db");
    let database_url = format!("sqlite://{}?mode=rwc", database.display());
    let state = Arc::new(
        AppState::build(RuntimeConfig::for_test(database_url.clone()))
            .await
            .expect("initial state"),
    );
    let spec = session_spec("ws_keep_running");
    let recovered = state
        .journal
        .insert_session("user_test", "idem-secret-recovery", "hash-1", &spec)
        .await
        .expect("insert recoverable session");
    state
        .journal
        .activate_session(
            recovered.view.id,
            "mock-session-recovery-ws_keep_running",
            "http://127.0.0.1:9",
            IDE_SECRET,
        )
        .await
        .expect("activate recoverable session");

    let missing = state
        .journal
        .insert_session("user_test", "idem-secret-missing", "hash-2", &spec)
        .await
        .expect("insert missing-secret session");
    state
        .journal
        .activate_session(
            missing.view.id,
            "mock-session-missing-ws_keep_running",
            "http://127.0.0.1:9",
            IDE_SECRET,
        )
        .await
        .expect("activate missing-secret session");
    let pool = sqlx::SqlitePool::connect(&database_url)
        .await
        .expect("open test database");
    sqlx::query("UPDATE sessions SET internal_secret = NULL WHERE id = ?")
        .bind(missing.view.id.to_string())
        .execute(&pool)
        .await
        .expect("simulate legacy missing secret");
    pool.close().await;
    drop(state);

    let restarted = Arc::new(
        AppState::build(RuntimeConfig::for_test(database_url))
            .await
            .expect("restarted state"),
    );
    restarted.reconcile().await.expect("reconcile sessions");
    let recovered_record = restarted
        .journal
        .session(recovered.view.id)
        .await
        .expect("recovered session");
    assert_eq!(recovered_record.view.state, SessionState::Running);
    assert_eq!(
        recovered_record.internal_secret.as_deref(),
        Some(IDE_SECRET)
    );

    let missing_record = restarted
        .journal
        .session(missing.view.id)
        .await
        .expect("failed-closed session");
    assert_eq!(missing_record.view.state, SessionState::Failed);
    assert!(
        missing_record
            .view
            .error
            .expect("missing secret reason")
            .contains("gateway secret")
    );
    restarted
        .reconcile()
        .await
        .expect("persistently clean failed session");
    assert!(
        restarted
            .journal
            .session(missing.view.id)
            .await
            .expect("cleaned session")
            .executor_id
            .is_none()
    );
}

fn session_spec(workspace_ref: &str) -> SessionSpec {
    SessionSpec {
        api_version: "shennong.dev/v1".into(),
        workspace_ref: workspace_ref.into(),
        worker_profile: "ide-small".into(),
        kind: IdeKind::Jupyterlab,
        resources: ResourceLimits {
            cpus: 1.0,
            memory_bytes: 1024 * 1024 * 1024,
            pids: 128,
            timeout_seconds: 3600,
            tmpfs_bytes: 128 * 1024 * 1024,
            max_log_bytes: 64 * 1024,
            max_artifact_bytes: 1024 * 1024,
            max_workspace_bytes: 64 * 1024 * 1024,
        },
        network: NetworkPolicy::InternetOnly,
        idle_timeout_seconds: 300,
        max_lifetime_seconds: 3600,
    }
}
