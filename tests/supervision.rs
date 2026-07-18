use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use shennong_runtime::{
    AppState, RuntimeConfig,
    auth::RuntimeClaims,
    error::{Result, RuntimeError},
    executor::{Executor, SessionHandle},
    model::{
        ArtifactManifestEntry, ArtifactRule, ExecutionOutcome, ExecutorObservation, JobSpec,
        JobState, LogStream, NetworkPolicy, ResolvedJob, ResolvedSession, ResourceLimits,
    },
    router,
};
use tokio::{sync::Notify, time::sleep};
use tower::ServiceExt;

#[derive(Default)]
struct ControlledExecutor {
    block_launch: AtomicBool,
    launch_active: AtomicBool,
    launch_entered: Notify,
    launch_release: Notify,
    orphan_calls: AtomicUsize,
    orphan_overlap: AtomicBool,
    cleanup_failed_once: AtomicBool,
    cancel_failed_once: AtomicBool,
    cancel_calls: AtomicUsize,
    observed_missing: AtomicBool,
    ping_fails: AtomicBool,
    workspace_overquota: AtomicBool,
    cancel_always_fails: AtomicBool,
    cleanup_always_fails: AtomicBool,
    wait_millis: AtomicUsize,
}

#[async_trait]
impl Executor for ControlledExecutor {
    fn name(&self) -> &'static str {
        "controlled-test"
    }

    async fn ping(&self) -> Result<()> {
        if self.ping_fails.load(Ordering::SeqCst) {
            Err(RuntimeError::Executor("controlled ping failure".into()))
        } else {
            Ok(())
        }
    }

    async fn workspace_usage_bytes(&self, _workspace_volume: &str) -> Result<i64> {
        Ok(if self.workspace_overquota.load(Ordering::SeqCst) {
            i64::MAX
        } else {
            0
        })
    }

    async fn start_job(&self, job: &ResolvedJob) -> Result<String> {
        if self.block_launch.load(Ordering::SeqCst) {
            self.launch_active.store(true, Ordering::SeqCst);
            self.launch_entered.notify_one();
            self.launch_release.notified().await;
            self.launch_active.store(false, Ordering::SeqCst);
        }
        Ok(format!("launched-{}", job.id))
    }

    async fn wait_job(&self, _executor_id: &str, _job: &ResolvedJob) -> Result<ExecutionOutcome> {
        let wait_millis = self.wait_millis.load(Ordering::SeqCst);
        sleep(Duration::from_millis(if wait_millis == 0 {
            200
        } else {
            wait_millis as u64
        }))
        .await;
        Ok(ExecutionOutcome {
            exit_code: 0,
            logs: vec![(LogStream::Stdout, "done\n".into())],
        })
    }

    async fn collect_artifacts(&self, _job: &ResolvedJob) -> Result<Vec<ArtifactManifestEntry>> {
        Ok(Vec::new())
    }

    async fn cancel_job(&self, executor_id: &str) -> Result<()> {
        self.cancel_calls.fetch_add(1, Ordering::SeqCst);
        if self.cancel_always_fails.load(Ordering::SeqCst) {
            return Err(RuntimeError::Executor(
                "controlled persistent cancel failure".into(),
            ));
        }
        if executor_id == "cancel-flaky" && !self.cancel_failed_once.swap(true, Ordering::SeqCst) {
            Err(RuntimeError::Executor("controlled cancel failure".into()))
        } else {
            Ok(())
        }
    }

    async fn observe_job(&self, executor_id: &str) -> Result<ExecutorObservation> {
        match executor_id {
            "bad-observe" => Err(RuntimeError::Executor(
                "controlled observation failure".into(),
            )),
            "missing-good" => {
                self.observed_missing.store(true, Ordering::SeqCst);
                Ok(ExecutorObservation::Missing)
            }
            _ => Ok(ExecutorObservation::Running),
        }
    }

    async fn cleanup_job(&self, executor_id: &str) -> Result<()> {
        if self.cleanup_always_fails.load(Ordering::SeqCst) {
            return Err(RuntimeError::Executor(
                "controlled persistent cleanup failure".into(),
            ));
        }
        if executor_id == "cleanup-flaky" && !self.cleanup_failed_once.swap(true, Ordering::SeqCst)
        {
            Err(RuntimeError::Executor("controlled cleanup failure".into()))
        } else {
            Ok(())
        }
    }

    async fn cleanup_orphans(&self, _known_executor_ids: &HashSet<String>) -> Result<()> {
        self.orphan_calls.fetch_add(1, Ordering::SeqCst);
        if self.launch_active.load(Ordering::SeqCst) {
            self.orphan_overlap.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    async fn start_session(&self, session: &ResolvedSession) -> Result<SessionHandle> {
        Ok(SessionHandle {
            executor_id: format!("session-{}", session.id),
            internal_target: "http://127.0.0.1:9".into(),
        })
    }

    async fn stop_session(&self, _executor_id: &str) -> Result<()> {
        Ok(())
    }

    async fn observe_session(&self, _executor_id: &str) -> Result<ExecutorObservation> {
        Ok(ExecutorObservation::Running)
    }
}

#[tokio::test]
async fn launch_and_persistence_are_serialized_against_orphan_sweeps() {
    let (_directory, config) = test_config();
    let executor = Arc::new(ControlledExecutor::default());
    executor.block_launch.store(true, Ordering::SeqCst);
    let state = Arc::new(
        AppState::build_with_executor(config, executor.clone())
            .await
            .expect("build controlled state"),
    );
    let app = router(Arc::clone(&state));
    let request = Request::builder()
        .method("POST")
        .uri("/v1/jobs")
        .header("authorization", format!("Bearer {}", token()))
        .header("idempotency-key", "idem-serialized-launch")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&job_spec()).unwrap()))
        .unwrap();
    let submit = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    executor.launch_entered.notified().await;

    let reconcile_state = Arc::clone(&state);
    let reconcile = tokio::spawn(async move { reconcile_state.reconcile().await });
    sleep(Duration::from_millis(40)).await;
    assert_eq!(executor.orphan_calls.load(Ordering::SeqCst), 0);
    executor.launch_release.notify_one();
    assert_eq!(submit.await.unwrap().status(), StatusCode::ACCEPTED);
    reconcile.await.unwrap().expect("serialized reconcile");
    assert_eq!(executor.orphan_calls.load(Ordering::SeqCst), 1);
    assert!(!executor.orphan_overlap.load(Ordering::SeqCst));
}

#[tokio::test]
async fn reconciliation_retries_cleanup_and_cancellation_without_starving_records() {
    let (_directory, config) = test_config();
    let database_url = config.database_url.clone();
    let executor = Arc::new(ControlledExecutor::default());
    let seeded = Arc::new(
        AppState::build_with_executor(config, executor.clone())
            .await
            .expect("build seed state"),
    );
    let cleanup = insert_running_job(&seeded, "idem-cleanup", "cleanup-flaky").await;
    seeded
        .journal
        .transition_job(cleanup, JobState::Failed, None, None, Some("failed"))
        .await
        .expect("terminal cleanup record");
    let bad = insert_running_job(&seeded, "idem-bad-observe", "bad-observe").await;
    let missing = insert_running_job(&seeded, "idem-missing", "missing-good").await;
    let cancel = insert_running_job(&seeded, "idem-cancel", "cancel-flaky").await;
    seeded
        .journal
        .transition_job(cancel, JobState::CancelRequested, None, None, None)
        .await
        .expect("request cancellation");
    drop(seeded);

    let first = Arc::new(
        AppState::build_with_executor(
            RuntimeConfig::for_test(database_url.clone()),
            executor.clone(),
        )
        .await
        .expect("first restart"),
    );
    assert!(first.reconcile().await.is_err());
    assert!(executor.observed_missing.load(Ordering::SeqCst));
    assert_eq!(
        first.journal.job(missing).await.unwrap().view.state,
        JobState::Lost
    );
    assert_eq!(
        first.journal.job(cancel).await.unwrap().view.state,
        JobState::CancelRequested
    );
    assert_eq!(
        first.journal.job(bad).await.unwrap().view.state,
        JobState::Running
    );
    assert!(
        first
            .journal
            .job(cleanup)
            .await
            .unwrap()
            .executor_id
            .is_some()
    );
    drop(first);

    let second = Arc::new(
        AppState::build_with_executor(RuntimeConfig::for_test(database_url), executor.clone())
            .await
            .expect("second restart"),
    );
    assert!(second.reconcile().await.is_err());
    assert!(
        second
            .journal
            .job(cleanup)
            .await
            .unwrap()
            .executor_id
            .is_none()
    );
    assert_eq!(
        second.journal.job(cancel).await.unwrap().view.state,
        JobState::Cancelled
    );
    assert!(second.reconcile().await.is_err());
    assert!(
        second
            .journal
            .job(cancel)
            .await
            .unwrap()
            .executor_id
            .is_none()
    );
    assert!(executor.cancel_calls.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn health_fails_when_the_executor_is_unavailable() {
    let (_directory, config) = test_config();
    let executor = Arc::new(ControlledExecutor::default());
    executor.ping_fails.store(true, Ordering::SeqCst);
    let state = Arc::new(
        AppState::build_with_executor(config, executor)
            .await
            .expect("build unhealthy state"),
    );
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn quota_and_deadline_persist_terminal_cleanup_intent_before_kill() {
    let (_quota_directory, quota_config) = test_config();
    let quota_executor = Arc::new(ControlledExecutor::default());
    quota_executor
        .workspace_overquota
        .store(true, Ordering::SeqCst);
    quota_executor
        .cancel_always_fails
        .store(true, Ordering::SeqCst);
    quota_executor
        .cleanup_always_fails
        .store(true, Ordering::SeqCst);
    quota_executor.wait_millis.store(500, Ordering::SeqCst);
    let quota_state = Arc::new(
        AppState::build_with_executor(quota_config, quota_executor.clone())
            .await
            .expect("build quota state"),
    );
    assert_eq!(
        submit_job(
            router(Arc::clone(&quota_state)),
            "idem-policy-quota",
            job_spec()
        )
        .await,
        StatusCode::ACCEPTED
    );
    sleep(Duration::from_millis(100)).await;
    let quota_job = quota_state
        .journal
        .job_by_idempotency("user_test", "idem-policy-quota")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(quota_job.view.state, JobState::Failed);
    assert!(quota_job.executor_id.is_some());
    quota_executor
        .cancel_always_fails
        .store(false, Ordering::SeqCst);
    quota_executor
        .cleanup_always_fails
        .store(false, Ordering::SeqCst);
    quota_state.reconcile().await.expect("retry quota cleanup");
    assert!(
        quota_state
            .journal
            .job(quota_job.view.id)
            .await
            .unwrap()
            .executor_id
            .is_none()
    );

    let (_deadline_directory, deadline_config) = test_config();
    let deadline_executor = Arc::new(ControlledExecutor::default());
    deadline_executor
        .cancel_always_fails
        .store(true, Ordering::SeqCst);
    deadline_executor
        .cleanup_always_fails
        .store(true, Ordering::SeqCst);
    deadline_executor.wait_millis.store(2_000, Ordering::SeqCst);
    let deadline_state = Arc::new(
        AppState::build_with_executor(deadline_config, deadline_executor.clone())
            .await
            .expect("build deadline state"),
    );
    let mut deadline_spec = job_spec();
    deadline_spec.resources.timeout_seconds = 1;
    assert_eq!(
        submit_job(
            router(Arc::clone(&deadline_state)),
            "idem-policy-deadline",
            deadline_spec,
        )
        .await,
        StatusCode::ACCEPTED
    );
    sleep(Duration::from_millis(1_150)).await;
    let deadline_job = deadline_state
        .journal
        .job_by_idempotency("user_test", "idem-policy-deadline")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deadline_job.view.state, JobState::TimedOut);
    assert!(deadline_job.executor_id.is_some());
    deadline_executor
        .cleanup_always_fails
        .store(false, Ordering::SeqCst);
    deadline_state
        .reconcile()
        .await
        .expect("retry deadline cleanup");
    assert!(
        deadline_state
            .journal
            .job(deadline_job.view.id)
            .await
            .unwrap()
            .executor_id
            .is_none()
    );
}

async fn insert_running_job(state: &AppState, key: &str, executor_id: &str) -> uuid::Uuid {
    let job = state
        .journal
        .insert_job("user_test", key, key, &job_spec())
        .await
        .expect("insert job");
    state
        .journal
        .transition_job(job.view.id, JobState::Preparing, None, None, None)
        .await
        .expect("prepare job");
    state
        .journal
        .transition_job(
            job.view.id,
            JobState::Running,
            Some(executor_id),
            None,
            None,
        )
        .await
        .expect("run job");
    job.view.id
}

fn test_config() -> (tempfile::TempDir, RuntimeConfig) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = directory.path().join("runtime.db");
    let config = RuntimeConfig::for_test(format!("sqlite://{}?mode=rwc", database.display()));
    (directory, config)
}

fn job_spec() -> JobSpec {
    JobSpec {
        api_version: "shennong.dev/v1".into(),
        workspace_ref: "ws_test123".into(),
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
    }
}

fn token() -> String {
    let now = Utc::now().timestamp();
    encode(
        &Header::default(),
        &RuntimeClaims {
            iss: "shennong-os".into(),
            aud: "shennong-runtime".into(),
            sub: "user_test".into(),
            exp: now + 60,
            iat: now,
            nbf: None,
            jti: "supervision-test".into(),
            scopes: vec!["runtime:jobs:write".into(), "runtime:jobs:read".into()],
            workspace_refs: vec!["ws_test123".into()],
        },
        &EncodingKey::from_secret(b"test-secret-at-least-32-bytes-long"),
    )
    .expect("encode test token")
}

async fn submit_job(app: Router, key: &str, spec: JobSpec) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/v1/jobs")
            .header("authorization", format!("Bearer {}", token()))
            .header("idempotency-key", key)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&spec).unwrap()))
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}
