use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::Utc;
use globset::Glob;
use sha2::{Digest, Sha256};
use tokio::{
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, watch},
    time::{MissedTickBehavior, interval, sleep},
};
use uuid::Uuid;

use crate::{
    auth::{JwtVerifier, Principal},
    config::{DockerMode, ExecutorKind, RuntimeConfig},
    error::{Result, RuntimeError},
    executor::{DockerExecutor, Executor, MockExecutor, workspace_volume_name},
    journal::Journal,
    model::{
        ArtifactManifestEntry, ExecutorObservation, JobRecord, JobSpec, JobState, JobView,
        LogEntry, LogStream, ResolvedJob, ResolvedSession, SessionRecord, SessionSpec,
        SessionState, SessionView, WorkerProfile,
    },
};

pub struct AppState {
    pub config: RuntimeConfig,
    pub journal: Journal,
    pub executor: Arc<dyn Executor>,
    pub jwt: JwtVerifier,
    pub proxy_client: reqwest::Client,
    job_slots: Arc<Semaphore>,
    session_slots: Arc<Semaphore>,
    job_monitors: Mutex<HashSet<Uuid>>,
    session_monitors: Mutex<HashSet<Uuid>>,
    executor_mutation: AsyncMutex<()>,
    session_cancellations: Mutex<HashMap<Uuid, watch::Sender<bool>>>,
}

pub(crate) struct SessionProxyTarget {
    pub base_url: String,
    pub secret: String,
    pub cancellation: watch::Receiver<bool>,
}

impl AppState {
    pub async fn build(config: RuntimeConfig) -> Result<Self> {
        let executor: Arc<dyn Executor> = match config.executor_kind {
            ExecutorKind::Mock => Arc::new(MockExecutor),
            ExecutorKind::Docker => Arc::new(
                DockerExecutor::connect(
                    config
                        .docker_socket
                        .as_deref()
                        .ok_or_else(|| RuntimeError::Internal("missing docker socket".into()))?,
                    config.job_network.clone(),
                    config.session_network.clone(),
                    config.runtime_instance_id.clone(),
                    config.egress_policy.clone(),
                    config.docker_mode == DockerMode::Hardened,
                )
                .await?,
            ),
        };
        Self::build_with_executor(config, executor).await
    }

    #[doc(hidden)]
    pub async fn build_with_executor(
        config: RuntimeConfig,
        executor: Arc<dyn Executor>,
    ) -> Result<Self> {
        let job_slots = Arc::new(Semaphore::new(config.max_concurrent_jobs));
        let session_slots = Arc::new(Semaphore::new(config.max_concurrent_sessions));
        let journal = Journal::connect(&config.database_url).await?;
        let jwt = JwtVerifier::new(&config)?;
        let proxy_client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| RuntimeError::Internal(error.to_string()))?;
        Ok(Self {
            config,
            journal,
            executor,
            jwt,
            proxy_client,
            job_slots,
            session_slots,
            job_monitors: Mutex::new(HashSet::new()),
            session_monitors: Mutex::new(HashSet::new()),
            executor_mutation: AsyncMutex::new(()),
            session_cancellations: Mutex::new(HashMap::new()),
        })
    }

    pub async fn reconcile(self: &Arc<Self>) -> Result<()> {
        let mut failures = Vec::new();
        let executor_guard = self.executor_mutation.lock().await;
        if let Err(error) = self.cleanup_pending_executors().await {
            failures.push(format!("pending cleanup: {error}"));
        }
        let active_jobs = self.journal.active_jobs().await?;
        let active_sessions = self.journal.active_sessions().await?;
        let known_executor_ids = self.journal.executor_ids().await?;
        if let Err(error) = self.executor.cleanup_orphans(&known_executor_ids).await {
            failures.push(format!("orphan cleanup: {error}"));
        }
        drop(executor_guard);

        for job in active_jobs {
            if self
                .job_monitors
                .lock()
                .expect("job monitor registry poisoned")
                .contains(&job.view.id)
            {
                continue;
            }
            let Some(executor_id) = job.executor_id.clone() else {
                if let Err(error) = self
                    .journal
                    .transition_job(
                        job.view.id,
                        JobState::Lost,
                        None,
                        None,
                        Some("daemon restarted before an executor handle was persisted"),
                    )
                    .await
                {
                    failures.push(format!("job {} missing handle: {error}", job.view.id));
                }
                continue;
            };
            let observation = match self.executor.observe_job(&executor_id).await {
                Ok(observation) => observation,
                Err(error) => {
                    failures.push(format!("job {} observation: {error}", job.view.id));
                    continue;
                }
            };
            match observation {
                observation @ (ExecutorObservation::Running | ExecutorObservation::Exited(_)) => {
                    if job.view.state == JobState::CancelRequested {
                        let cancellation = if matches!(observation, ExecutorObservation::Running) {
                            self.executor.cancel_job(&executor_id).await
                        } else {
                            Ok(())
                        };
                        match cancellation {
                            Ok(()) => {
                                if let Err(error) = self
                                    .journal
                                    .transition_job(
                                        job.view.id,
                                        JobState::Cancelled,
                                        None,
                                        None,
                                        None,
                                    )
                                    .await
                                {
                                    failures.push(format!(
                                        "job {} cancellation persistence: {error}",
                                        job.view.id
                                    ));
                                }
                            }
                            Err(error) => failures
                                .push(format!("job {} cancellation retry: {error}", job.view.id)),
                        }
                        continue;
                    }
                    let permit = match Arc::clone(&self.job_slots).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            if let Err(error) = self
                                .journal
                                .transition_job(
                                    job.view.id,
                                    JobState::Failed,
                                    None,
                                    None,
                                    Some("active Job exceeded configured capacity after restart"),
                                )
                                .await
                            {
                                failures.push(format!(
                                    "job {} capacity failure persistence: {error}",
                                    job.view.id
                                ));
                                continue;
                            }
                            if let Err(error) = self.executor.cancel_job(&executor_id).await {
                                failures
                                    .push(format!("job {} capacity cleanup: {error}", job.view.id));
                            }
                            continue;
                        }
                    };
                    self.spawn_job_monitor(
                        job.view.id,
                        executor_id,
                        remaining_job_timeout(&job),
                        permit,
                    );
                }
                ExecutorObservation::Missing => {
                    let state = if job.view.state == JobState::CancelRequested {
                        JobState::Cancelled
                    } else {
                        JobState::Lost
                    };
                    if let Err(error) = self
                        .journal
                        .transition_job(
                            job.view.id,
                            state,
                            None,
                            None,
                            Some("executor object was missing during reconciliation"),
                        )
                        .await
                    {
                        failures.push(format!("job {} missing transition: {error}", job.view.id));
                    }
                }
            }
        }

        for session in active_sessions {
            if self
                .session_monitors
                .lock()
                .expect("session monitor registry poisoned")
                .contains(&session.view.id)
            {
                continue;
            }
            if session.view.expires_at <= Utc::now() {
                self.expire_session(session.view.id, "absolute Session lifetime exceeded")
                    .await;
                continue;
            }
            if session.internal_secret.is_none() {
                if let Err(error) = self
                    .journal
                    .update_session(
                        session.view.id,
                        SessionState::Failed,
                        None,
                        None,
                        Some("active IDE has no persisted internal gateway secret"),
                    )
                    .await
                {
                    failures.push(format!(
                        "session {} missing secret persistence: {error}",
                        session.view.id
                    ));
                    continue;
                }
                self.revoke_session_proxy(session.view.id);
                if let Some(executor_id) = session.executor_id.as_deref()
                    && let Err(error) = self.executor.stop_session(executor_id).await
                {
                    failures.push(format!(
                        "session {} missing secret cleanup: {error}",
                        session.view.id
                    ));
                }
                continue;
            }
            let Some(executor_id) = session.executor_id.as_deref() else {
                if let Err(error) = self
                    .journal
                    .update_session(
                        session.view.id,
                        SessionState::Lost,
                        None,
                        None,
                        Some("daemon restarted before an executor handle was persisted"),
                    )
                    .await
                {
                    failures.push(format!(
                        "session {} missing handle: {error}",
                        session.view.id
                    ));
                }
                self.revoke_session_proxy(session.view.id);
                continue;
            };
            let observation = match self.executor.observe_session(executor_id).await {
                Ok(observation) => observation,
                Err(error) => {
                    failures.push(format!("session {} observation: {error}", session.view.id));
                    continue;
                }
            };
            match observation {
                ExecutorObservation::Running => {
                    if session.view.state == SessionState::StopRequested {
                        if let Err(error) = self
                            .journal
                            .update_session(
                                session.view.id,
                                SessionState::Stopped,
                                None,
                                None,
                                None,
                            )
                            .await
                        {
                            failures.push(format!(
                                "session {} stop persistence: {error}",
                                session.view.id
                            ));
                            continue;
                        }
                        self.revoke_session_proxy(session.view.id);
                        if let Err(error) = self.executor.stop_session(executor_id).await {
                            failures
                                .push(format!("session {} stop retry: {error}", session.view.id));
                        }
                    } else {
                        let permit = match Arc::clone(&self.session_slots).try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                if let Err(error) = self
                                    .journal
                                    .update_session(
                                        session.view.id,
                                        SessionState::Failed,
                                        None,
                                        None,
                                        Some(
                                            "active IDE exceeded configured capacity after restart",
                                        ),
                                    )
                                    .await
                                {
                                    failures.push(format!(
                                        "session {} capacity failure persistence: {error}",
                                        session.view.id
                                    ));
                                    continue;
                                }
                                self.revoke_session_proxy(session.view.id);
                                if let Err(error) = self.executor.stop_session(executor_id).await {
                                    failures.push(format!(
                                        "session {} capacity cleanup: {error}",
                                        session.view.id
                                    ));
                                }
                                continue;
                            }
                        };
                        self.schedule_session_expiry(session.view.clone());
                        let _ = self.session_cancellation(session.view.id);
                        self.spawn_session_monitor(session.view.id, executor_id.to_owned(), permit);
                    }
                }
                ExecutorObservation::Exited(code) => {
                    let next = if session.view.state == SessionState::StopRequested {
                        SessionState::Stopped
                    } else {
                        SessionState::Failed
                    };
                    let error = (next == SessionState::Failed)
                        .then(|| format!("IDE container exited with code {code}"));
                    if let Err(persist_error) = self
                        .journal
                        .update_session(session.view.id, next, None, None, error.as_deref())
                        .await
                    {
                        failures.push(format!(
                            "session {} exit persistence: {persist_error}",
                            session.view.id
                        ));
                    } else {
                        self.revoke_session_proxy(session.view.id);
                        if let Err(cleanup_error) = self.executor.cleanup_job(executor_id).await {
                            failures.push(format!(
                                "session {} exit cleanup: {cleanup_error}",
                                session.view.id
                            ));
                        } else if let Err(clear_error) = self
                            .journal
                            .clear_session_executor(session.view.id, executor_id)
                            .await
                        {
                            failures.push(format!(
                                "session {} exit handle clear: {clear_error}",
                                session.view.id
                            ));
                        }
                    }
                }
                ExecutorObservation::Missing => {
                    let next = if session.view.state == SessionState::StopRequested {
                        SessionState::Stopped
                    } else {
                        SessionState::Lost
                    };
                    let error = (next == SessionState::Lost)
                        .then_some("IDE container missing during reconciliation");
                    if let Err(error) = self
                        .journal
                        .update_session(session.view.id, next, None, None, error)
                        .await
                    {
                        failures.push(format!(
                            "session {} missing transition: {error}",
                            session.view.id
                        ));
                    } else {
                        self.revoke_session_proxy(session.view.id);
                    }
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError::Executor(format!(
                "reconciliation completed with failures: {}",
                failures.join("; ")
            )))
        }
    }

    pub fn spawn_maintenance(self: &Arc<Self>) {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                sleep(state.config.monitor_interval).await;
                if let Err(error) = state.reconcile().await {
                    tracing::warn!(%error, "periodic executor reconciliation failed");
                }
            }
        });
    }

    fn session_cancellation(&self, id: Uuid) -> watch::Receiver<bool> {
        let mut cancellations = self
            .session_cancellations
            .lock()
            .expect("session cancellation registry poisoned");
        cancellations
            .entry(id)
            .or_insert_with(|| watch::channel(false).0)
            .subscribe()
    }

    fn revoke_session_proxy(&self, id: Uuid) {
        if let Some(sender) = self
            .session_cancellations
            .lock()
            .expect("session cancellation registry poisoned")
            .remove(&id)
        {
            let _ = sender.send(true);
        }
    }

    async fn cleanup_pending_executors(&self) -> Result<()> {
        let mut failures = Vec::new();
        for (id, executor_id) in self.journal.pending_job_cleanups().await? {
            match self.executor.cleanup_job(&executor_id).await {
                Ok(()) => {
                    if let Err(error) = self.journal.clear_job_executor(id, &executor_id).await {
                        failures.push(format!("Job {id} handle clear: {error}"));
                    }
                }
                Err(error) => {
                    failures.push(format!("Job {id} executor {executor_id}: {error}"));
                }
            }
        }
        for (id, executor_id) in self.journal.pending_session_cleanups().await? {
            match self.executor.cleanup_job(&executor_id).await {
                Ok(()) => {
                    if let Err(error) = self.journal.clear_session_executor(id, &executor_id).await
                    {
                        failures.push(format!("Session {id} handle clear: {error}"));
                    }
                }
                Err(error) => {
                    failures.push(format!("Session {id} executor {executor_id}: {error}"));
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError::Executor(format!(
                "pending executor cleanup failures: {}",
                failures.join("; ")
            )))
        }
    }

    pub async fn submit_job(
        self: &Arc<Self>,
        principal: &Principal,
        idempotency_key: &str,
        spec: JobSpec,
    ) -> Result<JobView> {
        principal.require_scope("runtime:jobs:write")?;
        principal.require_workspace(&spec.workspace_ref)?;
        validate_idempotency_key(idempotency_key)?;
        let profile = self.batch_profile(&spec.worker_profile)?.clone();
        spec.validate(&profile)?;
        let request_hash = request_hash(&spec)?;

        if let Some(existing) = self
            .journal
            .job_by_idempotency(&principal.subject, idempotency_key)
            .await?
        {
            ensure_same_request(&existing.request_hash, &request_hash)?;
            return Ok(existing.view);
        }

        let permit = Arc::clone(&self.job_slots)
            .try_acquire_owned()
            .map_err(|_| RuntimeError::Capacity("concurrent Job limit reached".into()))?;
        let executor_guard = self.executor_mutation.lock().await;

        let job = match self
            .journal
            .insert_job(&principal.subject, idempotency_key, &request_hash, &spec)
            .await
        {
            Ok(job) => job,
            Err(RuntimeError::Conflict(_)) => {
                let existing = self
                    .journal
                    .job_by_idempotency(&principal.subject, idempotency_key)
                    .await?
                    .ok_or_else(|| RuntimeError::Conflict("idempotent insert raced".into()))?;
                ensure_same_request(&existing.request_hash, &request_hash)?;
                return Ok(existing.view);
            }
            Err(error) => return Err(error),
        };
        self.journal
            .transition_job(job.view.id, JobState::Preparing, None, None, None)
            .await?;
        let resolved = ResolvedJob {
            id: job.view.id,
            workspace_volume: workspace_volume_name(&spec.workspace_ref),
            spec: spec.clone(),
            profile,
        };
        let executor_id = match self.executor.start_job(&resolved).await {
            Ok(id) => id,
            Err(error) => {
                self.journal
                    .transition_job(
                        job.view.id,
                        JobState::Failed,
                        None,
                        None,
                        Some(&error.to_string()),
                    )
                    .await?;
                return Err(error);
            }
        };
        let running = match self
            .journal
            .transition_job(
                job.view.id,
                JobState::Running,
                Some(&executor_id),
                None,
                None,
            )
            .await
        {
            Ok(running) => running,
            Err(error) => {
                let _ = self.executor.cancel_job(&executor_id).await;
                let _ = self.executor.cleanup_job(&executor_id).await;
                let _ = self
                    .journal
                    .transition_job(
                        job.view.id,
                        JobState::Failed,
                        None,
                        None,
                        Some("executor handle could not be persisted"),
                    )
                    .await;
                return Err(error);
            }
        };
        let remaining = remaining_job_timeout(&running);
        self.spawn_job_monitor(job.view.id, executor_id, remaining, permit);
        drop(executor_guard);
        Ok(running.view)
    }

    pub async fn get_job(&self, principal: &Principal, id: Uuid) -> Result<JobView> {
        principal.require_scope("runtime:jobs:read")?;
        let job = self.owned_job(principal, id).await?;
        Ok(job.view)
    }

    pub async fn cancel_job(&self, principal: &Principal, id: Uuid) -> Result<JobView> {
        principal.require_scope("runtime:jobs:cancel")?;
        let job = self.owned_job(principal, id).await?;
        if job.view.state.is_terminal() {
            return Ok(job.view);
        }
        let requested = self
            .journal
            .transition_job(id, JobState::CancelRequested, None, None, None)
            .await?;
        if let Some(executor_id) = requested.executor_id.as_deref() {
            self.executor.cancel_job(executor_id).await?;
        }
        Ok(self
            .journal
            .transition_job(id, JobState::Cancelled, None, None, None)
            .await?
            .view)
    }

    pub async fn job_logs(
        &self,
        principal: &Principal,
        id: Uuid,
        after: i64,
        limit: u32,
    ) -> Result<Vec<LogEntry>> {
        principal.require_scope("runtime:jobs:read")?;
        self.owned_job(principal, id).await?;
        if after < 0 || limit == 0 {
            return Err(RuntimeError::Validation(
                "log cursor and limit must be positive".into(),
            ));
        }
        self.journal
            .logs(id, after, limit.min(self.config.max_log_page_size))
            .await
    }

    pub async fn job_artifacts(
        &self,
        principal: &Principal,
        id: Uuid,
    ) -> Result<Vec<ArtifactManifestEntry>> {
        principal.require_scope("runtime:jobs:read")?;
        self.owned_job(principal, id).await?;
        self.journal.artifacts(id).await
    }

    pub async fn submit_session(
        self: &Arc<Self>,
        principal: &Principal,
        idempotency_key: &str,
        spec: SessionSpec,
    ) -> Result<SessionView> {
        principal.require_scope("runtime:sessions:write")?;
        principal.require_workspace(&spec.workspace_ref)?;
        validate_idempotency_key(idempotency_key)?;
        let profile = self.ide_profile(&spec.worker_profile)?.clone();
        spec.validate(&profile)?;
        let request_hash = request_hash(&spec)?;
        if let Some(existing) = self
            .journal
            .session_by_idempotency(&principal.subject, idempotency_key)
            .await?
        {
            ensure_same_request(&existing.request_hash, &request_hash)?;
            return Ok(existing.view);
        }
        let permit = Arc::clone(&self.session_slots)
            .try_acquire_owned()
            .map_err(|_| RuntimeError::Capacity("concurrent IDE Session limit reached".into()))?;
        let executor_guard = self.executor_mutation.lock().await;
        let session = match self
            .journal
            .insert_session(&principal.subject, idempotency_key, &request_hash, &spec)
            .await
        {
            Ok(session) => session,
            Err(RuntimeError::Conflict(_)) => {
                let existing = self
                    .journal
                    .session_by_idempotency(&principal.subject, idempotency_key)
                    .await?
                    .ok_or_else(|| RuntimeError::Conflict("idempotent insert raced".into()))?;
                ensure_same_request(&existing.request_hash, &request_hash)?;
                return Ok(existing.view);
            }
            Err(error) => return Err(error),
        };
        let resolved = ResolvedSession {
            id: session.view.id,
            workspace_volume: workspace_volume_name(&spec.workspace_ref),
            spec: spec.clone(),
            profile,
            internal_secret: generate_session_secret()?,
        };
        let handle = match self.executor.start_session(&resolved).await {
            Ok(handle) => handle,
            Err(error) => {
                self.journal
                    .update_session(
                        session.view.id,
                        SessionState::Failed,
                        None,
                        None,
                        Some(&error.to_string()),
                    )
                    .await?;
                return Err(error);
            }
        };
        let running = match self
            .journal
            .activate_session(
                session.view.id,
                &handle.executor_id,
                &handle.internal_target,
                &resolved.internal_secret,
            )
            .await
        {
            Ok(running) => running,
            Err(error) => {
                let _ = self.executor.stop_session(&handle.executor_id).await;
                let _ = self
                    .journal
                    .update_session(
                        session.view.id,
                        SessionState::Failed,
                        None,
                        None,
                        Some("executor handle could not be persisted"),
                    )
                    .await;
                return Err(error);
            }
        };
        self.schedule_session_expiry(running.view.clone());
        let _ = self.session_cancellation(running.view.id);
        self.spawn_session_monitor(running.view.id, handle.executor_id, permit);
        drop(executor_guard);
        Ok(running.view)
    }

    pub async fn get_session(&self, principal: &Principal, id: Uuid) -> Result<SessionView> {
        principal.require_scope("runtime:sessions:read")?;
        Ok(self.owned_session(principal, id).await?.view)
    }

    pub async fn stop_session(&self, principal: &Principal, id: Uuid) -> Result<SessionView> {
        principal.require_scope("runtime:sessions:write")?;
        let session = self.owned_session(principal, id).await?;
        if session.view.state.is_terminal() {
            return Ok(session.view);
        }
        self.journal
            .update_session(id, SessionState::StopRequested, None, None, None)
            .await?;
        self.revoke_session_proxy(id);
        let executor_id = session.executor_id.clone();
        if let Some(executor_id) = executor_id.as_deref() {
            self.executor.stop_session(executor_id).await?;
        }
        let stopped = self
            .journal
            .update_session(id, SessionState::Stopped, None, None, None)
            .await?;
        if let Some(executor_id) = executor_id.as_deref() {
            self.journal.clear_session_executor(id, executor_id).await?;
        }
        Ok(stopped.view)
    }

    pub(crate) async fn session_proxy_target(
        &self,
        principal: &Principal,
        id: Uuid,
    ) -> Result<SessionProxyTarget> {
        principal.require_scope("runtime:sessions:proxy")?;
        let session = self.owned_session(principal, id).await?;
        if session.view.state != SessionState::Running {
            return Err(RuntimeError::Conflict(
                "IDE session is not in running state".into(),
            ));
        }
        let target = session
            .view
            .internal_target
            .ok_or_else(|| RuntimeError::Internal("session target is missing".into()))?;
        let parsed = reqwest::Url::parse(&target)
            .map_err(|error| RuntimeError::Internal(format!("invalid session target: {error}")))?;
        if parsed.scheme() != "http"
            || parsed.host_str() != Some("127.0.0.1")
            || parsed.port().is_none()
            || parsed.path() != "/"
        {
            return Err(RuntimeError::Internal(
                "session target violated the loopback-only invariant".into(),
            ));
        }
        let secret = session
            .internal_secret
            .ok_or_else(|| RuntimeError::Internal("session gateway secret is missing".into()))?;
        let cancellation = self.session_cancellation(id);
        if let Err(error) = self.journal.touch_session_activity(id).await {
            self.revoke_session_proxy(id);
            return Err(error);
        }
        Ok(SessionProxyTarget {
            base_url: target,
            secret,
            cancellation,
        })
    }

    fn spawn_job_monitor(
        self: &Arc<Self>,
        job_id: Uuid,
        executor_id: String,
        timeout_seconds: u64,
        permit: OwnedSemaphorePermit,
    ) {
        if !self
            .job_monitors
            .lock()
            .expect("job monitor registry poisoned")
            .insert(job_id)
        {
            return;
        }
        let state = Arc::clone(self);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = state
                .monitor_job(job_id, &executor_id, timeout_seconds)
                .await
            {
                if matches!(&error, RuntimeError::Conflict(_)) {
                    tracing::debug!(%job_id, %error, "job monitor lost a terminal-state race");
                } else if matches!(&error, RuntimeError::Executor(_) | RuntimeError::Journal(_)) {
                    tracing::warn!(%job_id, %error, "job supervision interrupted; reconciliation will resume it");
                } else {
                    tracing::error!(%job_id, %error, "job monitor failed");
                    if let Ok(current) = state.journal.job(job_id).await
                        && !current.view.state.is_terminal()
                    {
                        let next = if current.view.state == JobState::CancelRequested {
                            JobState::Cancelled
                        } else {
                            JobState::Failed
                        };
                        let _ = state
                            .journal
                            .transition_job(job_id, next, None, None, Some(&error.to_string()))
                            .await;
                    }
                }
            }
            if state
                .journal
                .job(job_id)
                .await
                .is_ok_and(|job| job.view.state.is_terminal())
                && state.executor.cleanup_job(&executor_id).await.is_ok()
            {
                let _ = state.journal.clear_job_executor(job_id, &executor_id).await;
            }
            state
                .job_monitors
                .lock()
                .expect("job monitor registry poisoned")
                .remove(&job_id);
        });
    }

    async fn monitor_job(
        &self,
        job_id: Uuid,
        executor_id: &str,
        timeout_seconds: u64,
    ) -> Result<()> {
        let job = self.journal.job(job_id).await?;
        let profile = self.batch_profile(&job.spec.worker_profile)?.clone();
        let resolved = ResolvedJob {
            id: job_id,
            workspace_volume: workspace_volume_name(&job.spec.workspace_ref),
            spec: job.spec.clone(),
            profile,
        };
        let execution = self.executor.wait_job(executor_id, &resolved);
        tokio::pin!(execution);
        let deadline = sleep(Duration::from_secs(timeout_seconds));
        tokio::pin!(deadline);
        let mut quota_poll = interval(self.config.monitor_interval);
        quota_poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut quota_failures = 0_u8;
        let outcome = loop {
            tokio::select! {
                outcome = &mut execution => break outcome?,
                _ = &mut deadline => {
                let current = self.journal.job(job_id).await?;
                let terminal = if current.view.state == JobState::CancelRequested {
                    JobState::Cancelled
                } else {
                    JobState::TimedOut
                };
                self.journal
                    .append_log(
                        job_id,
                        LogStream::System,
                        "runtime deadline exceeded\n",
                        job.spec.resources.max_log_bytes,
                    )
                    .await?;
                self.journal
                    .transition_job(job_id, terminal, None, None, None)
                    .await?;
                let _ = self.executor.cancel_job(executor_id).await;
                return Ok(());
                }
                _ = quota_poll.tick() => {
                    let current = self.journal.job(job_id).await?;
                    if current.view.state == JobState::CancelRequested {
                        self.journal
                            .transition_job(job_id, JobState::Cancelled, None, None, None)
                            .await?;
                        let _ = self.executor.cancel_job(executor_id).await;
                        return Ok(());
                    }
                    if current.view.state.is_terminal() {
                        return Ok(());
                    }
                    let usage = match self
                        .executor
                        .workspace_usage_bytes(&resolved.workspace_volume)
                        .await
                    {
                        Ok(usage) => {
                            quota_failures = 0;
                            usage
                        }
                        Err(error) => {
                            quota_failures = quota_failures.saturating_add(1);
                            if quota_failures < 3 {
                                tracing::warn!(%job_id, %error, quota_failures, "workspace quota measurement failed; retrying fail-closed check");
                                continue;
                            }
                            let message = format!(
                                "workspace quota measurement failed closed after {quota_failures} attempts: {error}"
                            );
                            self.journal
                                .append_log(
                                    job_id,
                                    LogStream::System,
                                    &format!("{message}\n"),
                                    job.spec.resources.max_log_bytes,
                                )
                                .await?;
                            self.journal
                                .transition_job(
                                    job_id,
                                    JobState::Failed,
                                    None,
                                    None,
                                    Some(&message),
                                )
                                .await?;
                            let _ = self.executor.cancel_job(executor_id).await;
                            return Ok(());
                        }
                    };
                    if usage > job.spec.resources.max_workspace_bytes {
                        let message = format!(
                            "workspace quota exceeded: {usage} > {} bytes\n",
                            job.spec.resources.max_workspace_bytes
                        );
                        self.journal
                            .append_log(
                                job_id,
                                LogStream::System,
                                &message,
                                job.spec.resources.max_log_bytes,
                            )
                            .await?;
                        self.journal
                            .transition_job(
                                job_id,
                                JobState::Failed,
                                None,
                                None,
                                Some(message.trim()),
                            )
                            .await?;
                        let _ = self.executor.cancel_job(executor_id).await;
                        return Ok(());
                    }
                }
            }
        };

        let final_usage = self
            .executor
            .workspace_usage_bytes(&resolved.workspace_volume)
            .await;
        let final_quota_error = match final_usage {
            Ok(usage) if usage > job.spec.resources.max_workspace_bytes => Some(format!(
                "workspace quota exceeded at worker exit: {usage} > {} bytes",
                job.spec.resources.max_workspace_bytes
            )),
            Ok(_) => None,
            Err(error) => Some(format!(
                "workspace quota measurement failed closed at worker exit: {error}"
            )),
        };
        if let Some(error) = final_quota_error {
            self.journal
                .append_log(
                    job_id,
                    LogStream::System,
                    &format!("{error}\n"),
                    job.spec.resources.max_log_bytes,
                )
                .await?;
            self.journal
                .transition_job(job_id, JobState::Failed, None, None, Some(&error))
                .await?;
            return Ok(());
        }

        for (stream, message) in outcome.logs {
            self.journal
                .append_log(job_id, stream, &message, job.spec.resources.max_log_bytes)
                .await?;
        }
        let artifacts = if outcome.exit_code == 0 {
            let _executor_guard = self.executor_mutation.lock().await;
            self.executor.collect_artifacts(&resolved).await?
        } else {
            Vec::new()
        };
        validate_artifacts(&job.spec, &artifacts)?;
        self.journal.replace_artifacts(job_id, &artifacts).await?;
        let current = self.journal.job(job_id).await?;
        if current.view.state.is_terminal() {
            return Ok(());
        }
        let next = if current.view.state == JobState::CancelRequested {
            JobState::Cancelled
        } else if outcome.exit_code == 0 {
            JobState::Succeeded
        } else {
            JobState::Failed
        };
        let error = (outcome.exit_code != 0)
            .then(|| format!("worker exited with code {}", outcome.exit_code));
        self.journal
            .transition_job(
                job_id,
                next,
                None,
                Some(outcome.exit_code),
                error.as_deref(),
            )
            .await?;
        Ok(())
    }

    fn schedule_session_expiry(self: &Arc<Self>, view: SessionView) {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            let delay = (view.expires_at - Utc::now())
                .to_std()
                .unwrap_or(Duration::ZERO);
            sleep(delay).await;
            state
                .expire_session(view.id, "absolute Session lifetime exceeded")
                .await;
        });
    }

    fn spawn_session_monitor(
        self: &Arc<Self>,
        session_id: Uuid,
        executor_id: String,
        permit: OwnedSemaphorePermit,
    ) {
        if !self
            .session_monitors
            .lock()
            .expect("session monitor registry poisoned")
            .insert(session_id)
        {
            return;
        }
        let state = Arc::clone(self);
        tokio::spawn(async move {
            let _permit = permit;
            let mut quota_failures = 0_u8;
            loop {
                sleep(state.config.monitor_interval).await;
                let Ok(session) = state.journal.session(session_id).await else {
                    break;
                };
                if session.view.state.is_terminal() {
                    break;
                }
                if session.view.state == SessionState::StopRequested {
                    if state
                        .journal
                        .update_session(session_id, SessionState::Stopped, None, None, None)
                        .await
                        .is_ok()
                    {
                        state.revoke_session_proxy(session_id);
                        let _ = state.executor.stop_session(&executor_id).await;
                    }
                    break;
                }
                let idle_deadline = session.last_activity_at
                    + chrono::Duration::seconds(session.spec.idle_timeout_seconds as i64);
                if idle_deadline <= Utc::now() {
                    if state
                        .expire_idle_session(
                            session_id,
                            session.spec.idle_timeout_seconds,
                            "IDE idle timeout exceeded",
                        )
                        .await
                    {
                        break;
                    }
                    continue;
                }
                let usage = match state
                    .executor
                    .workspace_usage_bytes(&workspace_volume_name(&session.spec.workspace_ref))
                    .await
                {
                    Ok(usage) => {
                        quota_failures = 0;
                        Some(usage)
                    }
                    Err(error) => {
                        quota_failures = quota_failures.saturating_add(1);
                        if quota_failures >= 3 {
                            let error = format!(
                                "workspace quota measurement failed closed after {quota_failures} attempts: {error}"
                            );
                            if state
                                .journal
                                .update_session(
                                    session_id,
                                    SessionState::Failed,
                                    None,
                                    None,
                                    Some(&error),
                                )
                                .await
                                .is_ok()
                            {
                                state.revoke_session_proxy(session_id);
                                let _ = state.executor.stop_session(&executor_id).await;
                            }
                            break;
                        }
                        tracing::warn!(%session_id, %error, quota_failures, "IDE workspace quota measurement failed; retrying fail-closed check");
                        None
                    }
                };
                if let Some(usage) = usage
                    && usage > session.spec.resources.max_workspace_bytes
                {
                    let error = format!(
                        "workspace quota exceeded: {usage} > {} bytes",
                        session.spec.resources.max_workspace_bytes
                    );
                    if state
                        .journal
                        .update_session(session_id, SessionState::Failed, None, None, Some(&error))
                        .await
                        .is_ok()
                    {
                        state.revoke_session_proxy(session_id);
                        let _ = state.executor.stop_session(&executor_id).await;
                    }
                    break;
                }
                let observation = match state.executor.observe_session(&executor_id).await {
                    Ok(observation) => observation,
                    Err(error) => {
                        tracing::warn!(%session_id, %error, "IDE session observation failed");
                        continue;
                    }
                };
                match observation {
                    ExecutorObservation::Running => continue,
                    ExecutorObservation::Exited(code) => {
                        let Ok(current) = state.journal.session(session_id).await else {
                            break;
                        };
                        if current.view.state.is_terminal() {
                            break;
                        }
                        let next = if current.view.state == SessionState::StopRequested {
                            SessionState::Stopped
                        } else {
                            SessionState::Failed
                        };
                        let error = (next == SessionState::Failed)
                            .then(|| format!("IDE container exited with code {code}"));
                        if state
                            .journal
                            .update_session(session_id, next, None, None, error.as_deref())
                            .await
                            .is_ok()
                        {
                            state.revoke_session_proxy(session_id);
                        }
                        let _ = state.executor.cleanup_job(&executor_id).await;
                        break;
                    }
                    ExecutorObservation::Missing => {
                        let Ok(current) = state.journal.session(session_id).await else {
                            break;
                        };
                        if current.view.state.is_terminal() {
                            break;
                        }
                        let next = if current.view.state == SessionState::StopRequested {
                            SessionState::Stopped
                        } else {
                            SessionState::Lost
                        };
                        let error = (next == SessionState::Lost)
                            .then_some("IDE container disappeared while the session was active");
                        if state
                            .journal
                            .update_session(session_id, next, None, None, error)
                            .await
                            .is_ok()
                        {
                            state.revoke_session_proxy(session_id);
                        }
                        break;
                    }
                }
            }
            if state
                .journal
                .session(session_id)
                .await
                .is_ok_and(|session| session.view.state.is_terminal())
                && state.executor.cleanup_job(&executor_id).await.is_ok()
            {
                let _ = state
                    .journal
                    .clear_session_executor(session_id, &executor_id)
                    .await;
            }
            state
                .session_monitors
                .lock()
                .expect("session monitor registry poisoned")
                .remove(&session_id);
        });
    }

    async fn expire_session(&self, id: Uuid, reason: &str) {
        let Ok(session) = self.journal.session(id).await else {
            return;
        };
        if session.view.state.is_terminal() {
            return;
        }
        // Revoke proxy authorization before stopping the container. Otherwise
        // the observer can race the stop/remove window and replace `expired`
        // with `failed` or `lost`.
        if self
            .journal
            .update_session(id, SessionState::Expired, None, None, Some(reason))
            .await
            .is_err()
        {
            return;
        }
        self.revoke_session_proxy(id);
        let Some(executor_id) = session.executor_id.as_deref() else {
            return;
        };
        if self.executor.stop_session(executor_id).await.is_ok() {
            let _ = self.journal.clear_session_executor(id, executor_id).await;
        }
    }

    async fn expire_idle_session(&self, id: Uuid, idle_seconds: u64, reason: &str) -> bool {
        let Ok(session) = self.journal.session(id).await else {
            return false;
        };
        let cutoff = Utc::now() - chrono::Duration::seconds(idle_seconds as i64);
        match self
            .journal
            .expire_session_if_idle(id, cutoff, reason)
            .await
        {
            Ok(true) => {
                self.revoke_session_proxy(id);
                if let Some(executor_id) = session.executor_id.as_deref()
                    && self.executor.stop_session(executor_id).await.is_ok()
                {
                    let _ = self.journal.clear_session_executor(id, executor_id).await;
                }
                true
            }
            Ok(false) => false,
            Err(error) => {
                tracing::warn!(%id, %error, "atomic IDE idle expiry failed");
                false
            }
        }
    }

    async fn owned_job(&self, principal: &Principal, id: Uuid) -> Result<JobRecord> {
        let job = self.journal.job(id).await?;
        if job.owner_sub != principal.subject {
            return Err(RuntimeError::NotFound(format!("job {id}")));
        }
        principal.require_workspace(&job.view.workspace_ref)?;
        Ok(job)
    }

    async fn owned_session(&self, principal: &Principal, id: Uuid) -> Result<SessionRecord> {
        let session = self.journal.session(id).await?;
        if session.owner_sub != principal.subject {
            return Err(RuntimeError::NotFound(format!("session {id}")));
        }
        principal.require_workspace(&session.view.workspace_ref)?;
        Ok(session)
    }

    fn batch_profile(&self, name: &str) -> Result<&WorkerProfile> {
        self.config
            .worker_profiles
            .get(name)
            .ok_or_else(|| RuntimeError::Validation("unknown server-side worker profile".into()))
    }

    fn ide_profile(&self, name: &str) -> Result<&WorkerProfile> {
        self.batch_profile(name)
    }
}

fn validate_idempotency_key(value: &str) -> Result<()> {
    if !(8..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(RuntimeError::Validation(
            "Idempotency-Key must be 8-128 URL-safe characters".into(),
        ));
    }
    Ok(())
}

fn request_hash<T: serde::Serialize>(value: &T) -> Result<String> {
    let encoded =
        serde_json::to_vec(value).map_err(|error| RuntimeError::Internal(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn generate_session_secret() -> Result<String> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|error| RuntimeError::Internal(format!("OS random source failed: {error}")))?;
    Ok(hex::encode(secret))
}

fn ensure_same_request(existing: &str, requested: &str) -> Result<()> {
    if existing == requested {
        Ok(())
    } else {
        Err(RuntimeError::Conflict(
            "Idempotency-Key was already used with a different request".into(),
        ))
    }
}

fn validate_artifacts(spec: &JobSpec, artifacts: &[ArtifactManifestEntry]) -> Result<()> {
    if artifacts.len() > 256 {
        return Err(RuntimeError::Validation(
            "worker returned too many artifacts".into(),
        ));
    }
    let mut paths = HashSet::new();
    let mut total = 0_i64;
    for artifact in artifacts {
        artifact.validate(spec.resources.max_artifact_bytes)?;
        if !paths.insert(&artifact.relative_path) {
            return Err(RuntimeError::Validation(
                "worker returned duplicate artifact paths".into(),
            ));
        }
        total = total
            .checked_add(artifact.size_bytes)
            .ok_or_else(|| RuntimeError::Validation("artifact size overflow".into()))?;
        let allowed = spec.artifact_rules.iter().any(|rule| {
            rule.kind == artifact.kind
                && Glob::new(&rule.path)
                    .map(|glob| glob.compile_matcher().is_match(&artifact.relative_path))
                    .unwrap_or(false)
        });
        if !allowed {
            return Err(RuntimeError::Validation(format!(
                "artifact {} does not match an expected output rule",
                artifact.relative_path
            )));
        }
    }
    if total > spec.resources.max_artifact_bytes {
        return Err(RuntimeError::Validation(
            "artifact manifest exceeds max_artifact_bytes".into(),
        ));
    }
    Ok(())
}

fn remaining_job_timeout(job: &JobRecord) -> u64 {
    let deadline =
        job.view.created_at + chrono::Duration::seconds(job.spec.resources.timeout_seconds as i64);
    (deadline - Utc::now())
        .to_std()
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::generate_session_secret;

    #[test]
    fn session_secrets_are_full_256_bit_os_random_values() {
        let first = generate_session_secret().unwrap();
        let second = generate_session_secret().unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }
}
