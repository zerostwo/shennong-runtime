use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use bollard::{
    Docker,
    container::{
        Config as ContainerConfig, CreateContainerOptions, InspectContainerOptions,
        KillContainerOptions, ListContainersOptions, LogOutput, LogsOptions,
        RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
        UploadToContainerOptions,
    },
    errors::Error as BollardError,
    models::{
        HostConfig, Mount, MountTypeEnum, MountVolumeOptions, Network, PortBinding,
        SystemInfoCgroupVersionEnum,
    },
    network::{CreateNetworkOptions, InspectNetworkOptions},
    volume::CreateVolumeOptions,
};
use bytes::Bytes;
use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout};
use uuid::Uuid;

use crate::{
    config::EgressPolicyConfig,
    error::{Result, RuntimeError},
    model::{
        ArtifactManifestEntry, ExecutionOutcome, ExecutorObservation, IdeKind, LogStream,
        ResolvedJob, ResolvedSession, WorkspaceFile,
    },
};

const CONTAINER_USER: &str = "65532:65532";
const IDE_GATEWAY_PORT: u16 = 18_080;
const SESSION_SECRET_HEADER: &str = "x-shennong-session-secret";
const RSTUDIO_REQUEST_HEADER: &str = "x-shennong-rstudio-request";

#[derive(Clone)]
struct EgressPolicyGuard {
    state_file: PathBuf,
    child_pid_file: PathBuf,
    rootless_uid: u32,
    job_bridge: String,
    session_bridge: String,
    runtime_proxy_v4: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressPolicyAttestation {
    version: u8,
    rootless_uid: u32,
    netns_pid: u32,
    netns_inode: u64,
    job_bridge: String,
    session_bridge: String,
    runtime_proxy_v4: String,
}

impl From<EgressPolicyConfig> for EgressPolicyGuard {
    fn from(config: EgressPolicyConfig) -> Self {
        Self {
            state_file: config.state_file,
            child_pid_file: config.child_pid_file,
            rootless_uid: config.rootless_uid,
            job_bridge: config.job_bridge,
            session_bridge: config.session_bridge,
            runtime_proxy_v4: config.runtime_proxy_v4,
        }
    }
}

impl EgressPolicyGuard {
    fn verify(&self) -> Result<()> {
        let child_pid_before = read_child_pid(&self.child_pid_file, self.rootless_uid)?;
        let metadata = fs::symlink_metadata(&self.state_file).map_err(|error| {
            RuntimeError::Executor(format!(
                "egress policy is not attested for the current RootlessKit namespace: {error}"
            ))
        })?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.len() > 4096
        {
            return Err(RuntimeError::Executor(
                "egress policy attestation must be a small, root-owned, non-writable regular file"
                    .into(),
            ));
        }
        let raw = fs::read_to_string(&self.state_file).map_err(|error| {
            RuntimeError::Executor(format!("cannot read egress policy attestation: {error}"))
        })?;
        let attestation: EgressPolicyAttestation = serde_json::from_str(&raw).map_err(|error| {
            RuntimeError::Executor(format!("invalid egress policy attestation: {error}"))
        })?;
        let child_pid_after = read_child_pid(&self.child_pid_file, self.rootless_uid)?;
        validate_egress_policy_attestation(
            &attestation,
            child_pid_before,
            child_pid_after,
            self.rootless_uid,
            &self.job_bridge,
            &self.session_bridge,
            &self.runtime_proxy_v4,
        )
    }
}

fn read_child_pid(path: &Path, rootless_uid: u32) -> Result<u32> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        RuntimeError::Executor(format!(
            "cannot read RootlessKit child PID metadata: {error}"
        ))
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rootless_uid
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 32
    {
        return Err(RuntimeError::Executor(
            "RootlessKit child PID must be a small, executor-owned, non-writable regular file"
                .into(),
        ));
    }
    let raw = fs::read_to_string(path).map_err(|error| {
        RuntimeError::Executor(format!("cannot read RootlessKit child PID: {error}"))
    })?;
    let pid = raw.trim().parse::<u32>().map_err(|_| {
        RuntimeError::Executor("RootlessKit child PID is not a positive integer".into())
    })?;
    if pid == 0 {
        return Err(RuntimeError::Executor(
            "RootlessKit child PID is not a positive integer".into(),
        ));
    }
    Ok(pid)
}

#[allow(clippy::too_many_arguments)]
fn validate_egress_policy_attestation(
    attestation: &EgressPolicyAttestation,
    child_pid_before: u32,
    child_pid_after: u32,
    rootless_uid: u32,
    job_bridge: &str,
    session_bridge: &str,
    runtime_proxy_v4: &str,
) -> Result<()> {
    if attestation.version != 1
        || attestation.rootless_uid != rootless_uid
        || attestation.netns_pid == 0
        || attestation.netns_inode == 0
        || child_pid_before != child_pid_after
        || attestation.netns_pid != child_pid_after
        || attestation.job_bridge != job_bridge
        || attestation.session_bridge != session_bridge
        || attestation.runtime_proxy_v4 != runtime_proxy_v4
    {
        return Err(RuntimeError::Executor(
            "egress policy attestation does not match the current RootlessKit namespace and Runtime policy"
                .into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct SessionHandle {
    pub executor_id: String,
    pub internal_target: String,
}

#[async_trait]
pub trait Executor: Send + Sync {
    fn name(&self) -> &'static str;
    async fn ping(&self) -> Result<()>;
    async fn workspace_usage_bytes(&self, workspace_volume: &str) -> Result<i64>;
    async fn start_job(&self, job: &ResolvedJob) -> Result<String>;
    async fn wait_job(&self, executor_id: &str, job: &ResolvedJob) -> Result<ExecutionOutcome>;
    async fn collect_artifacts(&self, job: &ResolvedJob) -> Result<Vec<ArtifactManifestEntry>>;
    async fn read_artifact(
        &self,
        job: &ResolvedJob,
        artifact: &ArtifactManifestEntry,
        max_bytes: usize,
    ) -> Result<Bytes>;
    async fn cancel_job(&self, executor_id: &str) -> Result<()>;
    async fn observe_job(&self, executor_id: &str) -> Result<ExecutorObservation>;
    async fn cleanup_job(&self, executor_id: &str) -> Result<()>;
    async fn cleanup_orphans(&self, known_executor_ids: &HashSet<String>) -> Result<()>;
    async fn start_session(&self, session: &ResolvedSession) -> Result<SessionHandle>;
    async fn stop_session(&self, executor_id: &str) -> Result<()>;
    async fn observe_session(&self, executor_id: &str) -> Result<ExecutorObservation>;
}

#[derive(Clone, Default)]
pub struct MockExecutor;

#[async_trait]
impl Executor for MockExecutor {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn workspace_usage_bytes(&self, workspace_volume: &str) -> Result<i64> {
        if workspace_volume == workspace_volume_name("ws_quotaerror") {
            Err(RuntimeError::Executor(
                "mock workspace usage measurement failed".into(),
            ))
        } else if workspace_volume == workspace_volume_name("ws_overquota")
            || workspace_volume == workspace_volume_name("ws_preoverquota")
        {
            Ok(i64::MAX)
        } else {
            Ok(0)
        }
    }

    async fn start_job(&self, job: &ResolvedJob) -> Result<String> {
        if job.spec.workspace_ref == "ws_preoverquota" {
            return Err(RuntimeError::Validation(
                "workspace uses more than max_workspace_bytes".into(),
            ));
        }
        let artifact = job
            .spec
            .artifact_rules
            .iter()
            .any(|rule| rule.path == "results/mock-result.txt");
        let failed = job
            .spec
            .argv
            .first()
            .is_some_and(|value| value == "mock-fail");
        Ok(format!(
            "mock-job-{}{}{}",
            job.id,
            if artifact { "-artifact" } else { "" },
            if failed { "-force-failure" } else { "" }
        ))
    }

    async fn wait_job(&self, executor_id: &str, job: &ResolvedJob) -> Result<ExecutionOutcome> {
        if matches!(
            job.spec.workspace_ref.as_str(),
            "ws_overquota" | "ws_quotaerror"
        ) {
            sleep(Duration::from_millis(200)).await;
        } else {
            sleep(Duration::from_millis(40)).await;
        }
        let failed = executor_id.contains("force-failure");
        Ok(ExecutionOutcome {
            exit_code: if failed { 2 } else { 0 },
            logs: vec![(
                LogStream::Stdout,
                format!("mock executor completed {executor_id}\n"),
            )],
        })
    }

    async fn collect_artifacts(&self, job: &ResolvedJob) -> Result<Vec<ArtifactManifestEntry>> {
        let mut artifacts = Vec::new();
        for rule in &job.spec.artifact_rules {
            let Some(bytes) = mock_artifact_bytes(job, &rule.path) else {
                continue;
            };
            artifacts.push(ArtifactManifestEntry {
                id: Uuid::new_v4(),
                relative_path: rule.path.clone(),
                kind: rule.kind.clone(),
                size_bytes: bytes.len() as i64,
                sha256: hex::encode(Sha256::digest(&bytes)),
                media_type: if rule.path.ends_with(".json") {
                    Some("application/json".into())
                } else {
                    Some("text/plain".into())
                },
                role: rule.role.clone(),
            });
        }
        Ok(artifacts)
    }

    async fn read_artifact(
        &self,
        job: &ResolvedJob,
        artifact: &ArtifactManifestEntry,
        max_bytes: usize,
    ) -> Result<Bytes> {
        let mut bytes = mock_artifact_bytes(job, &artifact.relative_path)
            .ok_or_else(|| RuntimeError::NotFound("mock artifact bytes".into()))?;
        if job.spec.workspace_ref == "ws_artifact_tamper" {
            bytes.extend_from_slice(b"tampered");
        }
        if bytes.len() > max_bytes {
            return Err(RuntimeError::Validation(
                "artifact exceeds the bounded byte-read limit".into(),
            ));
        }
        Ok(Bytes::from(bytes))
    }

    async fn cancel_job(&self, _executor_id: &str) -> Result<()> {
        Ok(())
    }

    async fn observe_job(&self, _executor_id: &str) -> Result<ExecutorObservation> {
        Ok(ExecutorObservation::Missing)
    }

    async fn cleanup_job(&self, _executor_id: &str) -> Result<()> {
        Ok(())
    }

    async fn cleanup_orphans(&self, _known_executor_ids: &HashSet<String>) -> Result<()> {
        Ok(())
    }

    async fn start_session(&self, session: &ResolvedSession) -> Result<SessionHandle> {
        if session.spec.workspace_ref == "ws_preoverquota" {
            return Err(RuntimeError::Validation(
                "workspace uses more than max_workspace_bytes".into(),
            ));
        }
        Ok(SessionHandle {
            executor_id: format!("mock-session-{}-{}", session.id, session.spec.workspace_ref),
            internal_target: "http://127.0.0.1:9".into(),
        })
    }

    async fn stop_session(&self, _executor_id: &str) -> Result<()> {
        Ok(())
    }

    async fn observe_session(&self, executor_id: &str) -> Result<ExecutorObservation> {
        if ["ws_overquota", "ws_quotaerror", "ws_keep_running"]
            .iter()
            .any(|workspace| executor_id.contains(workspace))
        {
            Ok(ExecutorObservation::Running)
        } else {
            Ok(ExecutorObservation::Missing)
        }
    }
}

#[derive(Clone)]
pub struct DockerExecutor {
    docker: Docker,
    job_network: String,
    session_network: String,
    instance_id: String,
    egress_policy: Option<EgressPolicyGuard>,
    hardened: bool,
}

impl DockerExecutor {
    pub async fn connect(
        socket: &Path,
        job_network: String,
        session_network: String,
        instance_id: String,
        egress_policy: Option<EgressPolicyConfig>,
        hardened: bool,
    ) -> Result<Self> {
        let egress_policy = egress_policy.map(EgressPolicyGuard::from);
        if hardened {
            egress_policy
                .as_ref()
                .ok_or_else(|| RuntimeError::Internal("missing Docker egress policy guard".into()))?
                .verify()?;
        }
        let socket = socket
            .to_str()
            .ok_or_else(|| RuntimeError::Validation("docker socket path is not UTF-8".into()))?;
        let docker = Docker::connect_with_unix(socket, 120, bollard::API_DEFAULT_VERSION)
            .map_err(|error| RuntimeError::Executor(error.to_string()))?;
        let info = docker.info().await.map_err(executor_error)?;
        let security_options = info.security_options.unwrap_or_default();
        if hardened
            && !security_options
                .iter()
                .any(|option| option.split(',').any(|part| part == "name=rootless"))
        {
            return Err(RuntimeError::Validation(
                "the configured workload Docker daemon does not report rootless mode".into(),
            ));
        }
        if !security_options
            .iter()
            .any(|option| option.split(',').any(|part| part == "name=seccomp"))
        {
            return Err(RuntimeError::Validation(
                "the configured workload Docker daemon does not report seccomp support".into(),
            ));
        }
        if info.cgroup_version != Some(SystemInfoCgroupVersionEnum::_2)
            || info.memory_limit != Some(true)
            || info.pids_limit != Some(true)
            || info.cpu_cfs_quota != Some(true)
        {
            return Err(RuntimeError::Validation(
                "the rootless Docker daemon must expose delegated cgroup v2 CPU, memory, and PID limits"
                    .into(),
            ));
        }
        let executor = Self {
            docker,
            job_network,
            session_network,
            instance_id,
            egress_policy,
            hardened,
        };
        if !executor.hardened {
            executor
                .ensure_simple_network(&executor.job_network, false)
                .await?;
            executor
                .ensure_simple_network(&executor.session_network, false)
                .await?;
        }
        executor.verify_launch_policy().await?;
        Ok(executor)
    }

    fn managed_labels(&self, kind: &str) -> HashMap<String, String> {
        HashMap::from([
            ("dev.shennong.managed".into(), "true".into()),
            ("dev.shennong.kind".into(), kind.into()),
            ("dev.shennong.instance".into(), self.instance_id.clone()),
        ])
    }

    async fn verify_launch_policy(&self) -> Result<()> {
        if !self.hardened {
            let job = self.inspect_managed_network(&self.job_network).await?;
            let session = self.inspect_managed_network(&self.session_network).await?;
            validate_simple_network(&job, &self.job_network)?;
            validate_simple_network(&session, &self.session_network)?;
            if job.id.is_none() || job.id == session.id {
                return Err(RuntimeError::Executor(
                    "Job and Session executor networks must have distinct Docker IDs".into(),
                ));
            }
            return Ok(());
        }
        let egress_policy = self
            .egress_policy
            .as_ref()
            .ok_or_else(|| RuntimeError::Internal("missing Docker egress policy guard".into()))?;
        egress_policy.verify()?;
        let job = self.inspect_managed_network(&self.job_network).await?;
        let session = self.inspect_managed_network(&self.session_network).await?;
        validate_managed_network(&job, &self.job_network, &egress_policy.job_bridge)?;
        validate_managed_network(
            &session,
            &self.session_network,
            &egress_policy.session_bridge,
        )?;
        if job.id.is_none() || job.id == session.id {
            return Err(RuntimeError::Executor(
                "Job and Session executor networks must have distinct Docker IDs".into(),
            ));
        }
        Ok(())
    }

    async fn ensure_simple_network(&self, name: &str, internal: bool) -> Result<()> {
        if self
            .docker
            .inspect_network(name, None::<InspectNetworkOptions<String>>)
            .await
            .is_ok()
        {
            return Ok(());
        }
        self.docker
            .create_network(CreateNetworkOptions {
                name: name.to_string(),
                check_duplicate: true,
                driver: "bridge".to_string(),
                internal,
                attachable: false,
                ingress: false,
                labels: HashMap::from([
                    ("dev.shennong.managed".to_string(), "true".to_string()),
                    (
                        "dev.shennong.network-policy".to_string(),
                        "simple".to_string(),
                    ),
                ]),
                ..Default::default()
            })
            .await
            .map_err(executor_error)?;
        Ok(())
    }

    async fn inspect_managed_network(&self, name: &str) -> Result<Network> {
        self.docker
            .inspect_network(name, None::<InspectNetworkOptions<String>>)
            .await
            .map_err(executor_error)
    }

    async fn ensure_workspace_volume(
        &self,
        name: &str,
        workspace_ref: &str,
        image: &str,
        resources: &crate::model::ResourceLimits,
    ) -> Result<()> {
        let mut labels = self.managed_labels("workspace-volume");
        labels.insert(
            "dev.shennong.workspace_ref".to_string(),
            workspace_ref.to_string(),
        );
        self.docker
            .create_volume(CreateVolumeOptions {
                name: name.to_string(),
                driver: "local".to_string(),
                driver_opts: HashMap::new(),
                labels,
            })
            .await
            .map_err(executor_error)?;
        let volume = self
            .docker
            .inspect_volume(name)
            .await
            .map_err(executor_error)?;
        if volume
            .labels
            .get("dev.shennong.workspace_ref")
            .map(String::as_str)
            != Some(workspace_ref)
            || volume
                .labels
                .get("dev.shennong.instance")
                .map(String::as_str)
                != Some(self.instance_id.as_str())
        {
            return Err(RuntimeError::Executor(
                "workspace volume labels do not match the authorized workspace or Runtime instance"
                    .into(),
            ));
        }

        // A fresh Docker named volume is root-owned even though the image's
        // /workspace directory is 65532. A tiny trusted, networkless init
        // container changes only the volume root before untrusted code starts.
        let mut init_host_config = self.locked_host_config("none", name, resources, false, false);
        init_host_config.cap_add = Some(vec!["CHOWN".into()]);
        let init_labels = self.managed_labels("workspace-init");
        let init_name = format!("shennong-workspace-init-{}", Uuid::new_v4());
        let init_config = ContainerConfig {
            image: Some(image.to_string()),
            entrypoint: Some(vec!["/usr/bin/chown".into()]),
            cmd: Some(vec![CONTAINER_USER.into(), "/workspace".into()]),
            user: Some("0:0".into()),
            working_dir: Some("/".into()),
            attach_stdout: Some(false),
            attach_stderr: Some(true),
            tty: Some(false),
            open_stdin: Some(false),
            labels: Some(init_labels),
            host_config: Some(init_host_config),
            ..Default::default()
        };
        let init_id = self.create_and_start(&init_name, init_config).await?;
        let result = self
            .wait_for_short_container(&init_id, "workspace initializer")
            .await;
        let _ = self.cleanup_job(&init_id).await;
        result?;
        let usage = self.workspace_usage_bytes(name).await?;
        if usage > resources.max_workspace_bytes {
            return Err(RuntimeError::Validation(format!(
                "workspace uses {usage} bytes, above max_workspace_bytes={}",
                resources.max_workspace_bytes
            )));
        }
        Ok(())
    }

    async fn stage_workspace_files(&self, job: &ResolvedJob) -> Result<()> {
        if job.spec.workspace_files.is_empty() {
            return Ok(());
        }
        let archive = build_workspace_tar(&self.instance_id, job.id, &job.spec.workspace_files)?;
        let name = format!("shennong-workspace-stage-{}", Uuid::new_v4());
        let labels = self.managed_labels("workspace-stage");
        let config = ContainerConfig {
            image: Some(job.profile.image.clone()),
            entrypoint: Some(vec!["/usr/bin/true".into()]),
            user: Some(CONTAINER_USER.into()),
            working_dir: Some("/workspace".into()),
            attach_stdout: Some(true),
            attach_stderr: Some(false),
            tty: Some(false),
            open_stdin: Some(false),
            labels: Some(labels),
            host_config: Some(self.locked_host_config(
                "none",
                &job.workspace_volume,
                &job.spec.resources,
                false,
                false,
            )),
            ..Default::default()
        };
        let response = self
            .docker
            .create_container(
                Some(CreateContainerOptions {
                    name,
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(executor_error)?;
        let upload = self
            .docker
            .upload_to_container(
                &response.id,
                Some(UploadToContainerOptions {
                    path: "/workspace".to_owned(),
                    no_overwrite_dir_non_dir: "true".to_owned(),
                }),
                Bytes::from(archive),
            )
            .await
            .map_err(executor_error);
        let cleanup = self.cleanup_job(&response.id).await;
        match (upload, cleanup) {
            (Err(error), _) | (Ok(()), Err(error)) => return Err(error),
            (Ok(()), Ok(())) => {}
        }
        let usage = self.workspace_usage_bytes(&job.workspace_volume).await?;
        if usage > job.spec.resources.max_workspace_bytes {
            return Err(RuntimeError::Validation(format!(
                "workspace uses {usage} bytes, above max_workspace_bytes={}",
                job.spec.resources.max_workspace_bytes
            )));
        }
        Ok(())
    }

    async fn wait_for_short_container(&self, executor_id: &str, label: &str) -> Result<()> {
        for _ in 0..100 {
            let inspection = self
                .docker
                .inspect_container(executor_id, None::<InspectContainerOptions>)
                .await
                .map_err(executor_error)?;
            let state = inspection.state.unwrap_or_default();
            if !state.running.unwrap_or(false) {
                let exit_code = state.exit_code.unwrap_or(-1);
                return if exit_code == 0 {
                    Ok(())
                } else {
                    Err(RuntimeError::Executor(format!(
                        "{label} exited with code {exit_code}"
                    )))
                };
            }
            sleep(Duration::from_millis(25)).await;
        }
        Err(RuntimeError::Executor(format!(
            "{label} exceeded its deadline"
        )))
    }

    async fn wait_for_artifact_reader(&self, executor_id: &str) -> Result<()> {
        for _ in 0..1200 {
            let inspection = self
                .docker
                .inspect_container(executor_id, None::<InspectContainerOptions>)
                .await
                .map_err(executor_error)?;
            let state = inspection.state.unwrap_or_default();
            if !state.running.unwrap_or(false) {
                let exit_code = state.exit_code.unwrap_or(-1);
                if exit_code == 0 {
                    return Ok(());
                }
                let mut logs = self.docker.logs(
                    executor_id,
                    Some(LogsOptions::<String> {
                        stdout: false,
                        stderr: true,
                        tail: "all".into(),
                        ..Default::default()
                    }),
                );
                let mut stderr = String::new();
                while let Some(output) = logs.next().await {
                    if let LogOutput::StdErr { message } = output.map_err(executor_error)? {
                        let remaining = (8 * 1024_usize).saturating_sub(stderr.len());
                        stderr.push_str(&String::from_utf8_lossy(
                            &message[..message.len().min(remaining)],
                        ));
                    }
                }
                return Err(RuntimeError::Validation(format!(
                    "artifact reader rejected the requested bytes: {}",
                    stderr.trim()
                )));
            }
            sleep(Duration::from_millis(25)).await;
        }
        Err(RuntimeError::Executor(
            "artifact reader exceeded its 30 second deadline".into(),
        ))
    }

    fn locked_host_config(
        &self,
        network: &str,
        workspace_volume: &str,
        resources: &crate::model::ResourceLimits,
        session_home: bool,
        workspace_read_only: bool,
    ) -> HostConfig {
        let mut tmpfs = HashMap::new();
        tmpfs.insert(
            "/tmp".to_string(),
            format!(
                "rw,nosuid,nodev,noexec,size={},mode=1777",
                resources.tmpfs_bytes
            ),
        );
        if session_home {
            tmpfs.insert(
                "/home/shennong".to_string(),
                "rw,nosuid,nodev,size=268435456,mode=0700,uid=65532,gid=65532".to_string(),
            );
            tmpfs.insert(
                "/var/run/rstudio-server".to_string(),
                "rw,nosuid,nodev,noexec,size=16777216,mode=0750,uid=65532,gid=65532".to_string(),
            );
            tmpfs.insert(
                "/var/lib/rstudio-server".to_string(),
                "rw,nosuid,nodev,noexec,size=67108864,mode=0750,uid=65532,gid=65532".to_string(),
            );
        }
        HostConfig {
            cap_drop: Some(vec!["ALL".into()]),
            security_opt: Some(vec![
                "no-new-privileges=true".into(),
                "seccomp=builtin".into(),
            ]),
            readonly_rootfs: Some(true),
            privileged: Some(false),
            publish_all_ports: Some(false),
            port_bindings: Some(HashMap::new()),
            network_mode: Some(network.to_string()),
            pids_limit: Some(resources.pids),
            nano_cpus: Some((resources.cpus * 1_000_000_000.0) as i64),
            memory: Some(resources.memory_bytes),
            memory_swap: Some(resources.memory_bytes),
            oom_kill_disable: Some(false),
            init: Some(true),
            auto_remove: Some(false),
            ipc_mode: Some("private".into()),
            tmpfs: Some(tmpfs),
            mounts: Some(vec![Mount {
                target: Some("/workspace".into()),
                source: Some(workspace_volume.into()),
                typ: Some(MountTypeEnum::VOLUME),
                read_only: Some(workspace_read_only),
                volume_options: Some(MountVolumeOptions {
                    no_copy: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            devices: Some(Vec::new()),
            device_requests: Some(Vec::new()),
            binds: Some(Vec::new()),
            ..Default::default()
        }
    }

    async fn create_and_start(
        &self,
        name: &str,
        config: ContainerConfig<String>,
    ) -> Result<String> {
        let response = self
            .docker
            .create_container(
                Some(CreateContainerOptions {
                    name: name.to_string(),
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(executor_error)?;
        if let Err(error) = self
            .docker
            .start_container(&response.id, None::<StartContainerOptions<String>>)
            .await
        {
            let _ = self
                .docker
                .remove_container(
                    &response.id,
                    Some(RemoveContainerOptions {
                        force: true,
                        v: false,
                        link: false,
                    }),
                )
                .await;
            return Err(executor_error(error));
        }
        Ok(response.id)
    }

    async fn create_and_start_guarded(
        &self,
        name: &str,
        config: ContainerConfig<String>,
    ) -> Result<String> {
        let response = self
            .docker
            .create_container(
                Some(CreateContainerOptions {
                    name: name.to_string(),
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(executor_error)?;
        if let Err(error) = self.verify_launch_policy().await {
            let _ = self.cleanup_job(&response.id).await;
            return Err(error);
        }
        if let Err(error) = self
            .docker
            .start_container(&response.id, None::<StartContainerOptions<String>>)
            .await
        {
            let _ = self.cleanup_job(&response.id).await;
            return Err(executor_error(error));
        }
        if let Err(error) = self.verify_launch_policy().await {
            let _ = self.cancel_job(&response.id).await;
            let _ = self.cleanup_job(&response.id).await;
            return Err(error);
        }
        Ok(response.id)
    }

    async fn scan_artifacts(&self, job: &ResolvedJob) -> Result<Vec<ArtifactManifestEntry>> {
        if job.spec.artifact_rules.is_empty() {
            return Ok(Vec::new());
        }
        let name = format!("shennong-scan-{}", job.id);
        let rules = serde_json::to_string(&job.spec.artifact_rules)
            .map_err(|error| RuntimeError::Internal(error.to_string()))?;
        let mut labels = self.managed_labels("artifact-scanner");
        labels.insert("dev.shennong.job_id".into(), job.id.to_string());
        let config = ContainerConfig {
            image: Some(job.profile.image.clone()),
            entrypoint: Some(vec![
                "python3".into(),
                "/opt/shennong/bin/scan_artifacts.py".into(),
            ]),
            cmd: Some(Vec::new()),
            env: Some(vec![
                format!("SHENNONG_ARTIFACT_RULES_JSON={rules}"),
                format!(
                    "SHENNONG_MAX_ARTIFACT_BYTES={}",
                    job.spec.resources.max_artifact_bytes
                ),
                "PYTHONDONTWRITEBYTECODE=1".into(),
            ]),
            user: Some(CONTAINER_USER.into()),
            working_dir: Some("/workspace".into()),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            tty: Some(false),
            open_stdin: Some(false),
            labels: Some(labels),
            host_config: Some(self.locked_host_config(
                "none",
                &job.workspace_volume,
                &job.spec.resources,
                false,
                true,
            )),
            ..Default::default()
        };
        let scanner_id = self.create_and_start(&name, config).await?;
        let outcome = match timeout(Duration::from_secs(30), async {
            let mut stream = self.docker.logs(
                &scanner_id,
                Some(LogsOptions::<String> {
                    follow: true,
                    stdout: true,
                    stderr: true,
                    tail: "all".into(),
                    ..Default::default()
                }),
            );
            let mut stdout = String::new();
            let mut stderr = String::new();
            while let Some(item) = stream.next().await {
                match item.map_err(executor_error)? {
                    LogOutput::StdOut { message } | LogOutput::Console { message } => {
                        if stdout.len() + message.len() > 1024 * 1024 {
                            return Err(RuntimeError::Executor(
                                "artifact scanner output exceeded 1 MiB".into(),
                            ));
                        }
                        stdout.push_str(&String::from_utf8_lossy(&message));
                    }
                    LogOutput::StdErr { message } => {
                        if stderr.len() < 64 * 1024 {
                            let remaining = 64 * 1024 - stderr.len();
                            stderr.push_str(&String::from_utf8_lossy(
                                &message[..message.len().min(remaining)],
                            ));
                        }
                    }
                    LogOutput::StdIn { .. } => {}
                }
            }
            let inspection = self
                .docker
                .inspect_container(&scanner_id, None::<InspectContainerOptions>)
                .await
                .map_err(executor_error)?;
            let exit_code = inspection
                .state
                .and_then(|state| state.exit_code)
                .unwrap_or(-1);
            if exit_code != 0 {
                return Err(RuntimeError::Executor(format!(
                    "artifact scanner exited with code {exit_code}: {stderr}"
                )));
            }
            serde_json::from_str(stdout.trim()).map_err(|error| {
                RuntimeError::Executor(format!("invalid artifact scanner output: {error}"))
            })
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => Err(RuntimeError::Executor(
                "artifact scanner exceeded 30 seconds".into(),
            )),
        };
        let cleanup = self.cleanup_job(&scanner_id).await;
        match (outcome, cleanup) {
            (Ok(artifacts), Ok(())) => Ok(artifacts),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    async fn read_artifact_from_volume(
        &self,
        job: &ResolvedJob,
        artifact: &ArtifactManifestEntry,
        max_bytes: usize,
    ) -> Result<Bytes> {
        if artifact.size_bytes < 0
            || artifact.size_bytes as usize > max_bytes
            || max_bytes > crate::model::MAX_ARTIFACT_DOWNLOAD_BYTES
        {
            return Err(RuntimeError::Validation(
                "artifact exceeds the bounded byte-read limit".into(),
            ));
        }
        let name = format!("shennong-artifact-read-{}", Uuid::new_v4());
        let mut labels = self.managed_labels("artifact-reader");
        labels.insert("dev.shennong.job_id".into(), job.id.to_string());
        let request = serde_json::json!({
            "path": artifact.relative_path,
            "size_bytes": artifact.size_bytes,
            "sha256": artifact.sha256.to_ascii_lowercase(),
            "max_bytes": max_bytes,
        });
        let config = ContainerConfig {
            image: Some(job.profile.image.clone()),
            entrypoint: Some(vec![
                "python3".into(),
                "/opt/shennong/bin/read_artifact.py".into(),
            ]),
            cmd: Some(Vec::new()),
            env: Some(vec![
                format!("SHENNONG_ARTIFACT_READ_JSON={request}"),
                "PYTHONDONTWRITEBYTECODE=1".into(),
            ]),
            user: Some(CONTAINER_USER.into()),
            working_dir: Some("/workspace".into()),
            attach_stdout: Some(false),
            attach_stderr: Some(true),
            tty: Some(false),
            open_stdin: Some(false),
            labels: Some(labels),
            host_config: Some(self.locked_host_config(
                "none",
                &job.workspace_volume,
                &job.spec.resources,
                false,
                true,
            )),
            ..Default::default()
        };
        let helper_id = self.create_and_start(&name, config).await?;
        let result = timeout(Duration::from_secs(30), async {
            self.wait_for_artifact_reader(&helper_id).await?;
            let mut logs = self.docker.logs(
                &helper_id,
                Some(LogsOptions::<String> {
                    stdout: true,
                    stderr: false,
                    tail: "all".into(),
                    ..Default::default()
                }),
            );
            let mut bytes = Vec::with_capacity(artifact.size_bytes as usize);
            while let Some(output) = logs.next().await {
                let message = match output.map_err(executor_error)? {
                    LogOutput::StdOut { message } | LogOutput::Console { message } => message,
                    _ => continue,
                };
                if bytes.len().saturating_add(message.len()) > max_bytes {
                    return Err(RuntimeError::Validation(
                        "artifact reader output exceeded its bounded limit".into(),
                    ));
                }
                bytes.extend_from_slice(&message);
            }
            if bytes.len() != artifact.size_bytes as usize
                || hex::encode(Sha256::digest(&bytes)) != artifact.sha256.to_ascii_lowercase()
            {
                return Err(RuntimeError::Validation(
                    "artifact reader output no longer matches the validated manifest".into(),
                ));
            }
            Ok(Bytes::from(bytes))
        })
        .await
        .map_err(|_| {
            RuntimeError::Executor("artifact reader exceeded its 30 second deadline".into())
        })
        .and_then(|result| result);
        let cleanup = self.cleanup_job(&helper_id).await;
        match (result, cleanup) {
            (Ok(bytes), Ok(())) => Ok(bytes),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}

#[async_trait]
impl Executor for DockerExecutor {
    fn name(&self) -> &'static str {
        "docker-rootless"
    }

    async fn ping(&self) -> Result<()> {
        self.docker.ping().await.map_err(executor_error)?;
        if !self.hardened {
            // Simple-mode networks may be removed by an operator or `docker
            // network prune` while the long-running Runtime container is
            // otherwise healthy. Reconcile them here so health checks restore
            // the executor instead of leaving it unavailable until restart.
            self.ensure_simple_network(&self.job_network, false).await?;
            self.ensure_simple_network(&self.session_network, false)
                .await?;
        }
        self.verify_launch_policy().await?;
        Ok(())
    }

    async fn workspace_usage_bytes(&self, workspace_volume: &str) -> Result<i64> {
        let usage = self.docker.df().await.map_err(executor_error)?;
        let volume = usage
            .volumes
            .unwrap_or_default()
            .into_iter()
            .find(|volume| volume.name == workspace_volume)
            .ok_or_else(|| {
                RuntimeError::Executor(format!(
                    "workspace volume {workspace_volume} was absent from Docker disk usage"
                ))
            })?;
        let bytes = volume
            .usage_data
            .map(|usage| usage.size)
            .filter(|size| *size >= 0)
            .ok_or_else(|| {
                RuntimeError::Executor(
                    "Docker did not provide enforceable local-volume usage data".into(),
                )
            })?;
        Ok(bytes)
    }

    async fn start_job(&self, job: &ResolvedJob) -> Result<String> {
        self.ensure_workspace_volume(
            &job.workspace_volume,
            &job.spec.workspace_ref,
            &job.profile.image,
            &job.spec.resources,
        )
        .await?;
        self.stage_workspace_files(job).await?;
        self.verify_launch_policy().await?;
        let name = format!("shennong-job-{}", job.id);
        let mut labels = self.managed_labels("job");
        labels.insert("dev.shennong.job_id".into(), job.id.to_string());
        let artifact_rules = serde_json::to_string(&job.spec.artifact_rules)
            .map_err(|error| RuntimeError::Internal(error.to_string()))?;
        let config = ContainerConfig {
            image: Some(job.profile.image.clone()),
            entrypoint: Some(vec![
                "python3".into(),
                "/opt/shennong/bin/job_entrypoint.py".into(),
            ]),
            cmd: Some(resolved_job_argv(&self.instance_id, job)?),
            env: Some(vec![
                format!("SHENNONG_JOB_ID={}", job.id),
                format!("SHENNONG_ARTIFACT_RULES_JSON={artifact_rules}"),
                format!(
                    "SHENNONG_MAX_ARTIFACT_BYTES={}",
                    job.spec.resources.max_artifact_bytes
                ),
                "PYTHONDONTWRITEBYTECODE=1".into(),
                "HOME=/workspace/.shennong/home".into(),
            ]),
            user: Some(CONTAINER_USER.into()),
            working_dir: Some("/workspace".into()),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            tty: Some(false),
            open_stdin: Some(false),
            labels: Some(labels),
            host_config: Some(self.locked_host_config(
                &self.job_network,
                &job.workspace_volume,
                &job.spec.resources,
                false,
                false,
            )),
            ..Default::default()
        };
        self.create_and_start_guarded(&name, config).await
    }

    async fn wait_job(&self, executor_id: &str, job: &ResolvedJob) -> Result<ExecutionOutcome> {
        let mut stream = self.docker.logs(
            executor_id,
            Some(LogsOptions::<String> {
                follow: true,
                stdout: true,
                stderr: true,
                timestamps: false,
                tail: "all".into(),
                ..Default::default()
            }),
        );
        let mut logs = Vec::new();
        let mut collected = 0_i64;
        while let Some(item) = stream.next().await {
            let output = item.map_err(executor_error)?;
            let (kind, bytes) = match output {
                LogOutput::StdOut { message } | LogOutput::Console { message } => {
                    (LogStream::Stdout, message)
                }
                LogOutput::StdErr { message } => (LogStream::Stderr, message),
                LogOutput::StdIn { .. } => continue,
            };
            let text = String::from_utf8_lossy(&bytes).to_string();
            if collected < job.spec.resources.max_log_bytes {
                let remaining = (job.spec.resources.max_log_bytes - collected) as usize;
                let bounded = if text.len() > remaining {
                    let mut end = remaining;
                    while end > 0 && !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    &text[..end]
                } else {
                    &text
                };
                collected += bounded.len() as i64;
                if !bounded.is_empty() {
                    push_log_chunk(&mut logs, kind, bounded);
                }
            }
        }
        let inspection = self
            .docker
            .inspect_container(executor_id, None::<InspectContainerOptions>)
            .await
            .map_err(executor_error)?;
        let exit_code = inspection
            .state
            .and_then(|state| state.exit_code)
            .unwrap_or(-1);
        Ok(ExecutionOutcome { exit_code, logs })
    }

    async fn collect_artifacts(&self, job: &ResolvedJob) -> Result<Vec<ArtifactManifestEntry>> {
        self.scan_artifacts(job).await
    }

    async fn read_artifact(
        &self,
        job: &ResolvedJob,
        artifact: &ArtifactManifestEntry,
        max_bytes: usize,
    ) -> Result<Bytes> {
        self.read_artifact_from_volume(job, artifact, max_bytes)
            .await
    }

    async fn cancel_job(&self, executor_id: &str) -> Result<()> {
        match self
            .docker
            .kill_container(executor_id, None::<KillContainerOptions<String>>)
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) || is_removal_in_progress(&error) => Ok(()),
            Err(error) => Err(executor_error(error)),
        }
    }

    async fn observe_job(&self, executor_id: &str) -> Result<ExecutorObservation> {
        observe(&self.docker, executor_id).await
    }

    async fn cleanup_job(&self, executor_id: &str) -> Result<()> {
        match self
            .docker
            .remove_container(
                executor_id,
                Some(RemoveContainerOptions {
                    force: true,
                    v: false,
                    link: false,
                }),
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(executor_error(error)),
        }
    }

    async fn cleanup_orphans(&self, known_executor_ids: &HashSet<String>) -> Result<()> {
        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions::<String> {
                all: true,
                filters: HashMap::from([(
                    "label".into(),
                    vec![
                        "dev.shennong.managed=true".into(),
                        format!("dev.shennong.instance={}", self.instance_id),
                    ],
                )]),
                ..Default::default()
            }))
            .await
            .map_err(executor_error)?;
        let now = chrono::Utc::now().timestamp();
        let mut failures = Vec::new();
        for container in containers {
            let Some(id) = container.id else {
                continue;
            };
            let kind = container
                .labels
                .as_ref()
                .and_then(|labels| labels.get("dev.shennong.kind"))
                .map(String::as_str);
            let helper_within_grace = helper_orphan_within_grace(kind, container.created, now);
            if matches!(
                kind,
                Some(
                    "job"
                        | "session"
                        | "artifact-scanner"
                        | "artifact-reader"
                        | "workspace-init"
                        | "workspace-stage"
                )
            ) && !known_executor_ids.contains(&id)
                && !helper_within_grace
                && let Err(error) = self.cleanup_job(&id).await
            {
                failures.push(format!("{id}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError::Executor(format!(
                "orphan cleanup failures: {}",
                failures.join("; ")
            )))
        }
    }

    async fn start_session(&self, session: &ResolvedSession) -> Result<SessionHandle> {
        self.ensure_workspace_volume(
            &session.workspace_volume,
            &session.spec.workspace_ref,
            &session.profile.image,
            &session.spec.resources,
        )
        .await?;
        self.verify_launch_policy().await?;
        let name = format!("shennong-session-{}", session.id);
        let mut labels = self.managed_labels("session");
        labels.insert("dev.shennong.session_id".into(), session.id.to_string());
        let proxy_path = format!("/v1/sessions/{}/proxy", session.id);
        let container_port = format!("{IDE_GATEWAY_PORT}/tcp");
        let mut host_config = self.locked_host_config(
            &self.session_network,
            &session.workspace_volume,
            &session.spec.resources,
            true,
            false,
        );
        host_config.port_bindings = Some(HashMap::from([(
            container_port.clone(),
            Some(vec![PortBinding {
                host_ip: Some("127.0.0.1".into()),
                host_port: Some(String::new()),
            }]),
        )]));
        let config = ContainerConfig {
            image: Some(session.profile.image.clone()),
            entrypoint: Some(vec![
                "python3".into(),
                "/opt/shennong/bin/launch_ide.py".into(),
            ]),
            cmd: Some(Vec::new()),
            env: Some(vec![
                format!(
                    "SHENNONG_IDE_KIND={}",
                    match session.spec.kind {
                        IdeKind::Rstudio => "rstudio",
                        IdeKind::Jupyterlab => "jupyterlab",
                    }
                ),
                format!("SHENNONG_IDE_PROXY_PATH={proxy_path}"),
                format!(
                    "SHENNONG_IDE_GATEWAY_SECRET_SHA256={}",
                    session_secret_digest(&session.internal_secret)
                ),
                format!("SHENNONG_IDE_GATEWAY_LISTEN=0.0.0.0:{IDE_GATEWAY_PORT}"),
                "PYTHONDONTWRITEBYTECODE=1".into(),
                "HOME=/workspace/.shennong/home".into(),
            ]),
            exposed_ports: Some(HashMap::from([(container_port.clone(), HashMap::new())])),
            user: Some(CONTAINER_USER.into()),
            working_dir: Some("/workspace".into()),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            tty: Some(false),
            open_stdin: Some(false),
            labels: Some(labels),
            host_config: Some(host_config),
            ..Default::default()
        };
        let executor_id = self.create_and_start_guarded(&name, config).await?;
        let host_port = match self
            .session_loopback_port(&executor_id, &container_port)
            .await
        {
            Ok(port) => port,
            Err(error) => {
                let _ = self.cleanup_job(&executor_id).await;
                return Err(error);
            }
        };
        if let Err(error) = self
            .wait_session_gateway(host_port, &proxy_path, &session.internal_secret)
            .await
        {
            let _ = self.cleanup_job(&executor_id).await;
            return Err(error);
        }
        Ok(SessionHandle {
            executor_id,
            internal_target: format!("http://127.0.0.1:{host_port}"),
        })
    }

    async fn stop_session(&self, executor_id: &str) -> Result<()> {
        match self
            .docker
            .stop_container(executor_id, Some(StopContainerOptions { t: 10 }))
            .await
        {
            Ok(()) => {}
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) if is_removal_in_progress(&error) => return Ok(()),
            Err(error) => return Err(executor_error(error)),
        }
        self.cleanup_job(executor_id).await
    }

    async fn observe_session(&self, executor_id: &str) -> Result<ExecutorObservation> {
        observe(&self.docker, executor_id).await
    }
}

impl DockerExecutor {
    async fn wait_session_gateway(
        &self,
        host_port: u16,
        proxy_path: &str,
        secret: &str,
    ) -> Result<()> {
        let url = format!("http://127.0.0.1:{host_port}{proxy_path}/");
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_millis(250))
            .timeout(Duration::from_secs(1))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| RuntimeError::Internal(error.to_string()))?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(70);
        while tokio::time::Instant::now() < deadline {
            match client.get(&url).send().await {
                Ok(response) if response.status() != reqwest::StatusCode::UNAUTHORIZED => {
                    return Err(RuntimeError::Executor(
                        "IDE gateway accepted a request without its internal secret".into(),
                    ));
                }
                Ok(_) => match authenticated_gateway_probe(&client, &url, secret)
                    .send()
                    .await
                {
                    Ok(response)
                        if response.status() != reqwest::StatusCode::UNAUTHORIZED
                            && response.status() != reqwest::StatusCode::NOT_FOUND
                            && !response.status().is_server_error() =>
                    {
                        return Ok(());
                    }
                    Ok(response)
                        if matches!(
                            response.status(),
                            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::NOT_FOUND
                        ) =>
                    {
                        return Err(RuntimeError::Executor(format!(
                            "IDE gateway rejected Runtime readiness authentication with {}",
                            response.status()
                        )));
                    }
                    Ok(_) | Err(_) => {}
                },
                Err(_) => {}
            }
            sleep(Duration::from_millis(100)).await;
        }
        Err(RuntimeError::Executor(
            "authenticated IDE gateway did not become ready within 70 seconds".into(),
        ))
    }

    async fn session_loopback_port(&self, executor_id: &str, container_port: &str) -> Result<u16> {
        for _ in 0..40 {
            let inspection = self
                .docker
                .inspect_container(executor_id, None::<InspectContainerOptions>)
                .await
                .map_err(executor_error)?;
            if let Some(bindings) = inspection
                .network_settings
                .and_then(|settings| settings.ports)
                .and_then(|ports| ports.get(container_port).cloned())
                .flatten()
            {
                for binding in bindings {
                    if binding.host_ip.as_deref() != Some("127.0.0.1") {
                        return Err(RuntimeError::Executor(
                            "IDE port was not bound to loopback".into(),
                        ));
                    }
                    if let Some(port) = binding.host_port {
                        return port.parse().map_err(|error| {
                            RuntimeError::Executor(format!("invalid IDE host port: {error}"))
                        });
                    }
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        Err(RuntimeError::Executor(
            "Docker did not allocate an IDE loopback port".into(),
        ))
    }
}

async fn observe(docker: &Docker, executor_id: &str) -> Result<ExecutorObservation> {
    match docker
        .inspect_container(executor_id, None::<InspectContainerOptions>)
        .await
    {
        Ok(inspection) => {
            let state = inspection.state;
            if state
                .as_ref()
                .and_then(|state| state.running)
                .unwrap_or(false)
            {
                Ok(ExecutorObservation::Running)
            } else {
                Ok(ExecutorObservation::Exited(
                    state.and_then(|state| state.exit_code).unwrap_or(-1),
                ))
            }
        }
        Err(error) if is_not_found(&error) => Ok(ExecutorObservation::Missing),
        Err(error) => Err(executor_error(error)),
    }
}

fn is_not_found(error: &BollardError) -> bool {
    matches!(
        error,
        BollardError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

fn is_removal_in_progress(error: &BollardError) -> bool {
    matches!(
        error,
        BollardError::DockerResponseServerError {
            status_code: 409,
            message,
        } if {
            let message = message.to_ascii_lowercase();
            message.contains("removal of container")
                && message.contains("is already in progress")
        }
    )
}

fn executor_error(error: BollardError) -> RuntimeError {
    RuntimeError::Executor(error.to_string())
}

fn validate_managed_network(network: &Network, expected_name: &str, bridge: &str) -> Result<()> {
    let options = network.options.as_ref();
    let labels = network.labels.as_ref();
    if network.name.as_deref() != Some(expected_name)
        || network.driver.as_deref() != Some("bridge")
        || network.scope.as_deref() != Some("local")
        || network.ingress == Some(true)
        || network.config_only == Some(true)
        || options
            .and_then(|values| values.get("com.docker.network.bridge.name"))
            .map(String::as_str)
            != Some(bridge)
        || labels
            .and_then(|values| values.get("dev.shennong.managed"))
            .map(String::as_str)
            != Some("true")
        || labels
            .and_then(|values| values.get("dev.shennong.network-policy"))
            .map(String::as_str)
            != Some("internet-only")
    {
        return Err(RuntimeError::Executor(format!(
            "Docker network {expected_name} is not the attested managed bridge {bridge}"
        )));
    }
    Ok(())
}

fn validate_simple_network(network: &Network, expected_name: &str) -> Result<()> {
    let labels = network.labels.as_ref();
    if network.name.as_deref() != Some(expected_name)
        || network.driver.as_deref() != Some("bridge")
        || network.scope.as_deref() != Some("local")
        || network.ingress == Some(true)
        || network.config_only == Some(true)
        || labels
            .and_then(|values| values.get("dev.shennong.managed"))
            .map(String::as_str)
            != Some("true")
        || labels
            .and_then(|values| values.get("dev.shennong.network-policy"))
            .map(String::as_str)
            != Some("simple")
    {
        return Err(RuntimeError::Executor(format!(
            "Docker network {expected_name} is not a Shennong simple-mode bridge"
        )));
    }
    Ok(())
}

fn push_log_chunk(logs: &mut Vec<(LogStream, String)>, stream: LogStream, message: &str) {
    const MAX_LOG_ENTRIES: usize = 4096;
    const TARGET_CHUNK_BYTES: usize = 16 * 1024;

    if let Some((last_stream, last_message)) = logs.last_mut()
        && *last_stream == stream
        && last_message.len() < TARGET_CHUNK_BYTES
    {
        last_message.push_str(message);
    } else if logs.len() < MAX_LOG_ENTRIES {
        logs.push((stream, message.to_string()));
    } else if let Some((_, last_message)) = logs.last_mut() {
        // Preserve the byte ceiling even under millions of alternating 1-byte
        // Docker frames without allocating one String per frame.
        last_message.push_str(message);
    }
}

fn helper_orphan_within_grace(kind: Option<&str>, created: Option<i64>, now: i64) -> bool {
    matches!(
        kind,
        Some("artifact-scanner" | "artifact-reader" | "workspace-init" | "workspace-stage")
    ) && created.is_some_and(|created| now.saturating_sub(created) < 120)
}

fn session_secret_digest(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

fn authenticated_gateway_probe(
    client: &reqwest::Client,
    url: &str,
    secret: &str,
) -> reqwest::RequestBuilder {
    client
        .get(url)
        .header(SESSION_SECRET_HEADER, secret)
        .header(RSTUDIO_REQUEST_HEADER, url)
}

fn workspace_input_root(instance_id: &str, job_id: Uuid) -> String {
    let digest = hex::encode(Sha256::digest(format!("{instance_id}:{job_id}").as_bytes()));
    format!(".shennong-input-{}", &digest[..32])
}

fn resolved_job_argv(instance_id: &str, job: &ResolvedJob) -> Result<Vec<String>> {
    let root = workspace_input_root(instance_id, job.id);
    job.spec
        .argv
        .iter()
        .map(|value| {
            if let Some(path) = value.strip_prefix("workspace-input://") {
                if !job
                    .spec
                    .workspace_files
                    .iter()
                    .any(|file| file.path == path)
                {
                    return Err(RuntimeError::Validation(
                        "argv references an unstaged workspace input".into(),
                    ));
                }
                Ok(format!("/workspace/{root}/{path}"))
            } else {
                Ok(value.clone())
            }
        })
        .collect()
}

fn build_workspace_tar(
    instance_id: &str,
    job_id: Uuid,
    files: &[WorkspaceFile],
) -> Result<Vec<u8>> {
    let root = workspace_input_root(instance_id, job_id);
    let mut directories = BTreeSet::from([root.clone()]);
    for file in files {
        let path = format!("{root}/{}", file.path);
        let mut parent = Path::new(&path).parent();
        while let Some(directory) = parent {
            if directory.as_os_str().is_empty() {
                break;
            }
            directories.insert(directory.to_string_lossy().into_owned());
            parent = directory.parent();
        }
    }
    let mut builder = tar::Builder::new(Vec::new());
    for directory in directories {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o700);
        header.set_uid(65_532);
        header.set_gid(65_532);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, directory, io::empty())
            .map_err(|error| {
                RuntimeError::Internal(format!("cannot build workspace input archive: {error}"))
            })?;
    }
    for file in files {
        let bytes = file.decoded_bytes()?;
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_uid(65_532);
        header.set_gid(65_532);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                format!("{root}/{}", file.path),
                bytes.as_slice(),
            )
            .map_err(|error| {
                RuntimeError::Internal(format!("cannot build workspace input archive: {error}"))
            })?;
    }
    builder.into_inner().map_err(|error| {
        RuntimeError::Internal(format!("cannot finalize workspace input archive: {error}"))
    })
}

fn mock_artifact_bytes(job: &ResolvedJob, path: &str) -> Option<Vec<u8>> {
    match path {
        "results/mock-result.txt" => Some(b"mock artifact\n".to_vec()),
        "results/mock-result-bundle.json" => Some(mock_result_bundle(job)),
        _ => None,
    }
}

fn mock_result_bundle(job: &ResolvedJob) -> Vec<u8> {
    let output = b"mock artifact\n";
    let output_sha256 = if job
        .spec
        .argv
        .iter()
        .any(|value| value == "mock-bundle-output-mismatch")
    {
        "0".repeat(64)
    } else {
        hex::encode(Sha256::digest(output))
    };
    let mut bundle = serde_json::json!({
        "schema": crate::model::RESULT_BUNDLE_SCHEMA,
        "created_at": "2026-07-26T00:00:00Z",
        "result": {
            "schema_version": "1.0.0",
            "analysis_type": "bulk_de",
            "name": "mock_result",
            "method": "mock",
            "backend": "mock",
            "input": {},
            "parameters": {},
            "tables": {},
            "embeddings": {},
            "graphs": {},
            "models": {},
            "diagnostics": {},
            "warnings": [],
            "provenance": {}
        },
        "validation": {"valid": true, "errors": [], "warnings": []},
        "inputs": [{
            "role": "expression",
            "resource_id": "mock-resource",
            "revision": "revision-1",
            "digest": {"algorithm": "sha256", "value": "a".repeat(64)}
        }],
        "provenance": {
            "package_versions": {"Shennong": "0.2.0.9000"},
            "random_seed": 1,
            "result_timestamp": "2026-07-26 UTC",
            "execution": {"runtime": "mock"}
        },
        "artifacts": [{
            "role": "primary_table",
            "path": "results/mock-result.txt",
            "media_type": "text/plain",
            "size_bytes": output.len(),
            "digest": {"algorithm": "sha256", "value": output_sha256}
        }]
    });
    if job
        .spec
        .argv
        .iter()
        .any(|value| value == "mock-sensitive-bundle")
    {
        bundle["provenance"]["execution"]["api_key"] = serde_json::json!("forbidden");
    }
    serde_json::to_vec(&bundle).expect("serialize mock Result Bundle")
}

pub fn workspace_volume_name(workspace_ref: &str) -> String {
    let digest = hex::encode(Sha256::digest(workspace_ref.as_bytes()));
    format!("shennong-ws-{}", &digest[..32])
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, io::Read, os::unix::fs::PermissionsExt};

    use super::{
        EgressPolicyAttestation, RSTUDIO_REQUEST_HEADER, SESSION_SECRET_HEADER,
        authenticated_gateway_probe, build_workspace_tar, helper_orphan_within_grace,
        is_removal_in_progress, session_secret_digest, validate_egress_policy_attestation,
        validate_managed_network,
    };
    use crate::model::{WorkspaceFile, WorkspaceFileEncoding};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    #[test]
    fn docker_removal_already_in_progress_is_an_idempotent_stop_outcome() {
        let error = bollard::errors::Error::DockerResponseServerError {
            status_code: 409,
            message: "removal of container abc123 is already in progress".into(),
        };

        assert!(is_removal_in_progress(&error));
    }

    #[test]
    fn unrelated_docker_conflicts_are_not_silently_accepted() {
        for (status_code, message) in [
            (409, "container abc123 has active exec sessions"),
            (409, "removal of image abc123 is already in progress"),
            (500, "removal of container abc123 is already in progress"),
        ] {
            let error = bollard::errors::Error::DockerResponseServerError {
                status_code,
                message: message.into(),
            };

            assert!(!is_removal_in_progress(&error));
        }
    }

    #[test]
    fn workspace_input_archive_uses_private_regular_files_under_an_unpredictable_root() {
        let job_id = Uuid::new_v4();
        let archive = build_workspace_tar(
            "runtime-secret-instance",
            job_id,
            &[WorkspaceFile {
                path: "scripts/analysis.py".into(),
                encoding: crate::model::WorkspaceFileEncoding::Utf8,
                content: "print('validated')\n".into(),
                sha256: hex::encode(Sha256::digest(b"print('validated')\n")),
            }],
        )
        .expect("workspace archive");
        let mut entries = tar::Archive::new(archive.as_slice())
            .entries()
            .expect("tar entries")
            .map(|entry| {
                let mut entry = entry.expect("tar entry");
                let path = entry.path().expect("entry path").into_owned();
                let mode = entry.header().mode().expect("mode");
                let mut content = String::new();
                entry.read_to_string(&mut content).expect("entry content");
                (path, mode, content)
            })
            .collect::<Vec<_>>();
        let file = entries.pop().expect("file entry");
        assert!(file.0.to_string_lossy().ends_with("/scripts/analysis.py"));
        assert!(file.0.to_string_lossy().starts_with(".shennong-input-"));
        assert_eq!(file.1, 0o600);
        assert_eq!(file.2, "print('validated')\n");
    }

    #[test]
    fn workspace_input_archive_stages_decoded_binary_bytes() {
        let payload = [0_u8, 255, 1, 128];
        let archive = build_workspace_tar(
            "runtime-secret-instance",
            Uuid::new_v4(),
            &[WorkspaceFile {
                path: "inputs/binary.bin".into(),
                encoding: WorkspaceFileEncoding::Base64,
                content: "AP8BgA==".into(),
                sha256: hex::encode(Sha256::digest(payload)),
            }],
        )
        .expect("workspace archive");
        let mut content = Vec::new();
        for entry in tar::Archive::new(archive.as_slice())
            .entries()
            .expect("tar entries")
        {
            let mut entry = entry.expect("tar entry");
            if entry.header().entry_type().is_file() {
                entry.read_to_end(&mut content).expect("binary content");
            }
        }
        assert_eq!(content, payload);
    }

    #[test]
    fn active_helper_containers_receive_a_bounded_orphan_grace_period() {
        assert!(helper_orphan_within_grace(
            Some("workspace-init"),
            Some(990),
            1_000
        ));
        assert!(helper_orphan_within_grace(
            Some("artifact-scanner"),
            Some(881),
            1_000
        ));
        assert!(helper_orphan_within_grace(
            Some("artifact-reader"),
            Some(999),
            1_000
        ));
        assert!(!helper_orphan_within_grace(
            Some("artifact-scanner"),
            Some(880),
            1_000
        ));
        assert!(!helper_orphan_within_grace(Some("job"), Some(999), 1_000));
    }

    #[test]
    fn docker_receives_only_a_non_replayable_session_secret_digest() {
        let secret = "test-session-secret-material".repeat(3);
        let digest = session_secret_digest(&secret);
        assert_eq!(digest.len(), 64);
        assert_ne!(digest, secret);
    }

    #[test]
    fn authenticated_gateway_readiness_probe_supplies_the_trusted_request_url() {
        let url = "http://127.0.0.1:32777/v1/sessions/00000000-0000-4000-8000-000000000000/proxy/";
        let request = authenticated_gateway_probe(&reqwest::Client::new(), url, "session-secret")
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(SESSION_SECRET_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
            "session-secret"
        );
        assert_eq!(
            request
                .headers()
                .get(RSTUDIO_REQUEST_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
            url
        );
    }

    fn policy_attestation() -> EgressPolicyAttestation {
        EgressPolicyAttestation {
            version: 1,
            rootless_uid: 1001,
            netns_pid: 4242,
            netns_inode: 4_026_531_999,
            job_bridge: "sn-job-egress".into(),
            session_bridge: "sn-session".into(),
            runtime_proxy_v4: "10.252.0.1/32".into(),
        }
    }

    #[test]
    fn current_rootless_namespace_policy_attestation_is_accepted() {
        validate_egress_policy_attestation(
            &policy_attestation(),
            4242,
            4242,
            1001,
            "sn-job-egress",
            "sn-session",
            "10.252.0.1/32",
        )
        .expect("current policy attestation");
    }

    #[test]
    fn stale_or_racing_rootless_namespace_policy_attestation_fails_closed() {
        assert!(
            validate_egress_policy_attestation(
                &policy_attestation(),
                4242,
                4243,
                1001,
                "sn-job-egress",
                "sn-session",
                "10.252.0.1/32",
            )
            .is_err()
        );
        assert!(
            validate_egress_policy_attestation(
                &policy_attestation(),
                4242,
                4242,
                1001,
                "sn-job-egress",
                "sn-session",
                "10.252.0.2/32",
            )
            .is_err()
        );
    }

    #[test]
    fn writable_policy_attestation_is_rejected() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().expect("temporary policy directory");
        let child_pid_file = directory.path().join("child_pid");
        let state_file = directory.path().join("policy.ready");
        fs::write(&child_pid_file, "4242\n").expect("child PID");
        fs::write(
            &state_file,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "rootless_uid": fs::metadata(&child_pid_file).expect("PID metadata").uid(),
                "netns_pid": 4242,
                "netns_inode": 4_026_531_999_u64,
                "job_bridge": "sn-job-egress",
                "session_bridge": "sn-session",
                "runtime_proxy_v4": "10.252.0.1/32"
            }))
            .expect("attestation JSON"),
        )
        .expect("attestation");
        fs::set_permissions(&state_file, fs::Permissions::from_mode(0o666))
            .expect("writable attestation permissions");

        let guard = super::EgressPolicyGuard {
            state_file,
            child_pid_file,
            rootless_uid: fs::metadata(directory.path().join("child_pid"))
                .expect("PID metadata")
                .uid(),
            job_bridge: "sn-job-egress".into(),
            session_bridge: "sn-session".into(),
            runtime_proxy_v4: "10.252.0.1/32".into(),
        };
        assert!(guard.verify().is_err());
    }

    #[test]
    fn docker_network_must_map_to_the_attested_managed_bridge() {
        let mut network = bollard::models::Network {
            name: Some("shennong-job-egress".into()),
            id: Some("network-job".into()),
            scope: Some("local".into()),
            driver: Some("bridge".into()),
            options: Some(HashMap::from([(
                "com.docker.network.bridge.name".into(),
                "sn-job-egress".into(),
            )])),
            labels: Some(HashMap::from([
                ("dev.shennong.managed".into(), "true".into()),
                ("dev.shennong.network-policy".into(), "internet-only".into()),
            ])),
            ..Default::default()
        };
        validate_managed_network(&network, "shennong-job-egress", "sn-job-egress")
            .expect("managed bridge");
        network.options.as_mut().expect("options").insert(
            "com.docker.network.bridge.name".into(),
            "unfiltered-bridge".into(),
        );
        assert!(
            validate_managed_network(&network, "shennong-job-egress", "sn-job-egress").is_err()
        );
    }
}
