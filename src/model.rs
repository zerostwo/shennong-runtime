use std::{collections::HashSet, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{Result, RuntimeError};

pub const RESULT_BUNDLE_SCHEMA: &str = "shennong.dev/analysis-result-bundle/v1";
pub const R_TOOLCHAIN_SCHEMA: &str = "shennong.dev/runtime-r-toolchain/v1";
pub const MAX_WORKSPACE_FILES: usize = 32;
pub const MAX_WORKSPACE_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_WORKSPACE_STAGING_BYTES: usize = 1024 * 1024;
pub const MAX_ARTIFACTS: usize = 256;
pub const MAX_ARTIFACT_DOWNLOAD_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RESULT_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    InternetOnly,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerKind {
    Batch,
    Ide,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerProfile {
    pub name: String,
    pub image: String,
    pub kind: WorkerKind,
    pub max_resources: ResourceLimits,
}

impl WorkerProfile {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("worker profile", &self.name, 64)?;
        validate_digest_image(&self.image)?;
        self.max_resources.validate_absolute()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub cpus: f64,
    pub memory_bytes: i64,
    pub pids: i64,
    pub timeout_seconds: u64,
    pub tmpfs_bytes: i64,
    pub max_log_bytes: i64,
    pub max_artifact_bytes: i64,
    pub max_workspace_bytes: i64,
}

impl ResourceLimits {
    pub fn default_batch() -> Self {
        Self {
            cpus: 2.0,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            pids: 256,
            timeout_seconds: 1800,
            tmpfs_bytes: 1024 * 1024 * 1024,
            max_log_bytes: 8 * 1024 * 1024,
            max_artifact_bytes: 2 * 1024 * 1024 * 1024,
            max_workspace_bytes: 20 * 1024 * 1024 * 1024,
        }
    }

    pub fn default_session() -> Self {
        Self {
            cpus: 4.0,
            memory_bytes: 16 * 1024 * 1024 * 1024,
            pids: 512,
            timeout_seconds: 8 * 60 * 60,
            tmpfs_bytes: 2 * 1024 * 1024 * 1024,
            max_log_bytes: 16 * 1024 * 1024,
            max_artifact_bytes: 4 * 1024 * 1024 * 1024,
            max_workspace_bytes: 50 * 1024 * 1024 * 1024,
        }
    }

    pub fn validate_against(&self, ceiling: &Self) -> Result<()> {
        self.validate_absolute()?;
        if self.cpus > ceiling.cpus
            || self.memory_bytes > ceiling.memory_bytes
            || self.pids > ceiling.pids
            || self.timeout_seconds > ceiling.timeout_seconds
            || self.tmpfs_bytes > ceiling.tmpfs_bytes
            || self.max_log_bytes > ceiling.max_log_bytes
            || self.max_artifact_bytes > ceiling.max_artifact_bytes
            || self.max_workspace_bytes > ceiling.max_workspace_bytes
        {
            return Err(RuntimeError::Validation(
                "requested resources exceed the server-side worker profile".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_absolute(&self) -> Result<()> {
        if !self.cpus.is_finite() || self.cpus <= 0.0 || self.cpus > 256.0 {
            return Err(RuntimeError::Validation(
                "cpus is outside the safe range".into(),
            ));
        }
        if !(64 * 1024 * 1024..=1024_i64.pow(4)).contains(&self.memory_bytes) {
            return Err(RuntimeError::Validation(
                "memory_bytes is outside the safe range".into(),
            ));
        }
        if !(16..=32768).contains(&self.pids) {
            return Err(RuntimeError::Validation(
                "pids is outside the safe range".into(),
            ));
        }
        if !(1..=7 * 24 * 60 * 60).contains(&self.timeout_seconds) {
            return Err(RuntimeError::Validation(
                "timeout_seconds is outside the safe range".into(),
            ));
        }
        if !(16 * 1024 * 1024..=64_i64 * 1024 * 1024 * 1024).contains(&self.tmpfs_bytes)
            || !(1024..=1024_i64.pow(3)).contains(&self.max_log_bytes)
            || !(1024..=16_i64 * 1024_i64.pow(3)).contains(&self.max_artifact_bytes)
            || !(64 * 1024 * 1024..=1024_i64.pow(4)).contains(&self.max_workspace_bytes)
        {
            return Err(RuntimeError::Validation(
                "tmpfs/log/artifact/workspace limit is outside the safe range".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub api_version: String,
    pub workspace_ref: String,
    pub worker_profile: String,
    pub argv: Vec<String>,
    pub resources: ResourceLimits,
    pub network: NetworkPolicy,
    #[serde(default)]
    pub workspace_files: Vec<WorkspaceFile>,
    #[serde(default)]
    pub artifact_rules: Vec<ArtifactRule>,
    #[serde(default)]
    pub compatibility_lock: Option<CompatibilityLock>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceFileEncoding {
    Utf8,
    Base64,
}

fn default_workspace_file_encoding() -> WorkspaceFileEncoding {
    WorkspaceFileEncoding::Utf8
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceFile {
    pub path: String,
    #[serde(default = "default_workspace_file_encoding")]
    pub encoding: WorkspaceFileEncoding,
    pub content: String,
    pub sha256: String,
}

impl WorkspaceFile {
    pub fn validate(&self) -> Result<()> {
        validate_workspace_relative_path(&self.path)?;
        if self.path == "."
            || self.path.ends_with('/')
            || self.path.contains('\\')
            || self
                .path
                .split('/')
                .any(|part| part.is_empty() || part == ".")
            || self.path.starts_with(".shennong-input-")
        {
            return Err(RuntimeError::Validation(
                "workspace input path must identify a regular project file".into(),
            ));
        }
        let bytes = self.decoded_bytes()?;
        if self.sha256.len() != 64
            || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || hex::encode(Sha256::digest(&bytes)) != self.sha256.to_ascii_lowercase()
        {
            return Err(RuntimeError::Validation(
                "workspace input content or sha256 is invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn decoded_bytes(&self) -> Result<Vec<u8>> {
        let max_encoded = MAX_WORKSPACE_FILE_BYTES.div_ceil(3) * 4;
        if self.content.len() > max_encoded {
            return Err(RuntimeError::Validation(
                "workspace input exceeds the per-file staging limit".into(),
            ));
        }
        let bytes = match self.encoding {
            WorkspaceFileEncoding::Utf8 => self.content.as_bytes().to_vec(),
            WorkspaceFileEncoding::Base64 => BASE64_STANDARD
                .decode(self.content.as_bytes())
                .map_err(|_| {
                    RuntimeError::Validation("workspace input base64 is invalid".into())
                })?,
        };
        if bytes.len() > MAX_WORKSPACE_FILE_BYTES {
            return Err(RuntimeError::Validation(
                "workspace input exceeds the per-file staging limit".into(),
            ));
        }
        Ok(bytes)
    }
}

impl JobSpec {
    pub fn validate(&self, profile: &WorkerProfile) -> Result<()> {
        if self.api_version != "shennong.dev/v1" {
            return Err(RuntimeError::Validation(
                "api_version must be shennong.dev/v1".into(),
            ));
        }
        validate_workspace_ref(&self.workspace_ref)?;
        if profile.kind != WorkerKind::Batch || profile.name != self.worker_profile {
            return Err(RuntimeError::Validation(
                "worker_profile is not a batch profile".into(),
            ));
        }
        validate_argv(&self.argv)?;
        self.resources.validate_against(&profile.max_resources)?;
        if self.artifact_rules.len() > 64 {
            return Err(RuntimeError::Validation(
                "at most 64 artifact rules are allowed".into(),
            ));
        }
        for rule in &self.artifact_rules {
            rule.validate()?;
        }
        if self.workspace_files.len() > MAX_WORKSPACE_FILES {
            return Err(RuntimeError::Validation(
                "workspace inputs exceed the 32-file or 1 MiB staging limit".into(),
            ));
        }
        let mut paths = HashSet::new();
        let mut staged_bytes = 0_usize;
        for file in &self.workspace_files {
            file.validate()?;
            staged_bytes = staged_bytes
                .checked_add(file.decoded_bytes()?.len())
                .ok_or_else(|| RuntimeError::Validation("workspace input size overflow".into()))?;
            if staged_bytes > MAX_WORKSPACE_STAGING_BYTES {
                return Err(RuntimeError::Validation(
                    "workspace inputs exceed the 32-file or 1 MiB staging limit".into(),
                ));
            }
            if !paths.insert(file.path.as_str()) {
                return Err(RuntimeError::Validation(
                    "workspace input paths must be unique".into(),
                ));
            }
        }
        for value in &self.argv {
            if let Some(path) = value.strip_prefix("workspace-input://") {
                validate_workspace_relative_path(path)?;
                if !paths.contains(path) {
                    return Err(RuntimeError::Validation(
                        "argv references an unstaged workspace input".into(),
                    ));
                }
            }
        }
        if let Some(compatibility_lock) = &self.compatibility_lock {
            compatibility_lock.validate()?;
            let result_bundle_rules = self
                .artifact_rules
                .iter()
                .filter(|rule| rule.role.as_deref() == Some("analysis_result_bundle"))
                .collect::<Vec<_>>();
            if result_bundle_rules.len() != 1 || !result_bundle_rules[0].required {
                return Err(RuntimeError::Validation(
                    "a compatibility-locked Job requires exactly one required analysis_result_bundle artifact rule"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRule {
    pub path: String,
    pub kind: ArtifactKind,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub required: bool,
}

impl ArtifactRule {
    pub fn validate(&self) -> Result<()> {
        validate_workspace_relative_path(&self.path)?;
        if let Some(role) = &self.role {
            validate_identifier("artifact role", role, 64)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityLock {
    pub result_bundle_schema: String,
    pub runtime_toolchain: RuntimeToolchainLock,
    pub packages: CompatibilityPackages,
}

impl CompatibilityLock {
    pub fn validate(&self) -> Result<()> {
        if self.result_bundle_schema != RESULT_BUNDLE_SCHEMA {
            return Err(RuntimeError::Validation(format!(
                "result_bundle_schema must be {RESULT_BUNDLE_SCHEMA}"
            )));
        }
        self.runtime_toolchain.validate()?;
        self.packages.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeToolchainLock {
    pub schema: String,
    pub sha256: String,
}

impl RuntimeToolchainLock {
    fn validate(&self) -> Result<()> {
        if self.schema != R_TOOLCHAIN_SCHEMA {
            return Err(RuntimeError::Validation(format!(
                "runtime toolchain schema must be {R_TOOLCHAIN_SCHEMA}"
            )));
        }
        validate_sha256("runtime toolchain sha256", &self.sha256)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityPackages {
    #[serde(rename = "Shennong")]
    pub shennong: CompatibilityPackage,
    #[serde(rename = "ShennongData")]
    pub shennong_data: CompatibilityPackage,
}

impl CompatibilityPackages {
    fn validate(&self) -> Result<()> {
        self.shennong.validate("Shennong")?;
        self.shennong_data.validate("ShennongData")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityPackage {
    pub version: String,
    pub commit: String,
}

impl CompatibilityPackage {
    fn validate(&self, name: &str) -> Result<()> {
        validate_identifier(&format!("{name} version"), &self.version, 128)?;
        validate_commit(&format!("{name} commit"), &self.commit)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Unbound,
    Verified,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Figure,
    Image,
    Table,
    Report,
    Notebook,
    Script,
    DatasetSubset,
    Archive,
    Other,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdeKind {
    Rstudio,
    Jupyterlab,
}

impl IdeKind {
    pub fn port(&self) -> u16 {
        match self {
            Self::Rstudio => 8787,
            Self::Jupyterlab => 8888,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSpec {
    pub api_version: String,
    pub workspace_ref: String,
    pub worker_profile: String,
    pub kind: IdeKind,
    pub resources: ResourceLimits,
    pub network: NetworkPolicy,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
}

impl SessionSpec {
    pub fn validate(&self, profile: &WorkerProfile) -> Result<()> {
        if self.api_version != "shennong.dev/v1" {
            return Err(RuntimeError::Validation(
                "api_version must be shennong.dev/v1".into(),
            ));
        }
        validate_workspace_ref(&self.workspace_ref)?;
        if profile.kind != WorkerKind::Ide || profile.name != self.worker_profile {
            return Err(RuntimeError::Validation(
                "worker_profile is not an IDE profile".into(),
            ));
        }
        self.resources.validate_against(&profile.max_resources)?;
        if !(300..=8 * 60 * 60).contains(&self.idle_timeout_seconds) {
            return Err(RuntimeError::Validation(
                "idle_timeout_seconds must be between 300 and 28800".into(),
            ));
        }
        if self.max_lifetime_seconds < self.idle_timeout_seconds
            || self.max_lifetime_seconds > profile.max_resources.timeout_seconds
        {
            return Err(RuntimeError::Validation(
                "max_lifetime_seconds is invalid for the profile".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Preparing,
    Running,
    CancelRequested,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Lost,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut | Self::Lost
        )
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        use JobState::*;
        matches!(
            (self, next),
            (Queued, Preparing | CancelRequested | Failed | Lost)
                | (Preparing, Running | CancelRequested | Failed | Lost)
                | (
                    Running,
                    CancelRequested | Succeeded | Failed | TimedOut | Lost
                )
                | (CancelRequested, Cancelled | Failed | Lost)
        ) || self == next
    }
}

impl std::fmt::Display for JobState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Queued => "queued",
            Self::Preparing => "preparing",
            Self::Running => "running",
            Self::CancelRequested => "cancel_requested",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::Lost => "lost",
        })
    }
}

impl std::str::FromStr for JobState {
    type Err = RuntimeError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "preparing" => Ok(Self::Preparing),
            "running" => Ok(Self::Running),
            "cancel_requested" => Ok(Self::CancelRequested),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "timed_out" => Ok(Self::TimedOut),
            "lost" => Ok(Self::Lost),
            other => Err(RuntimeError::Internal(format!("unknown job state {other}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Starting,
    Running,
    StopRequested,
    Stopped,
    Failed,
    Expired,
    Lost,
}

impl SessionState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Stopped | Self::Failed | Self::Expired | Self::Lost
        )
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        use SessionState::*;
        matches!(
            (self, next),
            (Starting, Running | StopRequested | Failed | Expired | Lost)
                | (Running, StopRequested | Failed | Expired | Lost)
                | (StopRequested, Stopped | Failed | Expired | Lost)
        ) || self == next
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::StopRequested => "stop_requested",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Lost => "lost",
        })
    }
}

impl std::str::FromStr for SessionState {
    type Err = RuntimeError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "starting" => Ok(Self::Starting),
            "running" => Ok(Self::Running),
            "stop_requested" => Ok(Self::StopRequested),
            "stopped" => Ok(Self::Stopped),
            "failed" => Ok(Self::Failed),
            "expired" => Ok(Self::Expired),
            "lost" => Ok(Self::Lost),
            other => Err(RuntimeError::Internal(format!(
                "unknown session state {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct JobView {
    pub id: Uuid,
    pub state: JobState,
    pub workspace_ref: String,
    pub worker_profile: String,
    pub attempt: i64,
    pub exit_code: Option<i64>,
    pub error: Option<String>,
    pub log_truncated: bool,
    pub compatibility_status: CompatibilityStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct JobRecord {
    pub view: JobView,
    pub owner_sub: String,
    pub idempotency_key: String,
    pub request_hash: String,
    pub spec: JobSpec,
    pub executor_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub cursor: i64,
    pub stream: LogStream,
    pub message: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Stdout,
    Stderr,
    System,
}

impl std::fmt::Display for LogStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::System => "system",
        })
    }
}

impl std::str::FromStr for LogStream {
    type Err = RuntimeError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            "system" => Ok(Self::System),
            other => Err(RuntimeError::Internal(format!(
                "unknown log stream {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifestEntry {
    pub id: Uuid,
    pub relative_path: String,
    pub kind: ArtifactKind,
    pub size_bytes: i64,
    pub sha256: String,
    pub media_type: Option<String>,
    pub role: Option<String>,
}

impl ArtifactManifestEntry {
    pub fn validate(&self, max_size: i64) -> Result<()> {
        validate_workspace_relative_path(&self.relative_path)?;
        if self.relative_path == "."
            || self.relative_path.ends_with('/')
            || self.relative_path.contains('\\')
            || self
                .relative_path
                .chars()
                .any(|character| matches!(character, '\0' | '\r' | '\n'))
            || self
                .relative_path
                .split('/')
                .any(|component| component.is_empty() || component == ".")
        {
            return Err(RuntimeError::Validation(
                "artifact path must identify a regular workspace file".into(),
            ));
        }
        if self.size_bytes < 0 || self.size_bytes > max_size {
            return Err(RuntimeError::Validation(
                "artifact exceeds size policy".into(),
            ));
        }
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(RuntimeError::Validation(
                "artifact sha256 is invalid".into(),
            ));
        }
        if let Some(role) = &self.role {
            validate_identifier("artifact role", role, 64)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionView {
    pub id: Uuid,
    pub state: SessionState,
    pub workspace_ref: String,
    pub kind: IdeKind,
    pub proxy_path: Option<String>,
    #[serde(skip_serializing)]
    pub internal_target: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct SessionRecord {
    pub view: SessionView,
    pub owner_sub: String,
    pub idempotency_key: String,
    pub request_hash: String,
    pub spec: SessionSpec,
    pub executor_id: Option<String>,
    pub internal_secret: Option<String>,
    pub last_activity_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ResolvedJob {
    pub id: Uuid,
    pub spec: JobSpec,
    pub profile: WorkerProfile,
    pub workspace_volume: String,
}

#[derive(Clone)]
pub struct ResolvedSession {
    pub id: Uuid,
    pub spec: SessionSpec,
    pub profile: WorkerProfile,
    pub workspace_volume: String,
    pub internal_secret: String,
}

#[derive(Clone, Debug)]
pub struct ExecutionOutcome {
    pub exit_code: i64,
    pub logs: Vec<(LogStream, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutorObservation {
    Running,
    Exited(i64),
    Missing,
}

pub fn validate_workspace_ref(value: &str) -> Result<()> {
    if !(8..=128).contains(&value.len())
        || !value.starts_with("ws_")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(RuntimeError::Validation(
            "workspace_ref must be an opaque ws_ identifier".into(),
        ));
    }
    Ok(())
}

fn validate_argv(argv: &[String]) -> Result<()> {
    if argv.is_empty() || argv.len() > 256 {
        return Err(RuntimeError::Validation(
            "argv must contain between 1 and 256 values".into(),
        ));
    }
    let executable = Path::new(&argv[0])
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&argv[0])
        .to_ascii_lowercase();
    let forbidden: HashSet<&str> = [
        "sh",
        "bash",
        "dash",
        "zsh",
        "fish",
        "csh",
        "tcsh",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
    ]
    .into_iter()
    .collect();
    if forbidden.contains(executable.as_str()) {
        return Err(RuntimeError::Validation(
            "shell executables are forbidden; submit an argv vector for the target program".into(),
        ));
    }
    for value in argv {
        if value.is_empty() || value.len() > 8192 || value.contains('\0') || value.contains('\n') {
            return Err(RuntimeError::Validation(
                "argv contains an invalid value".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_workspace_relative_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 512
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        })
    {
        return Err(RuntimeError::Validation(
            "artifact paths must remain relative to /workspace".into(),
        ));
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(RuntimeError::Validation(format!("invalid {label}")));
    }
    Ok(())
}

fn validate_commit(label: &str, value: &str) -> Result<()> {
    if value.len() != 40
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(RuntimeError::Validation(format!("invalid {label}")));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RuntimeError::Validation(format!("invalid {label}")));
    }
    Ok(())
}

fn validate_digest_image(value: &str) -> Result<()> {
    let Some((name, digest)) = value.rsplit_once("@sha256:") else {
        return Err(RuntimeError::Validation(
            "worker image must be pinned by sha256 digest".into(),
        ));
    };
    if name.is_empty() || digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(RuntimeError::Validation(
            "invalid worker image digest".into(),
        ));
    }
    Ok(())
}
