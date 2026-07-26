use std::{
    collections::{HashMap, HashSet},
    env,
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, RuntimeError},
    model::{ResourceLimits, WorkerProfile},
};

const MOCK_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutorKind {
    Mock,
    Docker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DockerMode {
    Hardened,
    Simple,
}

#[derive(Clone, Debug)]
pub enum JwtKey {
    Hs256(Vec<u8>),
    Ed25519Pem(Vec<u8>),
    Rs256Pem(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct EgressPolicyConfig {
    pub state_file: PathBuf,
    pub child_pid_file: PathBuf,
    pub rootless_uid: u32,
    pub job_bridge: String,
    pub session_bridge: String,
    pub runtime_proxy_v4: String,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub listen: SocketAddr,
    pub database_url: String,
    pub executor_kind: ExecutorKind,
    pub docker_mode: DockerMode,
    pub docker_socket: Option<PathBuf>,
    pub job_network: String,
    pub session_network: String,
    pub runtime_instance_id: String,
    pub egress_policy: Option<EgressPolicyConfig>,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwt_key: JwtKey,
    pub max_token_ttl_seconds: i64,
    pub worker_profiles: HashMap<String, WorkerProfile>,
    pub max_log_page_size: u32,
    pub os_auth_cookie_names: HashSet<String>,
    pub max_concurrent_jobs: usize,
    pub max_concurrent_sessions: usize,
    pub monitor_interval: Duration,
    pub r_toolchain_manifest_path: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerProfilesDocument {
    profiles: Vec<WorkerProfile>,
}

impl RuntimeConfig {
    pub fn from_env() -> Result<Self> {
        let executor_kind = match env::var("SHENNONG_EXECUTOR")
            .unwrap_or_else(|_| "mock".into())
            .as_str()
        {
            "mock" => ExecutorKind::Mock,
            "docker" => ExecutorKind::Docker,
            other => {
                return Err(RuntimeError::Validation(format!(
                    "SHENNONG_EXECUTOR must be mock or docker, got {other}"
                )));
            }
        };

        let docker_mode = match env::var("SHENNONG_RUNTIME_DOCKER_MODE")
            .unwrap_or_else(|_| "hardened".into())
            .as_str()
        {
            "hardened" => DockerMode::Hardened,
            "simple" => DockerMode::Simple,
            other => {
                return Err(RuntimeError::Validation(format!(
                    "SHENNONG_RUNTIME_DOCKER_MODE must be hardened or simple, got {other}"
                )));
            }
        };
        let hardened = executor_kind == ExecutorKind::Docker && docker_mode == DockerMode::Hardened;

        let docker_socket = env::var_os("SHENNONG_ROOTLESS_DOCKER_SOCKET").map(PathBuf::from);
        if executor_kind == ExecutorKind::Docker {
            let socket = docker_socket.as_ref().ok_or_else(|| {
                RuntimeError::Validation(
                    "SHENNONG_ROOTLESS_DOCKER_SOCKET is required for docker executor".into(),
                )
            })?;
            validate_docker_socket(socket, docker_mode)?;
        }

        let jwt_key = parse_jwt_key(executor_kind == ExecutorKind::Docker)?;
        if executor_kind == ExecutorKind::Docker
            && matches!(&jwt_key, JwtKey::Hs256(value) if value == b"development-only-change-me-32-bytes")
        {
            return Err(RuntimeError::Validation(
                "development JWT key is forbidden with docker executor".into(),
            ));
        }

        let worker_profiles = parse_profiles(executor_kind == ExecutorKind::Docker)?;
        let os_auth_cookie_names =
            parse_os_auth_cookie_names(executor_kind == ExecutorKind::Docker)?;
        let runtime_instance_id = parse_runtime_instance_id(executor_kind == ExecutorKind::Docker)?;
        let egress_policy = parse_egress_policy(hardened)?;
        let job_network =
            parse_executor_network("SHENNONG_JOB_EGRESS_NETWORK", "shennong-job-egress")?;
        let session_network =
            parse_executor_network("SHENNONG_SESSION_PROXY_NETWORK", "shennong-session-proxy")?;
        if job_network == session_network {
            return Err(RuntimeError::Validation(
                "Job and Session Docker networks must differ".into(),
            ));
        }

        let listen: SocketAddr = env::var("SHENNONG_RUNTIME_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:7000".into())
            .parse()
            .map_err(|error| {
                RuntimeError::Validation(format!("invalid listen address: {error}"))
            })?;
        if hardened && !is_internal_address(listen.ip()) {
            return Err(RuntimeError::Validation(
                "docker executor requires an explicit loopback or private control-plane listen address; 0.0.0.0 and public addresses are forbidden"
                    .into(),
            ));
        }

        Ok(Self {
            listen,
            database_url: env::var("SHENNONG_RUNTIME_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://runtime.db?mode=rwc".into()),
            executor_kind,
            docker_mode,
            docker_socket,
            job_network,
            session_network,
            runtime_instance_id,
            egress_policy,
            jwt_issuer: env::var("SHENNONG_JWT_ISSUER").unwrap_or_else(|_| "shennong-os".into()),
            jwt_audience: env::var("SHENNONG_JWT_AUDIENCE")
                .unwrap_or_else(|_| "shennong-runtime".into()),
            jwt_key,
            max_token_ttl_seconds: env::var("SHENNONG_JWT_MAX_TTL_SECONDS")
                .unwrap_or_else(|_| "120".into())
                .parse()
                .map_err(|error| RuntimeError::Validation(format!("invalid JWT TTL: {error}")))?,
            worker_profiles,
            max_log_page_size: env::var("SHENNONG_MAX_LOG_PAGE_SIZE")
                .unwrap_or_else(|_| "200".into())
                .parse()
                .map_err(|error| {
                    RuntimeError::Validation(format!("invalid log page size: {error}"))
                })?,
            os_auth_cookie_names,
            max_concurrent_jobs: parse_concurrency("SHENNONG_MAX_CONCURRENT_JOBS", 4, 256)?,
            max_concurrent_sessions: parse_concurrency("SHENNONG_MAX_CONCURRENT_SESSIONS", 2, 64)?,
            monitor_interval: Duration::from_millis(parse_monitor_interval()?),
            r_toolchain_manifest_path: env::var_os("SHENNONG_R_TOOLCHAIN_MANIFEST")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/opt/shennong/runtime-r-toolchain.json")),
        })
    }

    pub fn for_test(database_url: String) -> Self {
        Self {
            listen: "127.0.0.1:0".parse().expect("test address"),
            database_url,
            executor_kind: ExecutorKind::Mock,
            docker_mode: DockerMode::Hardened,
            docker_socket: None,
            job_network: "shennong-job-egress".into(),
            session_network: "shennong-session-proxy".into(),
            runtime_instance_id: "runtime-test".into(),
            egress_policy: None,
            jwt_issuer: "shennong-os".into(),
            jwt_audience: "shennong-runtime".into(),
            jwt_key: JwtKey::Hs256(b"test-secret-at-least-32-bytes-long".to_vec()),
            max_token_ttl_seconds: 120,
            worker_profiles: default_mock_profiles(),
            max_log_page_size: 200,
            os_auth_cookie_names: HashSet::from(["shennong_os_session".into()]),
            max_concurrent_jobs: 4,
            max_concurrent_sessions: 2,
            monitor_interval: Duration::from_millis(20),
            r_toolchain_manifest_path: PathBuf::from(
                "/nonexistent/shennong-runtime-test-toolchain.json",
            ),
        }
    }
}

fn parse_executor_network(variable: &str, default: &str) -> Result<String> {
    let value = env::var(variable).unwrap_or_else(|_| default.into());
    if matches!(value.as_str(), "bridge" | "default" | "host" | "none")
        || value.starts_with("container:")
        || !(3..=63).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(RuntimeError::Validation(format!(
            "{variable} must name a dedicated 3-63 character Docker bridge network"
        )));
    }
    Ok(value)
}

fn parse_egress_policy(required: bool) -> Result<Option<EgressPolicyConfig>> {
    if !required {
        return Ok(None);
    }
    let required_path = |variable: &str| -> Result<PathBuf> {
        let path = env::var_os(variable)
            .map(PathBuf::from)
            .ok_or_else(|| RuntimeError::Validation(format!("{variable} is required")))?;
        if !path.is_absolute() {
            return Err(RuntimeError::Validation(format!(
                "{variable} must be an absolute path"
            )));
        }
        Ok(path)
    };
    let state_file = required_path("SHENNONG_EGRESS_POLICY_STATE_FILE")?;
    let child_pid_file = required_path("SHENNONG_ROOTLESSKIT_CHILD_PID_FILE")?;
    if state_file == child_pid_file {
        return Err(RuntimeError::Validation(
            "egress policy state and RootlessKit child PID paths must differ".into(),
        ));
    }

    let rootless_uid = env::var("SHENNONG_ROOTLESS_UID")
        .map_err(|_| RuntimeError::Validation("SHENNONG_ROOTLESS_UID is required".into()))?
        .parse::<u32>()
        .map_err(|_| {
            RuntimeError::Validation("SHENNONG_ROOTLESS_UID must be a positive numeric UID".into())
        })?;
    if rootless_uid == 0 {
        return Err(RuntimeError::Validation(
            "SHENNONG_ROOTLESS_UID must identify a non-root executor account".into(),
        ));
    }

    let bridge = |variable: &str| -> Result<String> {
        let value = env::var(variable)
            .map_err(|_| RuntimeError::Validation(format!("{variable} is required")))?;
        if value.is_empty()
            || value.len() > 15
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            return Err(RuntimeError::Validation(format!(
                "{variable} must be a 1-15 character Linux interface name"
            )));
        }
        Ok(value)
    };
    let job_bridge = bridge("SHENNONG_JOB_BRIDGE")?;
    let session_bridge = bridge("SHENNONG_SESSION_BRIDGE")?;
    if job_bridge == session_bridge {
        return Err(RuntimeError::Validation(
            "Job and Session bridge interface names must differ".into(),
        ));
    }

    let runtime_proxy_v4 = env::var("SHENNONG_RUNTIME_PROXY_V4")
        .map_err(|_| RuntimeError::Validation("SHENNONG_RUNTIME_PROXY_V4 is required".into()))?;
    let Some((address, prefix)) = runtime_proxy_v4.split_once('/') else {
        return Err(RuntimeError::Validation(
            "SHENNONG_RUNTIME_PROXY_V4 must be one exact IPv4 /32".into(),
        ));
    };
    if prefix != "32" || address.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(RuntimeError::Validation(
            "SHENNONG_RUNTIME_PROXY_V4 must be one exact IPv4 /32".into(),
        ));
    }

    Ok(Some(EgressPolicyConfig {
        state_file,
        child_pid_file,
        rootless_uid,
        job_bridge,
        session_bridge,
        runtime_proxy_v4,
    }))
}

fn parse_runtime_instance_id(required: bool) -> Result<String> {
    let value = match env::var("SHENNONG_RUNTIME_INSTANCE_ID") {
        Ok(value) => value,
        Err(_) if required => {
            return Err(RuntimeError::Validation(
                "SHENNONG_RUNTIME_INSTANCE_ID is required for the Docker executor".into(),
            ));
        }
        Err(_) => "runtime-development".into(),
    };
    if !(3..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(RuntimeError::Validation(
            "SHENNONG_RUNTIME_INSTANCE_ID must be 3-64 ASCII letters, digits, '_' or '-'".into(),
        ));
    }
    Ok(value)
}

fn parse_concurrency(variable: &str, default: usize, maximum: usize) -> Result<usize> {
    let value = env::var(variable)
        .unwrap_or_else(|_| default.to_string())
        .parse::<usize>()
        .map_err(|error| RuntimeError::Validation(format!("invalid {variable}: {error}")))?;
    if !(1..=maximum).contains(&value) {
        return Err(RuntimeError::Validation(format!(
            "{variable} must be between 1 and {maximum}"
        )));
    }
    Ok(value)
}

fn parse_monitor_interval() -> Result<u64> {
    let value = env::var("SHENNONG_MONITOR_INTERVAL_MS")
        .unwrap_or_else(|_| "2000".into())
        .parse::<u64>()
        .map_err(|error| RuntimeError::Validation(format!("invalid monitor interval: {error}")))?;
    if !(100..=60_000).contains(&value) {
        return Err(RuntimeError::Validation(
            "SHENNONG_MONITOR_INTERVAL_MS must be between 100 and 60000".into(),
        ));
    }
    Ok(value)
}

fn parse_os_auth_cookie_names(required: bool) -> Result<HashSet<String>> {
    let raw = match env::var("SHENNONG_OS_AUTH_COOKIE_NAMES") {
        Ok(raw) => raw,
        Err(_) if required => {
            return Err(RuntimeError::Validation(
                "SHENNONG_OS_AUTH_COOKIE_NAMES is required for the Docker executor".into(),
            ));
        }
        Err(_) => "shennong_os_session".into(),
    };
    let names: HashSet<_> = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    if names.is_empty()
        || names.iter().any(|name| {
            !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        })
    {
        return Err(RuntimeError::Validation(
            "SHENNONG_OS_AUTH_COOKIE_NAMES must contain valid comma-separated cookie names".into(),
        ));
    }
    Ok(names)
}

fn is_internal_address(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => address.is_loopback() || address.is_private(),
        std::net::IpAddr::V6(address) => {
            address.is_loopback() || (address.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn validate_docker_socket(path: &std::path::Path, mode: DockerMode) -> Result<()> {
    let text = path.to_string_lossy();
    if !path.is_absolute()
        || !text.ends_with("docker.sock")
        || (mode == DockerMode::Hardened
            && matches!(text.as_ref(), "/var/run/docker.sock" | "/run/docker.sock"))
    {
        return Err(RuntimeError::Validation(
            "docker executor requires an absolute docker.sock path; hardened mode forbids the system socket"
                .into(),
        ));
    }
    Ok(())
}

fn parse_jwt_key(production: bool) -> Result<JwtKey> {
    let algorithm = env::var("SHENNONG_JWT_ALGORITHM").unwrap_or_else(|_| "HS256".into());
    match algorithm.as_str() {
        "HS256" => {
            let secret = if env::var_os("SHENNONG_JWT_HS256_SECRET_FILE").is_some() {
                let secret = read_key_file("SHENNONG_JWT_HS256_SECRET_FILE")?;
                trim_secret_line_endings(secret)
            } else if production {
                return Err(RuntimeError::Validation(
                    "docker executor with HS256 requires SHENNONG_JWT_HS256_SECRET_FILE; environment secrets are development-only"
                        .into(),
                ));
            } else {
                env::var("SHENNONG_JWT_HS256_SECRET")
                    .unwrap_or_else(|_| "development-only-change-me-32-bytes".into())
                    .into_bytes()
            };
            if secret.len() < 32 {
                return Err(RuntimeError::Validation(
                    "HS256 verification secret must contain at least 32 bytes".into(),
                ));
            }
            Ok(JwtKey::Hs256(secret))
        }
        "EdDSA" => Ok(JwtKey::Ed25519Pem(read_key_file(
            "SHENNONG_JWT_PUBLIC_KEY_FILE",
        )?)),
        "RS256" => Ok(JwtKey::Rs256Pem(read_key_file(
            "SHENNONG_JWT_PUBLIC_KEY_FILE",
        )?)),
        other => Err(RuntimeError::Validation(format!(
            "unsupported SHENNONG_JWT_ALGORITHM {other}"
        ))),
    }
}

fn read_key_file(variable: &str) -> Result<Vec<u8>> {
    let path = env::var(variable)
        .map_err(|_| RuntimeError::Validation(format!("{variable} is required")))?;
    std::fs::read(&path)
        .map_err(|error| RuntimeError::Validation(format!("cannot read {path}: {error}")))
}

fn trim_secret_line_endings(mut secret: Vec<u8>) -> Vec<u8> {
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    secret
}

fn parse_profiles(required: bool) -> Result<HashMap<String, WorkerProfile>> {
    let Some(raw) = env::var_os("SHENNONG_WORKER_PROFILES_JSON") else {
        if required {
            return Err(RuntimeError::Validation(
                "SHENNONG_WORKER_PROFILES_JSON is required for docker executor".into(),
            ));
        }
        return Ok(default_mock_profiles());
    };
    let document: WorkerProfilesDocument = serde_json::from_str(&raw.to_string_lossy())
        .map_err(|error| RuntimeError::Validation(format!("invalid worker profiles: {error}")))?;
    let mut profiles = HashMap::new();
    for profile in document.profiles {
        profile.validate()?;
        if profiles.insert(profile.name.clone(), profile).is_some() {
            return Err(RuntimeError::Validation("duplicate worker profile".into()));
        }
    }
    if profiles.is_empty() {
        return Err(RuntimeError::Validation(
            "at least one worker profile is required".into(),
        ));
    }
    Ok(profiles)
}

fn default_mock_profiles() -> HashMap<String, WorkerProfile> {
    [
        WorkerProfile {
            name: "cpu-small".into(),
            image: format!("zerostwo/shennong-runtime@{MOCK_DIGEST}"),
            kind: crate::model::WorkerKind::Batch,
            max_resources: ResourceLimits::default_batch(),
        },
        WorkerProfile {
            name: "ide-small".into(),
            image: format!("zerostwo/shennong-runtime@{MOCK_DIGEST}"),
            kind: crate::model::WorkerKind::Ide,
            max_resources: ResourceLimits::default_session(),
        },
    ]
    .into_iter()
    .map(|profile| (profile.name.clone(), profile))
    .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{DockerMode, trim_secret_line_endings, validate_docker_socket};

    #[test]
    fn system_socket_requires_explicit_simple_mode() {
        let socket = Path::new("/var/run/docker.sock");
        assert!(validate_docker_socket(socket, DockerMode::Hardened).is_err());
        assert!(validate_docker_socket(socket, DockerMode::Simple).is_ok());
        assert!(
            validate_docker_socket(
                Path::new("/run/user/1001/shennong-runtime/docker.sock"),
                DockerMode::Hardened,
            )
            .is_ok()
        );
    }

    #[test]
    fn trims_only_trailing_secret_line_endings() {
        assert_eq!(
            trim_secret_line_endings(b"secret\r\n\r\n".to_vec()),
            b"secret"
        );
        assert_eq!(
            trim_secret_line_endings(b"  secret with spaces  \n".to_vec()),
            b"  secret with spaces  "
        );
        assert_eq!(
            trim_secret_line_endings(b"secret\ninside".to_vec()),
            b"secret\ninside"
        );
    }
}
