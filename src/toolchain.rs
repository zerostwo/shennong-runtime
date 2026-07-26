use std::{fs, io::ErrorKind, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    error::{Result, RuntimeError},
    model::{CompatibilityLock, R_TOOLCHAIN_SCHEMA},
};

const MAX_TOOLCHAIN_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RToolchainManifest {
    pub schema: String,
    pub r: String,
    pub packages: ToolchainPackages,
    pub source_commits: SourceCommits,
    pub mcp: ToolchainMcp,
    pub skills: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainPackages {
    #[serde(rename = "Shennong")]
    pub shennong: String,
    #[serde(rename = "ShennongData")]
    pub shennong_data: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCommits {
    #[serde(rename = "Shennong")]
    pub shennong: String,
    #[serde(rename = "ShennongData")]
    pub shennong_data: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainMcp {
    #[serde(rename = "Shennong")]
    pub shennong: Vec<String>,
    #[serde(rename = "ShennongData")]
    pub shennong_data: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RuntimeToolchain {
    pub manifest: RToolchainManifest,
    pub sha256: String,
}

impl RuntimeToolchain {
    pub fn load(path: &Path) -> Result<Option<Self>> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(RuntimeError::Validation(format!(
                    "cannot inspect R toolchain manifest: {error}"
                )));
            }
        };
        if !metadata.is_file() || metadata.len() > MAX_TOOLCHAIN_MANIFEST_BYTES {
            return Err(RuntimeError::Validation(
                "R toolchain manifest must be a regular file no larger than 64 KiB".into(),
            ));
        }
        let bytes = fs::read(path).map_err(|error| {
            RuntimeError::Validation(format!("cannot read R toolchain manifest: {error}"))
        })?;
        let manifest: RToolchainManifest = serde_json::from_slice(&bytes).map_err(|error| {
            RuntimeError::Validation(format!("invalid R toolchain manifest: {error}"))
        })?;
        manifest.validate()?;
        let canonical = serde_json::to_vec(&manifest)
            .map_err(|error| RuntimeError::Internal(error.to_string()))?;
        Ok(Some(Self {
            manifest,
            sha256: hex::encode(Sha256::digest(canonical)),
        }))
    }

    pub fn validate_lock(&self, lock: &CompatibilityLock) -> Result<()> {
        lock.validate()?;
        if lock.runtime_toolchain.schema != self.manifest.schema {
            return Err(RuntimeError::Validation(
                "compatibility lock runtime toolchain schema does not match this Runtime".into(),
            ));
        }
        if lock.runtime_toolchain.sha256 != self.sha256 {
            return Err(RuntimeError::Validation(
                "compatibility lock toolchain manifest sha256 does not match this Runtime".into(),
            ));
        }
        for (name, requested, actual_version, actual_commit) in [
            (
                "Shennong",
                &lock.packages.shennong,
                &self.manifest.packages.shennong,
                &self.manifest.source_commits.shennong,
            ),
            (
                "ShennongData",
                &lock.packages.shennong_data,
                &self.manifest.packages.shennong_data,
                &self.manifest.source_commits.shennong_data,
            ),
        ] {
            if requested.version != *actual_version {
                return Err(RuntimeError::Validation(format!(
                    "compatibility lock {name} version does not match this Runtime"
                )));
            }
            if requested.commit != *actual_commit {
                return Err(RuntimeError::Validation(format!(
                    "compatibility lock {name} commit does not match this Runtime"
                )));
            }
        }
        Ok(())
    }
}

impl RToolchainManifest {
    fn validate(&self) -> Result<()> {
        if self.schema != R_TOOLCHAIN_SCHEMA {
            return Err(RuntimeError::Validation(format!(
                "R toolchain manifest schema must be {R_TOOLCHAIN_SCHEMA}"
            )));
        }
        for (label, value) in [
            ("R version", self.r.as_str()),
            ("Shennong version", self.packages.shennong.as_str()),
            ("ShennongData version", self.packages.shennong_data.as_str()),
        ] {
            if value.is_empty() || value.len() > 256 {
                return Err(RuntimeError::Validation(format!(
                    "R toolchain manifest has an invalid {label}"
                )));
            }
        }
        if self.mcp.shennong.is_empty()
            || self.mcp.shennong_data.is_empty()
            || self.skills.is_empty()
            || self
                .mcp
                .shennong
                .iter()
                .chain(&self.mcp.shennong_data)
                .chain(&self.skills)
                .any(|value| value.is_empty() || value.len() > 128)
        {
            return Err(RuntimeError::Validation(
                "R toolchain manifest MCP and Skill inventories must be non-empty bounded strings"
                    .into(),
            ));
        }
        for (label, commit) in [
            ("Shennong", self.source_commits.shennong.as_str()),
            ("ShennongData", self.source_commits.shennong_data.as_str()),
        ] {
            if commit.len() != 40
                || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
                || commit.bytes().any(|byte| byte.is_ascii_uppercase())
            {
                return Err(RuntimeError::Validation(format!(
                    "R toolchain manifest has an invalid {label} source commit"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write, os::unix::fs::symlink};

    use super::RuntimeToolchain;

    #[test]
    fn canonical_manifest_digest_ignores_json_whitespace() {
        let compact = tempfile::NamedTempFile::new().unwrap();
        let mut pretty = tempfile::NamedTempFile::new().unwrap();
        let document = r#"{"schema":"shennong.dev/runtime-r-toolchain/v1","r":"R version 4.6.0","packages":{"Shennong":"0.2.0.9000","ShennongData":"0.2.0.9000"},"source_commits":{"Shennong":"c1d958db3319f635ff5d6f9ad484a208774a4a39","ShennongData":"17f0f0e87dd8ad2a3751dd11c58c8aa43823aa69"},"mcp":{"Shennong":["list_methods"],"ShennongData":["check_compatibility"]},"skills":["manage-shennong-results"]}"#;
        std::fs::write(compact.path(), document).unwrap();
        write!(
            pretty,
            "{}",
            serde_json::to_string_pretty(
                &serde_json::from_str::<serde_json::Value>(document).unwrap()
            )
            .unwrap()
        )
        .unwrap();

        let compact = RuntimeToolchain::load(compact.path()).unwrap().unwrap();
        let pretty = RuntimeToolchain::load(pretty.path()).unwrap().unwrap();
        assert_eq!(compact.sha256, pretty.sha256);
    }

    #[test]
    fn manifest_symlink_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("manifest.json");
        let link = directory.path().join("manifest-link.json");
        std::fs::write(&manifest, "{}").unwrap();
        symlink(&manifest, &link).unwrap();

        let error = RuntimeToolchain::load(&link).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must be a regular file no larger than 64 KiB")
        );
    }
}
