use std::collections::{HashMap, HashSet};

use chrono::DateTime;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    error::{Result, RuntimeError},
    model::{
        ArtifactManifestEntry, MAX_ARTIFACTS, MAX_RESULT_BUNDLE_BYTES, RESULT_BUNDLE_SCHEMA,
        validate_workspace_relative_path,
    },
};

const MAX_INPUT_REFS: usize = 64;
const SENSITIVE_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "admin_key",
    "authorization",
    "client_secret",
    "secret",
    "access_key",
    "secret_key",
];

pub fn validate_result_bundle(
    bytes: &[u8],
    bundle_artifact: &ArtifactManifestEntry,
    artifacts: &[ArtifactManifestEntry],
) -> Result<()> {
    if bytes.len() > MAX_RESULT_BUNDLE_BYTES {
        return Err(RuntimeError::Validation(
            "analysis Result Bundle exceeds the 16 MiB validation limit".into(),
        ));
    }
    let bundle: Value = serde_json::from_slice(bytes).map_err(|error| {
        RuntimeError::Validation(format!("analysis Result Bundle is not valid JSON: {error}"))
    })?;
    reject_sensitive_fields(&bundle, "bundle")?;
    let object = bundle.as_object().ok_or_else(|| {
        RuntimeError::Validation("analysis Result Bundle must be a JSON object".into())
    })?;
    require_fields(
        object,
        &[
            "schema",
            "created_at",
            "result",
            "validation",
            "inputs",
            "provenance",
            "artifacts",
        ],
        "analysis Result Bundle",
    )?;
    if string_field(object, "schema", "analysis Result Bundle")? != RESULT_BUNDLE_SCHEMA {
        return Err(RuntimeError::Validation(format!(
            "analysis Result Bundle schema must be {RESULT_BUNDLE_SCHEMA}"
        )));
    }
    validate_timestamp(string_field(
        object,
        "created_at",
        "analysis Result Bundle",
    )?)?;
    validate_analysis_result(object.get("result").expect("required field"))?;
    validate_validation_report(object.get("validation").expect("required field"))?;
    validate_inputs(object.get("inputs").expect("required field"))?;
    validate_provenance(object.get("provenance").expect("required field"))?;
    validate_output_artifacts(
        object.get("artifacts").expect("required field"),
        bundle_artifact,
        artifacts,
    )
}

fn validate_analysis_result(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| RuntimeError::Validation("Result Bundle result must be an object".into()))?;
    require_fields(
        object,
        &[
            "schema_version",
            "analysis_type",
            "name",
            "method",
            "backend",
            "input",
            "parameters",
            "tables",
            "embeddings",
            "graphs",
            "models",
            "diagnostics",
            "warnings",
            "provenance",
        ],
        "Result Bundle result",
    )?;
    if string_field(object, "schema_version", "Result Bundle result")? != "1.0.0" {
        return Err(RuntimeError::Validation(
            "Result Bundle result schema_version must be 1.0.0".into(),
        ));
    }
    for field in ["analysis_type", "name", "method", "backend"] {
        string_field(object, field, "Result Bundle result")?;
    }
    for field in [
        "input",
        "parameters",
        "tables",
        "embeddings",
        "graphs",
        "models",
        "diagnostics",
        "provenance",
    ] {
        if !object.get(field).is_some_and(is_json_container) {
            return Err(RuntimeError::Validation(format!(
                "Result Bundle result {field} must be a JSON object or array"
            )));
        }
    }
    if !object.get("warnings").is_some_and(is_string_array) {
        return Err(RuntimeError::Validation(
            "Result Bundle result warnings must be an array of strings".into(),
        ));
    }
    Ok(())
}

fn validate_validation_report(value: &Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        RuntimeError::Validation("Result Bundle validation must be an object".into())
    })?;
    let has_empty_errors =
        matches!(object.get("errors"), Some(Value::Array(values)) if values.is_empty());
    if object.get("valid") != Some(&Value::Bool(true))
        || !has_empty_errors
        || !object.get("warnings").is_some_and(is_string_array)
    {
        return Err(RuntimeError::Validation(
            "Result Bundle validation must record valid=true, empty errors, and string-array warnings"
                .into(),
        ));
    }
    Ok(())
}

fn validate_inputs(value: &Value) -> Result<()> {
    let inputs = value
        .as_array()
        .ok_or_else(|| RuntimeError::Validation("Result Bundle inputs must be an array".into()))?;
    if inputs.is_empty() || inputs.len() > MAX_INPUT_REFS {
        return Err(RuntimeError::Validation(
            "a Runtime Result Bundle requires between 1 and 64 immutable input references".into(),
        ));
    }
    for (index, input) in inputs.iter().enumerate() {
        let label = format!("Result Bundle inputs[{index}]");
        let object = input
            .as_object()
            .ok_or_else(|| RuntimeError::Validation(format!("{label} must be an object")))?;
        require_fields(object, &["role", "revision", "digest"], &label)?;
        reject_unknown_fields(
            object,
            &[
                "role",
                "revision",
                "digest",
                "resource_id",
                "artifact_id",
                "media_type",
                "size_bytes",
                "metadata",
            ],
            &label,
        )?;
        string_field(object, "role", &label)?;
        string_field(object, "revision", &label)?;
        let has_identifier = ["resource_id", "artifact_id"]
            .into_iter()
            .filter_map(|field| object.get(field))
            .any(|value| value.as_str().is_some_and(|value| !value.is_empty()));
        if !has_identifier {
            return Err(RuntimeError::Validation(format!(
                "{label} requires resource_id or artifact_id"
            )));
        }
        validate_optional_record_fields(object, &label)?;
        validate_digest(object.get("digest").expect("required field"), &label)?;
    }
    Ok(())
}

fn validate_provenance(value: &Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        RuntimeError::Validation("Result Bundle provenance must be an object".into())
    })?;
    require_fields(
        object,
        &[
            "package_versions",
            "random_seed",
            "result_timestamp",
            "execution",
        ],
        "Result Bundle provenance",
    )?;
    if !object
        .get("package_versions")
        .is_some_and(is_json_container)
        || !object.get("execution").is_some_and(is_json_container)
    {
        return Err(RuntimeError::Validation(
            "Result Bundle provenance package_versions and execution must be JSON objects or arrays"
                .into(),
        ));
    }
    if !match object.get("result_timestamp") {
        Some(Value::Null) => true,
        Some(Value::String(value)) => !value.is_empty(),
        _ => false,
    } {
        return Err(RuntimeError::Validation(
            "Result Bundle provenance result_timestamp must be null or a non-empty string".into(),
        ));
    }
    Ok(())
}

fn validate_output_artifacts(
    value: &Value,
    bundle_artifact: &ArtifactManifestEntry,
    manifest: &[ArtifactManifestEntry],
) -> Result<()> {
    let records = value.as_array().ok_or_else(|| {
        RuntimeError::Validation("Result Bundle artifacts must be an array".into())
    })?;
    if records.len() > MAX_ARTIFACTS {
        return Err(RuntimeError::Validation(
            "Result Bundle contains more than 256 artifact records".into(),
        ));
    }
    let by_path: HashMap<&str, &ArtifactManifestEntry> = manifest
        .iter()
        .map(|artifact| (artifact.relative_path.as_str(), artifact))
        .collect();
    let by_id: HashMap<Uuid, &ArtifactManifestEntry> = manifest
        .iter()
        .map(|artifact| (artifact.id, artifact))
        .collect();
    let mut matched = HashSet::new();
    for (index, record) in records.iter().enumerate() {
        let label = format!("Result Bundle artifacts[{index}]");
        let object = record
            .as_object()
            .ok_or_else(|| RuntimeError::Validation(format!("{label} must be an object")))?;
        require_fields(object, &["role", "digest"], &label)?;
        reject_unknown_fields(
            object,
            &[
                "role",
                "digest",
                "artifact_id",
                "path",
                "media_type",
                "size_bytes",
                "metadata",
            ],
            &label,
        )?;
        let role = string_field(object, "role", &label)?;
        validate_optional_record_fields(object, &label)?;
        let digest = validate_digest(object.get("digest").expect("required field"), &label)?;
        let path_artifact = if let Some(value) = object.get("path") {
            let path = value
                .as_str()
                .filter(|path| !path.is_empty())
                .ok_or_else(|| {
                    RuntimeError::Validation(format!("{label} path must be a non-empty string"))
                })?;
            validate_bundle_relative_path(path, &label)?;
            Some(by_path.get(path).copied().ok_or_else(|| {
                RuntimeError::Validation(format!(
                    "{label} path does not match a scanned Job artifact"
                ))
            })?)
        } else {
            None
        };
        let id_artifact = if let Some(value) = object.get("artifact_id") {
            let id = value.as_str().filter(|id| !id.is_empty()).ok_or_else(|| {
                RuntimeError::Validation(format!(
                    "{label} artifact_id must be a non-empty UUID string"
                ))
            })?;
            let artifact_id = Uuid::parse_str(id).map_err(|_| {
                RuntimeError::Validation(format!("{label} artifact_id must be a UUID"))
            })?;
            Some(by_id.get(&artifact_id).copied().ok_or_else(|| {
                RuntimeError::Validation(format!(
                    "{label} artifact_id does not match a scanned Job artifact"
                ))
            })?)
        } else {
            None
        };
        let artifact = match (path_artifact, id_artifact) {
            (Some(by_path), Some(by_id)) if by_path.id == by_id.id => by_path,
            (Some(_), Some(_)) => {
                return Err(RuntimeError::Validation(format!(
                    "{label} path and artifact_id identify different Job artifacts"
                )));
            }
            (Some(artifact), None) | (None, Some(artifact)) => artifact,
            (None, None) => {
                return Err(RuntimeError::Validation(format!(
                    "{label} requires path or a Runtime manifest artifact_id for byte verification"
                )));
            }
        };
        if artifact.id == bundle_artifact.id {
            return Err(RuntimeError::Validation(format!(
                "{label} cannot recursively describe the Result Bundle itself"
            )));
        }
        if artifact.sha256.to_ascii_lowercase() != digest || artifact.role.as_deref() != Some(role)
        {
            return Err(RuntimeError::Validation(format!(
                "{label} role or sha256 does not match the scanned Job artifact"
            )));
        }
        if let Some(size) = object.get("size_bytes").and_then(Value::as_u64)
            && size != artifact.size_bytes as u64
        {
            return Err(RuntimeError::Validation(format!(
                "{label} size_bytes does not match the scanned Job artifact"
            )));
        }
        if let Some(media_type) = object.get("media_type").and_then(Value::as_str)
            && artifact.media_type.as_deref() != Some(media_type)
        {
            return Err(RuntimeError::Validation(format!(
                "{label} media_type does not match the scanned Job artifact"
            )));
        }
        if !matched.insert(artifact.id) {
            return Err(RuntimeError::Validation(format!(
                "{label} duplicates a previously described Job artifact"
            )));
        }
    }
    for artifact in manifest {
        if artifact.id != bundle_artifact.id
            && artifact.role.is_some()
            && !matched.contains(&artifact.id)
        {
            return Err(RuntimeError::Validation(format!(
                "scanned role-bearing artifact {} is absent from the Result Bundle artifacts",
                artifact.relative_path
            )));
        }
    }
    Ok(())
}

fn validate_optional_record_fields(object: &Map<String, Value>, label: &str) -> Result<()> {
    for field in ["resource_id", "artifact_id", "media_type"] {
        if let Some(value) = object.get(field)
            && !matches!(value, Value::String(value) if !value.is_empty() && value.len() <= 512)
        {
            return Err(RuntimeError::Validation(format!(
                "{label} {field} must be a non-empty bounded string"
            )));
        }
    }
    if let Some(value) = object.get("size_bytes")
        && value.as_u64().is_none()
    {
        return Err(RuntimeError::Validation(format!(
            "{label} size_bytes must be a non-negative integer"
        )));
    }
    if let Some(value) = object.get("metadata")
        && !is_json_container(value)
    {
        return Err(RuntimeError::Validation(format!(
            "{label} metadata must be a JSON object or array"
        )));
    }
    Ok(())
}

fn validate_digest(value: &Value, label: &str) -> Result<String> {
    let object = value
        .as_object()
        .ok_or_else(|| RuntimeError::Validation(format!("{label} digest must be an object")))?;
    reject_unknown_fields(object, &["algorithm", "value"], &format!("{label} digest"))?;
    if string_field(object, "algorithm", &format!("{label} digest"))? != "sha256" {
        return Err(RuntimeError::Validation(format!(
            "{label} digest algorithm must be sha256"
        )));
    }
    let value = string_field(object, "value", &format!("{label} digest"))?;
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(RuntimeError::Validation(format!(
            "{label} digest value must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(value.to_owned())
}

fn validate_bundle_relative_path(path: &str, label: &str) -> Result<()> {
    validate_workspace_relative_path(path)?;
    if path.contains('\\')
        || path.ends_with('/')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == ".")
    {
        return Err(RuntimeError::Validation(format!(
            "{label} path must be a safe bundle-relative path"
        )));
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<()> {
    if !value.ends_with('Z') || DateTime::parse_from_rfc3339(value).is_err() {
        return Err(RuntimeError::Validation(
            "Result Bundle created_at must be an RFC 3339 UTC timestamp ending in Z".into(),
        ));
    }
    Ok(())
}

fn reject_sensitive_fields(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized = normalize_field(key);
                if SENSITIVE_FIELDS.contains(&normalized.as_str()) {
                    return Err(RuntimeError::Validation(format!(
                        "Result Bundle contains forbidden credential field {path}.{key}"
                    )));
                }
                reject_sensitive_fields(child, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_sensitive_fields(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn normalize_field(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut separator = false;
    for byte in value.bytes().map(|byte| byte.to_ascii_lowercase()) {
        if byte.is_ascii_alphanumeric() {
            normalized.push(char::from(byte));
            separator = false;
        } else if !separator {
            normalized.push('_');
            separator = true;
        }
    }
    normalized.trim_matches('_').to_owned()
}

fn string_field<'a>(object: &'a Map<String, Value>, field: &str, label: &str) -> Result<&'a str> {
    match object.get(field) {
        Some(Value::String(value)) if !value.is_empty() && value.len() <= 1024 => Ok(value),
        _ => Err(RuntimeError::Validation(format!(
            "{label} {field} must be a non-empty bounded string"
        ))),
    }
}

fn require_fields(object: &Map<String, Value>, fields: &[&str], label: &str) -> Result<()> {
    let missing = fields
        .iter()
        .copied()
        .filter(|field| !object.contains_key(*field))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::Validation(format!(
            "{label} is missing required fields: {}",
            missing.join(", ")
        )))
    }
}

fn reject_unknown_fields(object: &Map<String, Value>, fields: &[&str], label: &str) -> Result<()> {
    let unknown = object
        .keys()
        .filter(|field| !fields.contains(&field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::Validation(format!(
            "{label} contains unsupported fields: {}",
            unknown.join(", ")
        )))
    }
}

fn is_string_array(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|values| values.iter().all(Value::is_string))
}

fn is_json_container(value: &Value) -> bool {
    value.is_object() || value.is_array()
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::validate_result_bundle;
    use crate::model::{ArtifactKind, ArtifactManifestEntry};

    fn fixture() -> (Vec<u8>, ArtifactManifestEntry, Vec<ArtifactManifestEntry>) {
        let output = b"feature,value\ngene1,1\n";
        let output_sha = hex::encode(Sha256::digest(output));
        let bundle = json!({
            "schema": "shennong.dev/analysis-result-bundle/v1",
            "created_at": "2026-07-26T00:00:00Z",
            "result": {
                "schema_version": "1.0.0",
                "analysis_type": "bulk_de",
                "name": "treated_vs_control",
                "method": "limma",
                "backend": "limma",
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
                "resource_id": "resource-1",
                "revision": "revision-7",
                "digest": {"algorithm": "sha256", "value": "a".repeat(64)}
            }],
            "provenance": {
                "package_versions": {"Shennong": "0.2.0.9000"},
                "random_seed": 1,
                "result_timestamp": "2026-07-26 UTC",
                "execution": {}
            },
            "artifacts": [{
                "role": "primary_table",
                "path": "results/table.csv",
                "size_bytes": output.len(),
                "media_type": "text/csv",
                "digest": {"algorithm": "sha256", "value": output_sha}
            }]
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let bundle_artifact = ArtifactManifestEntry {
            id: uuid::Uuid::new_v4(),
            relative_path: "results/bundle.json".into(),
            kind: ArtifactKind::Report,
            size_bytes: bytes.len() as i64,
            sha256: hex::encode(Sha256::digest(&bytes)),
            media_type: Some("application/json".into()),
            role: Some("analysis_result_bundle".into()),
        };
        let output_artifact = ArtifactManifestEntry {
            id: uuid::Uuid::new_v4(),
            relative_path: "results/table.csv".into(),
            kind: ArtifactKind::Table,
            size_bytes: output.len() as i64,
            sha256: output_sha,
            media_type: Some("text/csv".into()),
            role: Some("primary_table".into()),
        };
        (
            bytes,
            bundle_artifact.clone(),
            vec![bundle_artifact, output_artifact],
        )
    }

    #[test]
    fn validates_immutable_inputs_and_scanned_outputs() {
        let (bytes, bundle, manifest) = fixture();
        validate_result_bundle(&bytes, &bundle, &manifest).unwrap();
    }

    #[test]
    fn rejects_recursive_normalized_credential_fields() {
        let (bytes, bundle, manifest) = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["provenance"]["execution"]["API-Key"] = json!("must-not-cross-boundary");
        let error =
            validate_result_bundle(&serde_json::to_vec(&value).unwrap(), &bundle, &manifest)
                .unwrap_err();
        assert!(error.to_string().contains("credential"));
    }

    #[test]
    fn rejects_missing_immutable_input_references() {
        let (bytes, bundle, manifest) = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["inputs"] = json!([]);
        let error =
            validate_result_bundle(&serde_json::to_vec(&value).unwrap(), &bundle, &manifest)
                .unwrap_err();
        assert!(error.to_string().contains("immutable input"));
    }

    #[test]
    fn rejects_valid_report_with_errors() {
        let (bytes, bundle, manifest) = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["validation"]["errors"] = json!(["semantic validation failed"]);
        let error =
            validate_result_bundle(&serde_json::to_vec(&value).unwrap(), &bundle, &manifest)
                .unwrap_err();
        assert!(error.to_string().contains("empty errors"));
    }

    #[test]
    fn rejects_mismatched_or_duplicate_output_identifiers() {
        let (bytes, bundle, manifest) = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["artifacts"][0]["artifact_id"] = json!(bundle.id.to_string());
        let error =
            validate_result_bundle(&serde_json::to_vec(&value).unwrap(), &bundle, &manifest)
                .unwrap_err();
        assert!(error.to_string().contains("identify different"));

        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["artifacts"] = json!([value["artifacts"][0].clone(), value["artifacts"][0].clone()]);
        let error =
            validate_result_bundle(&serde_json::to_vec(&value).unwrap(), &bundle, &manifest)
                .unwrap_err();
        assert!(error.to_string().contains("duplicates"));
    }

    #[test]
    fn accepts_jsonlite_empty_list_arrays_and_null_result_timestamp() {
        let (bytes, bundle, manifest) = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for field in ["input", "parameters", "embeddings", "graphs", "models"] {
            value["result"][field] = json!([]);
        }
        value["provenance"]["package_versions"] = json!([]);
        value["provenance"]["execution"] = json!([]);
        value["provenance"]["result_timestamp"] = serde_json::Value::Null;
        validate_result_bundle(&serde_json::to_vec(&value).unwrap(), &bundle, &manifest).unwrap();
    }
}
