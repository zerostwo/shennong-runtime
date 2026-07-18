use std::{collections::HashSet, sync::Arc};

use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};

use crate::{
    config::{JwtKey, RuntimeConfig},
    error::{Result, RuntimeError},
    service::AppState,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    pub jti: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub workspace_refs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Principal {
    pub subject: String,
    scopes: HashSet<String>,
    workspace_refs: HashSet<String>,
}

impl Principal {
    pub fn require_scope(&self, scope: &str) -> Result<()> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(RuntimeError::Forbidden(format!("missing scope {scope}")))
        }
    }

    pub fn require_workspace(&self, workspace_ref: &str) -> Result<()> {
        if self.workspace_refs.contains(workspace_ref) {
            Ok(())
        } else {
            Err(RuntimeError::Forbidden(
                "token does not authorize this workspace_ref".into(),
            ))
        }
    }
}

#[derive(Clone)]
pub struct JwtVerifier {
    key: DecodingKey,
    validation: Validation,
    max_ttl_seconds: i64,
}

impl JwtVerifier {
    pub fn new(config: &RuntimeConfig) -> Result<Self> {
        let (algorithm, key) = match &config.jwt_key {
            JwtKey::Hs256(secret) => (Algorithm::HS256, DecodingKey::from_secret(secret)),
            JwtKey::Ed25519Pem(pem) => (
                Algorithm::EdDSA,
                DecodingKey::from_ed_pem(pem).map_err(|error| {
                    RuntimeError::Validation(format!("invalid Ed25519 public key: {error}"))
                })?,
            ),
            JwtKey::Rs256Pem(pem) => (
                Algorithm::RS256,
                DecodingKey::from_rsa_pem(pem).map_err(|error| {
                    RuntimeError::Validation(format!("invalid RSA public key: {error}"))
                })?,
            ),
        };
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[config.jwt_audience.as_str()]);
        validation.set_issuer(&[config.jwt_issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub", "jti"]);
        validation.leeway = 5;
        validation.validate_nbf = true;
        Ok(Self {
            key,
            validation,
            max_ttl_seconds: config.max_token_ttl_seconds,
        })
    }

    pub fn verify(&self, token: &str) -> Result<Principal> {
        let claims = decode::<RuntimeClaims>(token, &self.key, &self.validation)
            .map_err(|error| RuntimeError::Unauthorized(error.to_string()))?
            .claims;
        let now = Utc::now().timestamp();
        if claims.jti.is_empty()
            || claims.sub.is_empty()
            || claims.iat > now + 5
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > self.max_ttl_seconds
        {
            return Err(RuntimeError::Unauthorized(
                "JWT lifetime or required identity claim is invalid".into(),
            ));
        }
        Ok(Principal {
            subject: claims.sub,
            scopes: claims.scopes.into_iter().collect(),
            workspace_refs: claims.workspace_refs.into_iter().collect(),
        })
    }
}

pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let result = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| RuntimeError::Unauthorized("missing bearer token".into()))
        .and_then(|token| state.jwt.verify(token));

    match result {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(error) => error.into_response(),
    }
}
