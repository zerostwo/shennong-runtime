use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header::HeaderName},
    middleware,
    response::Response,
    routing::{any, get, post},
};
use serde::{Deserialize, Serialize};
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;

use crate::{
    auth::{Principal, require_auth},
    error::{Result, RuntimeError},
    model::{ArtifactManifestEntry, JobSpec, JobView, LogEntry, SessionSpec, SessionView},
    proxy::{session_proxy_path, session_proxy_root},
    service::AppState,
};

static IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

pub fn router(state: Arc<AppState>) -> Router {
    let public = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/info", get(info));
    let protected = Router::new()
        .route("/v1/jobs", post(submit_job))
        .route("/v1/jobs/{id}", get(get_job))
        .route("/v1/jobs/{id}/cancel", post(cancel_job))
        .route("/v1/jobs/{id}/logs", get(job_logs))
        .route("/v1/jobs/{id}/artifacts", get(job_artifacts))
        .route("/v1/sessions", post(submit_session))
        .route("/v1/sessions/{id}", get(get_session))
        .route("/v1/sessions/{id}/stop", post(stop_session))
        .route("/v1/sessions/{id}/proxy", any(session_proxy_root))
        .route("/v1/sessions/{id}/proxy/", any(session_proxy_root))
        .route("/v1/sessions/{id}/proxy/{*path}", any(session_proxy_path))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ));

    Router::new()
        .merge(public)
        .merge(protected)
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(RequestBodyLimitLayer::new(64 * 1024 * 1024))
        .with_state(state)
}

async fn health(State(state): State<Arc<AppState>>) -> Result<Json<HealthResponse>> {
    state.journal.ping().await?;
    state.executor.ping().await?;
    Ok(Json(HealthResponse {
        status: "ok",
        journal: "ok",
        executor: state.executor.name(),
    }))
}

async fn info(State(state): State<Arc<AppState>>) -> Json<InfoResponse> {
    let mut profiles: Vec<_> = state.config.worker_profiles.keys().cloned().collect();
    profiles.sort();
    Json(InfoResponse {
        service: "shennong-runtime",
        version: env!("CARGO_PKG_VERSION"),
        api_versions: vec!["shennong.dev/v1"],
        executor: state.executor.name(),
        worker_profiles: profiles,
        network_policy: "internet_only",
    })
}

async fn submit_job(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    payload: std::result::Result<Json<JobSpec>, JsonRejection>,
) -> Result<(StatusCode, Json<JobView>)> {
    let spec = validated_json(payload)?;
    let key = idempotency_key(&headers)?;
    let view = state.submit_job(&principal, key, spec).await?;
    Ok((StatusCode::ACCEPTED, Json(view)))
}

async fn get_job(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<JobView>> {
    Ok(Json(state.get_job(&principal, id).await?))
}

async fn cancel_job(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<JobView>> {
    Ok(Json(state.cancel_job(&principal, id).await?))
}

async fn job_logs(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Query(query): Query<LogQuery>,
) -> Result<Json<LogPage>> {
    let entries = state
        .job_logs(
            &principal,
            id,
            query.after.unwrap_or(0),
            query.limit.unwrap_or(100),
        )
        .await?;
    let next_cursor = entries
        .last()
        .map(|entry| entry.cursor)
        .unwrap_or(query.after.unwrap_or(0));
    Ok(Json(LogPage {
        entries,
        next_cursor,
    }))
}

async fn job_artifacts(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactPage>> {
    Ok(Json(ArtifactPage {
        artifacts: state.job_artifacts(&principal, id).await?,
    }))
}

async fn submit_session(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    payload: std::result::Result<Json<SessionSpec>, JsonRejection>,
) -> Result<(StatusCode, Json<SessionView>)> {
    let spec = validated_json(payload)?;
    let key = idempotency_key(&headers)?;
    let view = state.submit_session(&principal, key, spec).await?;
    Ok((StatusCode::ACCEPTED, Json(view)))
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<SessionView>> {
    Ok(Json(state.get_session(&principal, id).await?))
}

async fn stop_session(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<SessionView>> {
    Ok(Json(state.stop_session(&principal, id).await?))
}

async fn not_found() -> Response<Body> {
    RuntimeError::NotFound("route".into()).into_response()
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str> {
    headers
        .get(&IDEMPOTENCY_KEY)
        .ok_or_else(|| RuntimeError::Validation("Idempotency-Key header is required".into()))?
        .to_str()
        .map_err(|_| RuntimeError::Validation("Idempotency-Key is not valid ASCII".into()))
}

fn validated_json<T>(payload: std::result::Result<Json<T>, JsonRejection>) -> Result<T> {
    payload.map(|Json(value)| value).map_err(|_| {
        RuntimeError::Validation("request JSON does not match the strict API schema".into())
    })
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    journal: &'static str,
    executor: &'static str,
}

#[derive(Serialize)]
struct InfoResponse {
    service: &'static str,
    version: &'static str,
    api_versions: Vec<&'static str>,
    executor: &'static str,
    worker_profiles: Vec<String>,
    network_policy: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogQuery {
    after: Option<i64>,
    limit: Option<u32>,
}

#[derive(Serialize)]
struct LogPage {
    entries: Vec<LogEntry>,
    next_cursor: i64,
}

#[derive(Serialize)]
struct ArtifactPage {
    artifacts: Vec<ArtifactManifestEntry>,
}

use axum::response::IntoResponse;
