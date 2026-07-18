use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("authentication failed: {0}")]
    Unauthorized(String),
    #[error("permission denied: {0}")]
    Forbidden(String),
    #[error("invalid request: {0}")]
    Validation(String),
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("request conflicts with existing state: {0}")]
    Conflict(String),
    #[error("executor capacity exhausted: {0}")]
    Capacity(String),
    #[error("executor unavailable: {0}")]
    Executor(String),
    #[error("journal error: {0}")]
    Journal(#[from] sqlx::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    retryable: bool,
}

impl IntoResponse for RuntimeError {
    fn into_response(self) -> Response {
        let (status, code, retryable) = match &self {
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized", false),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden", false),
            Self::Validation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_request", false),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "not_found", false),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict", false),
            Self::Capacity(_) => (StatusCode::TOO_MANY_REQUESTS, "capacity_exhausted", true),
            Self::Executor(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "executor_unavailable",
                true,
            ),
            Self::Journal(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", true)
            }
        };
        let message = self.to_string();
        (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code,
                    message,
                    retryable,
                },
            }),
        )
            .into_response()
    }
}

pub type Result<T> = std::result::Result<T, RuntimeError>;
