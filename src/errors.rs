use axum::extract::rejection::JsonRejection;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;
use tracing::error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error(transparent)]
    DatabaseError(sqlx::Error),

    #[error("KMS error: {0}")]
    KmsError(String),

    #[error("Item not found")]
    NotFoundError,

    #[error("A conflict occurred")]
    Conflict,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Method not allowed")]
    MethodNotAllowed,

    #[error("Unauthorized")]
    Unauthorized,

    #[error(transparent)]
    JsonExtractionError(#[from] JsonRejection),

    #[error(transparent)]
    ParseJsonError(#[from] serde_json::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::DatabaseError(db_err) => {
                error!("Database error: {}", db_err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal database error occurred".to_string(),
                )
            }
            AppError::KmsError(kms_err) => {
                error!("KMS error: {}", kms_err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal KMS error occurred".to_string(),
                )
            }
            AppError::NotFoundError => (
                StatusCode::NOT_FOUND,
                "The requested item was not found".to_string(),
            ),
            AppError::Conflict => (
                StatusCode::CONFLICT,
                "A conflict occurred. The resource may already exist.".to_string(),
            ),
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::CryptoError(msg) => {
                error!("Crypto error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "A cryptographic operation failed".to_string(),
                )
            }
            AppError::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                "This method is not allowed for the requested resource".to_string(),
            ),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "You are not authorized to perform this action".to_string(),
            ),
            AppError::JsonExtractionError(rejection) => {
                let message = rejection.body_text();
                let status = rejection.status();
                error!("JSON Extractor failed: {} - {}", status, message);
                (status, message)
            }
            AppError::ParseJsonError(error) => {
                (StatusCode::BAD_REQUEST, format!("JSON Error: {}", error))
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        if let Some(e) = err.as_database_error() {
            if e.is_unique_violation() {
                return AppError::Conflict;
            }
        }
        AppError::DatabaseError(err)
    }
}
