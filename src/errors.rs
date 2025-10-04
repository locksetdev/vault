use axum::extract::rejection::JsonRejection;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use lockset_vault_provider::ProviderError;
use serde::Serialize;
use serde_json::json;
use std::borrow::Cow;
use thiserror::Error;
use tracing::error;
use validator::ValidationErrors;

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

    #[error("Validation error: {0}")]
    ValidationError(#[from] ValidationErrors),
}

#[derive(Serialize)]
#[serde(untagged)]
enum AppErrorData {
    ValidatorErrors(std::collections::HashMap<Cow<'static, str>, Vec<String>>),
}

impl From<ProviderError> for AppError {
    fn from(err: ProviderError) -> Self {
        match err {
            ProviderError::InvalidConfiguration(msg) => AppError::InvalidInput(msg),
            ProviderError::SecretNotFound(_) => AppError::NotFoundError,
            ProviderError::ClientError(e) => {
                AppError::KmsError(format!("Provider client error: {}", e))
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message, data) = match self {
            AppError::DatabaseError(db_err) => {
                error!("Database error: {}", db_err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal database error occurred".to_string(),
                    None,
                )
            }
            AppError::KmsError(kms_err) => {
                error!("KMS error: {}", kms_err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal KMS error occurred".to_string(),
                    None,
                )
            }
            AppError::NotFoundError => (
                StatusCode::NOT_FOUND,
                "The requested item was not found".to_string(),
                None,
            ),
            AppError::Conflict => (
                StatusCode::CONFLICT,
                "A conflict occurred. The resource may already exist.".to_string(),
                None,
            ),
            AppError::InvalidInput(msg) => {
                error!("Invalid input: {}", msg);
                (StatusCode::BAD_REQUEST, msg, None)
            }
            AppError::CryptoError(msg) => {
                error!("Crypto error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "A cryptographic operation failed".to_string(),
                    None,
                )
            }
            AppError::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                "This method is not allowed for the requested resource".to_string(),
                None,
            ),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "You are not authorized to perform this action".to_string(),
                None,
            ),
            AppError::JsonExtractionError(rejection) => {
                let message = rejection.body_text();
                let status = rejection.status();
                error!("JSON Extractor failed: {} - {}", status, message);
                (status, message, None)
            }
            AppError::ParseJsonError(error) => (
                StatusCode::BAD_REQUEST,
                format!("JSON Error: {}", error),
                None,
            ),
            AppError::ValidationError(errors) => {
                let simplified_errors = errors
                    .field_errors()
                    .into_iter()
                    .map(|(field, errors)| {
                        let messages: Vec<String> = errors
                            .iter()
                            .map(|e| e.message.as_ref().unwrap().to_string())
                            .collect();
                        (field, messages)
                    })
                    .collect::<std::collections::HashMap<_, _>>();

                (
                    StatusCode::BAD_REQUEST,
                    "Payload Validation Error".to_string(),
                    Some(AppErrorData::ValidatorErrors(simplified_errors)),
                )
            }
        };

        let body = if data.is_none() {
            json!({
                "error": error_message,
            })
        } else {
            json!({
                "error": error_message,
                "data": data,
            })
        };
        (status, Json(body)).into_response()
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
