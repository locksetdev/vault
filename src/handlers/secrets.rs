use crate::{
    errors::AppError,
    models::{
        CreateSecretRequest, CreateSecretResponse, CreateSecretVersionRequest,
        CreateSecretVersionResponse, JsonPayload, SecretResponse,
    },
    services::secrets::SecretService,
    state::AppState,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use std::sync::Arc;

pub struct SecretHandler;

impl SecretHandler {
    /// Register a new secret with its first version
    pub async fn create_secret(
        State(state): State<Arc<AppState>>,
        JsonPayload(payload): JsonPayload<CreateSecretRequest>,
    ) -> Result<(StatusCode, Json<CreateSecretResponse>), AppError> {
        let response = SecretService::create_secret_with_version(&state, payload).await?;
        Ok((StatusCode::CREATED, Json(response)))
    }

    /// Get the current version of a secret by name
    pub async fn get_secret(
        State(state): State<Arc<AppState>>,
        Path(name): Path<String>,
    ) -> Result<Json<SecretResponse>, AppError> {
        let response =
            SecretService::get_secret_current_version(&state.db, &state.kms_client, &name).await?;
        Ok(Json(response))
    }

    /// Create a new version for a first-class secret
    pub async fn create_secret_version(
        State(state): State<Arc<AppState>>,
        Path(name): Path<String>,
        JsonPayload(payload): JsonPayload<CreateSecretVersionRequest>,
    ) -> Result<(StatusCode, Json<CreateSecretVersionResponse>), AppError> {
        let response = SecretService::create_secret_version(&state, &name, payload).await?;
        Ok((StatusCode::CREATED, Json(response)))
    }

    /// Get a specific version of a secret
    pub async fn get_secret_version(
        State(state): State<Arc<AppState>>,
        Path((name, tag)): Path<(String, String)>,
    ) -> Result<Json<SecretResponse>, AppError> {
        let response =
            SecretService::get_secret_version(&state.db, &state.kms_client, &name, &tag).await?;
        Ok(Json(response))
    }
}
