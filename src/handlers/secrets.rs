use crate::{
    errors::AppError,
    models::{
        CreateSecretRequest, CreateSecretResponse, CreateSecretVersionRequest,
        CreateSecretVersionResponse, JsonPayload, SecretResponse,
    },
    regex::{get_secret_name_regex, get_version_tag_regex},
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
        if payload.vault_connection.is_some() && payload.value.is_some() {
            return Err(AppError::InvalidInput(
                "Only one of `vault_connection_id` or `value` can be present".to_string(),
            ));
        }

        if payload.vault_connection.is_none() && payload.value.is_none() {
            return Err(AppError::InvalidInput(
                "One of `vault_connection_id` or `value` must be present".to_string(),
            ));
        }
        let response = SecretService::create_secret_with_version(&state, payload).await?;
        Ok((StatusCode::CREATED, Json(response)))
    }

    /// Get the current version of a secret by name
    pub async fn get_secret(
        State(state): State<Arc<AppState>>,
        Path(name): Path<String>,
    ) -> Result<Json<SecretResponse>, AppError> {
        if !get_secret_name_regex().is_match(&name) {
            return Err(AppError::InvalidInput(
                "Invalid secret name format".to_string(),
            ));
        }
        let response = SecretService::get_secret_current_version(&state, &name).await?;
        Ok(Json(response))
    }

    /// Create a new version for a first-class secret
    pub async fn create_secret_version(
        State(state): State<Arc<AppState>>,
        Path(name): Path<String>,
        JsonPayload(payload): JsonPayload<CreateSecretVersionRequest>,
    ) -> Result<(StatusCode, Json<CreateSecretVersionResponse>), AppError> {
        if !get_secret_name_regex().is_match(&name) {
            return Err(AppError::InvalidInput(
                "Invalid secret name format".to_string(),
            ));
        }
        let response = SecretService::create_secret_version(&state, &name, payload).await?;
        Ok((StatusCode::CREATED, Json(response)))
    }

    /// Get a specific version of a secret
    pub async fn get_secret_version(
        State(state): State<Arc<AppState>>,
        Path((name, tag)): Path<(String, String)>,
    ) -> Result<Json<SecretResponse>, AppError> {
        if !get_secret_name_regex().is_match(&name) {
            return Err(AppError::InvalidInput(
                "Invalid secret name format".to_string(),
            ));
        }
        if !get_version_tag_regex().is_match(&tag) {
            return Err(AppError::InvalidInput(
                "Invalid version tag format".to_string(),
            ));
        }
        let response =
            SecretService::get_secret_version(&state.db, &state.kms_client, &name, &tag).await?;
        Ok(Json(response))
    }
}
