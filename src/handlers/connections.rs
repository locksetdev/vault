use crate::{
    errors::AppError,
    models::{CreateVaultConnectionRequest, VaultConnectionResponse},
    services::connections::ConnectionService,
    state::AppState,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use std::sync::Arc;
use crate::models::JsonPayload;

pub struct ConnectionHandler;

impl ConnectionHandler {
    /// Create a new Vault Connection
    pub async fn create_vault_connection(
        State(state): State<Arc<AppState>>,
        JsonPayload(payload): JsonPayload<CreateVaultConnectionRequest>,
    ) -> Result<(StatusCode, Json<VaultConnectionResponse>), AppError> {
        let response = ConnectionService::create_vault_connection(&state, payload).await?;
        Ok((StatusCode::CREATED, Json(response)))
    }

    /// Get a Vault Connection by its public ID
    pub async fn get_vault_connection(
        State(state): State<Arc<AppState>>,
        Path(public_id): Path<String>,
    ) -> Result<Json<VaultConnectionResponse>, AppError> {
        let response =
            ConnectionService::get_vault_connection(&state.db, &state.kms_client, &public_id)
                .await?;
        Ok(Json(response))
    }

    /// Delete a Vault Connection
    pub async fn delete_vault_connection(
        State(state): State<Arc<AppState>>,
        Path(public_id): Path<String>,
    ) -> Result<StatusCode, AppError> {
        let deleted = ConnectionService::delete_vault_connection(&state.db, &public_id).await?;

        if !deleted {
            return Err(AppError::NotFoundError);
        }

        Ok(StatusCode::NO_CONTENT)
    }
}
