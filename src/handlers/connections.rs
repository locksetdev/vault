use crate::models::{JsonPayload, UpdateVaultConnectionResponse};
use crate::{
    errors::AppError,
    models::{CreateVaultConnectionRequest, UpdateVaultConnectionRequest, VaultConnectionResponse},
    services::connections::ConnectionService,
    state::AppState,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use std::sync::Arc;

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

    /// Update a Vault Connection
    pub async fn update_vault_connection(
        State(state): State<Arc<AppState>>,
        Path(public_id): Path<String>,
        JsonPayload(payload): JsonPayload<UpdateVaultConnectionRequest>,
    ) -> Result<Json<UpdateVaultConnectionResponse>, AppError> {
        let response =
            ConnectionService::update_vault_connection(&state, &public_id, payload).await?;
        Ok(Json(response))
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
