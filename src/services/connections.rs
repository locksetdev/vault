use crate::{
    crypto,
    errors::AppError,
    models::{
        CreateVaultConnectionRequest, CreateVaultConnectionResponse, UpdateVaultConnectionRequest,
        UpdateVaultConnectionResponse, VaultConnectionResponse,
    },
    repositories::connections::ConnectionRepository,
    state::AppState,
};
use aws_sdk_kms::Client as KmsClient;
use sqlx::PgPool;
use std::sync::Arc;

pub struct ConnectionService;

impl ConnectionService {
    /// Create a new vault connection
    pub async fn create_vault_connection(
        state: &Arc<AppState>,
        payload: CreateVaultConnectionRequest,
    ) -> Result<CreateVaultConnectionResponse, AppError> {
        let mut tx = state.db.begin().await?;

        // Encrypt the configuration
        let config_bytes = payload.config.as_bytes();
        let encrypted_payload = crypto::encrypt(&mut tx, &state.kms_client, &config_bytes).await?;

        // Insert into database
        let new_connection = ConnectionRepository::create_vault_connection(
            &mut tx,
            &payload,
            &encrypted_payload.sha256sum,
            &encrypted_payload.encrypted_blob,
            encrypted_payload.dek_id,
        )
        .await?;

        tx.commit().await?;

        let response = CreateVaultConnectionResponse {
            public_id: new_connection.public_id,
            integration_type: new_connection.integration_type,
            sha256sum: new_connection.sha256sum,
            ttl: new_connection.ttl,
            created_at: new_connection.created_at,
            updated_at: new_connection.updated_at,
        };

        Ok(response)
    }

    /// Update a vault connection
    pub async fn update_vault_connection(
        state: &Arc<AppState>,
        public_id: &str,
        payload: UpdateVaultConnectionRequest,
    ) -> Result<UpdateVaultConnectionResponse, AppError> {
        let mut tx = state.db.begin().await?;

        let mut encrypted_config = None;
        let mut sha256sum = None;
        let mut dek_id = None;

        if let Some(config) = payload.config {
            let config_bytes = config.as_bytes();
            let encrypted_payload =
                crypto::encrypt(&mut tx, &state.kms_client, &config_bytes).await?;
            encrypted_config = Some(encrypted_payload.encrypted_blob);
            sha256sum = Some(encrypted_payload.sha256sum);
            dek_id = Some(encrypted_payload.dek_id);
        }

        let updated_connection = ConnectionRepository::update_vault_connection(
            &mut tx,
            public_id,
            encrypted_config.as_deref(),
            sha256sum.as_deref(),
            dek_id,
            payload.ttl,
            payload.integration_type.as_deref(),
        )
        .await?;

        tx.commit().await?;

        let response = UpdateVaultConnectionResponse {
            public_id: updated_connection.public_id,
            integration_type: updated_connection.integration_type,
            sha256sum: updated_connection.sha256sum,
            ttl: updated_connection.ttl,
            created_at: updated_connection.created_at,
            updated_at: updated_connection.updated_at,
        };

        Ok(response)
    }

    /// Get a vault connection by its public ID
    pub async fn get_vault_connection(
        db: &PgPool,
        kms_client: &Arc<KmsClient>,
        public_id: &str,
    ) -> Result<VaultConnectionResponse, AppError> {
        let connection = ConnectionRepository::get_vault_connection_by_public_id(db, public_id)
            .await?
            .ok_or(AppError::NotFoundError)?;

        // Decrypt the configuration
        let decrypted_config_bytes = crypto::decrypt(
            db,
            kms_client,
            connection.dek_id,
            &connection.encrypted_config,
        )
        .await?;

        let config = String::from_utf8(decrypted_config_bytes).map_err(|e| {
            AppError::CryptoError(format!("Decrypted config is not valid UTF-8: {}", e))
        })?;

        let response = VaultConnectionResponse {
            public_id: connection.public_id,
            integration_type: connection.integration_type,
            config,
            sha256sum: connection.sha256sum,
            ttl: connection.ttl,
            created_at: connection.created_at,
            updated_at: connection.updated_at,
        };

        Ok(response)
    }

    /// Delete a vault connection
    pub async fn delete_vault_connection(db: &PgPool, public_id: &str) -> Result<bool, AppError> {
        let rows_affected = ConnectionRepository::delete_vault_connection(db, public_id).await?;
        Ok(rows_affected > 0)
    }
}
