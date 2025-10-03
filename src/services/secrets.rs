use crate::{
    crypto,
    errors::AppError,
    models::{
        CreateSecretRequest, CreateSecretResponse, CreateSecretVersionRequest,
        CreateSecretVersionResponse, SecretResponse,
    },
    repositories::{connections::ConnectionRepository, secrets::SecretRepository},
    state::AppState,
};
use aws_sdk_kms::Client as KmsClient;
use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;

pub struct SecretService;

impl SecretService {
    /// Create a new secret with its first version
    pub async fn create_secret_with_version(
        state: &Arc<AppState>,
        request: CreateSecretRequest,
    ) -> Result<CreateSecretResponse, AppError> {
        let mut tx = state.db.begin().await?;

        // Resolve vault connection ID if provided
        let vault_connection_id = if let Some(public_id) = &request.vault_connection_id {
            let connection =
                ConnectionRepository::get_vault_connection_by_public_id(&state.db, public_id)
                    .await?
                    .ok_or_else(|| {
                        AppError::InvalidInput(format!(
                            "Vault connection with public_id '{}' not found.",
                            public_id
                        ))
                    })?;
            Some(connection.id)
        } else {
            None
        };

        // Create the secret record
        let secret =
            SecretRepository::create_secret(&mut tx, &request.name, vault_connection_id).await?;

        // Encrypt the secret value
        let encrypted_payload =
            crypto::encrypt(&mut tx, &state.kms_client, request.value.as_bytes()).await?;

        // Create the first version
        let new_version = SecretRepository::create_secret_version(
            &mut tx,
            secret.id,
            &request.version_tag,
            &encrypted_payload.sha256sum,
            &encrypted_payload.encrypted_blob,
            encrypted_payload.dek_id,
        )
        .await?;

        // Update the secret to set the current version
        SecretRepository::update_secret_versions(
            &mut tx,
            secret.id,
            &request.version_tag,
            None, // No previous version for the first version
        )
        .await?;

        tx.commit().await?;
        Ok(CreateSecretResponse {
            name: secret.name,
            version_tag: new_version.version_tag,
            created_at: new_version.created_at,
        })
    }

    /// Get the current version of a secret by name
    pub async fn get_secret_current_version(
        db: &PgPool,
        kms_client: &Arc<KmsClient>,
        name: &str,
    ) -> Result<SecretResponse, AppError> {
        let mut secret = SecretRepository::get_secret_by_name(db, name)
            .await?
            .ok_or(AppError::NotFoundError)?;

        // If it's a proxied secret, and it's expired, refresh it
        if let Some(_vc_id) = secret.vault_connection_id {
            if let Some(expire_at) = secret.expire_at {
                if Utc::now() > expire_at {
                    // TODO: Implement third-party client logic here.
                    return Err(AppError::CryptoError(
                        "Proxied secret has expired and refresh logic is not implemented."
                            .to_string(),
                    ));
                }
            }
        }

        let current_version_tag = secret
            .current_version
            .take()
            .ok_or(AppError::NotFoundError)?;

        let version =
            SecretRepository::get_secret_version_by_tag(db, secret.id, &current_version_tag)
                .await?
                .ok_or(AppError::NotFoundError)?;

        let decrypted_value =
            Self::decrypt_secret_value(db, kms_client, &version.encrypted_secret, version.dek_id)
                .await?;

        Ok(SecretResponse {
            name: secret.name,
            value: decrypted_value,
            version_tag: current_version_tag,
        })
    }

    /// Create a new version for an existing secret
    pub async fn create_secret_version(
        state: &Arc<AppState>,
        name: &str,
        request: CreateSecretVersionRequest,
    ) -> Result<CreateSecretVersionResponse, AppError> {
        let mut tx = state.db.begin().await?;

        let mut secret = SecretRepository::get_secret_by_name_for_update(&mut tx, name)
            .await?
            .ok_or(AppError::NotFoundError)?;

        // This operation is forbidden for proxied secrets
        if secret.vault_connection_id.is_some() {
            return Err(AppError::MethodNotAllowed);
        }

        // Encrypt the secret value
        let encrypted_payload =
            crypto::encrypt(&mut tx, &state.kms_client, request.value.as_bytes()).await?;

        // Insert the new version
        let new_version = SecretRepository::create_secret_version(
            &mut tx,
            secret.id,
            &request.version_tag,
            &encrypted_payload.sha256sum,
            &encrypted_payload.encrypted_blob,
            encrypted_payload.dek_id,
        )
        .await?;

        // Update the parent secret record
        let previous_version = secret.current_version.take();
        SecretRepository::update_secret_versions(
            &mut tx,
            secret.id,
            &request.version_tag,
            previous_version,
        )
        .await?;

        tx.commit().await?;
        Ok(CreateSecretVersionResponse {
            name: secret.name,
            version_tag: new_version.version_tag,
            created_at: new_version.created_at,
        })
    }

    /// Get a specific version of a secret
    pub async fn get_secret_version(
        db: &PgPool,
        kms_client: &Arc<KmsClient>,
        name: &str,
        tag: &str,
    ) -> Result<SecretResponse, AppError> {
        let secret = SecretRepository::get_secret_by_name(db, name)
            .await?
            .ok_or(AppError::NotFoundError)?;

        let version = SecretRepository::get_secret_version_by_tag(db, secret.id, tag)
            .await?
            .ok_or(AppError::NotFoundError)?;

        let decrypted_value =
            Self::decrypt_secret_value(db, kms_client, &version.encrypted_secret, version.dek_id)
                .await?;

        Ok(SecretResponse {
            name: secret.name,
            value: decrypted_value,
            version_tag: tag.to_string(),
        })
    }

    /// Helper method to decrypt secret values
    async fn decrypt_secret_value(
        db: &PgPool,
        kms_client: &Arc<KmsClient>,
        encrypted_secret: &str,
        dek_id: i32,
    ) -> Result<String, AppError> {
        let decrypted_value_bytes =
            crypto::decrypt(db, kms_client, dek_id, encrypted_secret).await?;
        String::from_utf8(decrypted_value_bytes).map_err(|e| {
            AppError::CryptoError(format!(
                "Failed to convert decrypted bytes to string: {}",
                e
            ))
        })
    }
}
