use crate::services::connections::ConnectionService;
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
use chrono::{Duration, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;

pub struct SecretService;

impl SecretService {
    /// Create a new secret with its first version
    pub async fn create_secret_with_version(
        state: &Arc<AppState>,
        request: CreateSecretRequest,
    ) -> Result<CreateSecretResponse, AppError> {
        let mut tx = state.db.begin().await?;

        let secret = Self::create_secret_record(&mut tx, &state.db, &request).await?;

        let new_version =
            Self::create_new_secret_version(&mut tx, &state.kms_client, &secret, &request).await?;

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

    async fn create_secret_record(
        tx: &mut Transaction<'_, Postgres>,
        db: &PgPool,
        request: &CreateSecretRequest,
    ) -> Result<crate::models::Secret, AppError> {
        // Resolve vault connection ID if provided
        let vault_connection_id = if let Some(public_id) = &request.vault_connection_id {
            Some(
                ConnectionRepository::get_vault_connection_by_public_id(db, public_id)
                    .await?
                    .ok_or_else(|| {
                        AppError::InvalidInput(format!(
                            "Vault connection with public_id '{}' not found.",
                            public_id
                        ))
                    })?
                    .id,
            )
        } else {
            None
        };

        // Create the secret record
        SecretRepository::create_secret(tx, &request.name, vault_connection_id).await
    }

    async fn create_new_secret_version(
        tx: &mut Transaction<'_, Postgres>,
        kms_client: &Arc<KmsClient>,
        secret: &crate::models::Secret,
        request: &CreateSecretRequest,
    ) -> Result<crate::models::SecretVersion, AppError> {
        // Encrypt the secret value
        let encrypted_payload = crypto::encrypt(tx, kms_client, request.value.as_bytes()).await?;

        // Create the first version
        SecretRepository::create_secret_version(
            tx,
            secret.id,
            &request.version_tag,
            &encrypted_payload.sha256sum,
            &encrypted_payload.encrypted_blob,
            encrypted_payload.dek_id,
        )
        .await
    }

    /// Get the current version of a secret by name
    pub async fn get_secret_current_version(
        state: &Arc<AppState>,
        name: &str,
    ) -> Result<SecretResponse, AppError> {
        let mut secret = SecretRepository::get_secret_by_name(&state.db, name)
            .await?
            .ok_or(AppError::NotFoundError)?;

        // If it's a proxied secret, and it's expired or has never been fetched, refresh it
        if let Some(vc_id) = secret.vault_connection_id {
            let should_refresh = secret.expire_at.map_or(true, |ea| Utc::now() > ea);

            if should_refresh {
                return Self::refresh_proxied_secret(state, &mut secret, vc_id).await;
            }
        }

        let current_version_tag = secret.current_version.ok_or(AppError::NotFoundError)?;

        let version =
            SecretRepository::get_secret_version_by_tag(&state.db, secret.id, &current_version_tag)
                .await?
                .ok_or(AppError::NotFoundError)?;

        let decrypted_value = Self::decrypt_secret_value(
            &state.db,
            &state.kms_client,
            &version.encrypted_secret,
            version.dek_id,
        )
        .await?;

        Ok(SecretResponse {
            name: secret.name,
            value: decrypted_value,
            version_tag: current_version_tag,
        })
    }

    async fn refresh_proxied_secret(
        state: &Arc<AppState>,
        secret: &mut crate::models::Secret,
        vc_id: i32,
    ) -> Result<SecretResponse, AppError> {
        let connection = ConnectionService::get_vault_connection_config_by_id(
            &state.db,
            &state.kms_client,
            vc_id,
        )
        .await?;

        let factory = state
            .provider_factories
            .get(&connection.integration_type)
            .ok_or_else(|| {
                AppError::InvalidInput(format!(
                    "Provider '{}' not found",
                    connection.integration_type
                ))
            })?;

        let provider = factory.create(connection.config).await?;
        let provider_secret = provider.get_secret(&secret.name).await?;

        let mut tx = state.db.begin().await?;

        let encrypted_payload =
            crypto::encrypt(&mut tx, &state.kms_client, provider_secret.value.as_bytes()).await?;

        let new_version_tag = provider_secret.version.unwrap_or_else(|| "latest".into());

        SecretRepository::create_secret_version(
            &mut tx,
            secret.id,
            &new_version_tag,
            &encrypted_payload.sha256sum,
            &encrypted_payload.encrypted_blob,
            encrypted_payload.dek_id,
        )
        .await?;

        let previous_version = secret.current_version.take();
        let expire_at = Utc::now() + Duration::seconds(connection.ttl.unwrap_or(3600) as i64);

        SecretRepository::update_secret_proxied(
            &mut tx,
            secret.id,
            &new_version_tag,
            previous_version,
            expire_at,
        )
        .await?;

        tx.commit().await?;

        Ok(SecretResponse {
            name: secret.name.clone(),
            value: provider_secret.value.to_string(),
            version_tag: new_version_tag,
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
