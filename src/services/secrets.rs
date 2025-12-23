use crate::regex::get_ending_number_regex;
use crate::services::connections::ConnectionService;
use crate::{
    crypto,
    errors::AppError,
    models::{
        CreateSecretRequest, CreateSecretResponse, CreateSecretVersionRequest,
        CreateSecretVersionResponse, Secret, SecretResponse,
    },
    repositories::secrets::SecretRepository,
    state::AppState,
};
use aws_sdk_kms::Client as KmsClient;
use chrono::{Duration, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use tracing::info;
use zeroize::Zeroizing;

pub struct SecretService;

const DEFAULT_TTL_SECONDS: i32 = 3600; // 1 hour

impl SecretService {
    /// Create a new secret with its first version
    pub async fn create_secret_with_version(
        state: &Arc<AppState>,
        request: CreateSecretRequest,
    ) -> Result<CreateSecretResponse, AppError> {
        let mut tx = state.db.begin().await?;

        let (secret_value, vault_connection_id) = if let Some(public_id) = &request.vault_connection
        {
            let (value, connection_id) =
                Self::get_secret_value_from_provider(state, &request.name, &public_id).await?;
            (value, Some(connection_id))
        } else {
            (request.value.unwrap_or_default(), None)
        };

        let encrypted_payload =
            crypto::encrypt(&mut tx, &state.kms_client, secret_value.as_bytes()).await?;

        let secret = SecretRepository::create_secret(
            &mut tx,
            &request.name,
            vault_connection_id,
            &request.version_tag,
        )
        .await?;

        let new_version = SecretRepository::create_secret_version(
            &mut tx,
            secret.id,
            &request.version_tag,
            &encrypted_payload.sha256sum,
            &encrypted_payload.encrypted_blob,
            encrypted_payload.dek_id,
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
        state: &Arc<AppState>,
        name: &str,
    ) -> Result<SecretResponse, AppError> {
        let secret = SecretRepository::get_secret_by_name(&state.db, name)
            .await?
            .ok_or(AppError::NotFoundError)?;

        if let Some(vc_id) = secret.vault_connection_id {
            // If it's a proxied secret, and it's expired, refresh it
            let should_refresh = secret.expire_at.map_or(true, |ea| Utc::now() > ea);

            if should_refresh {
                return Self::refresh_proxied_secret(state, secret, vc_id).await;
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

    async fn refresh_proxied_secret(
        state: &Arc<AppState>,
        secret: Secret,
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

        let version_tag = Self::update_secret_from_provider(
            &mut tx,
            state,
            &secret,
            provider_secret.value.as_bytes(),
            connection.ttl,
        )
        .await?;

        tx.commit().await?;

        Ok(SecretResponse {
            name: secret.name.clone(),
            value: provider_secret.value,
            version_tag,
        })
    }

    async fn update_secret_from_provider(
        tx: &mut Transaction<'_, Postgres>,
        state: &Arc<AppState>,
        secret: &Secret,
        new_value: &[u8],
        ttl: Option<i32>,
    ) -> Result<String, AppError> {
        let expire_at = Utc::now() + Duration::seconds(ttl.unwrap_or(DEFAULT_TTL_SECONDS) as i64);
        let new_sha256sum = crypto::sha256_hash(new_value);

        if let Some(current_version_tag) = &secret.current_version {
            let current_version = SecretRepository::get_secret_version_by_tag(
                &mut **tx,
                secret.id,
                current_version_tag,
            )
            .await?
            .ok_or(AppError::NotFoundError)?;

            // If the hash is the same, we just update the expiry and we're done.
            if Some(new_sha256sum) == current_version.sha256sum {
                SecretRepository::update_secret_version_expiry(tx, current_version.id, expire_at)
                    .await?;
                SecretRepository::update_secret_expiry(tx, secret.id, expire_at).await?;

                return Ok(current_version_tag.clone());
            }
        }

        let new_version_tag = Self::get_next_version_tag(
            &secret
                .current_version
                .clone()
                .unwrap_or_else(|| "v".to_string()),
        );

        let encrypted_payload = crypto::encrypt(tx, &state.kms_client, new_value).await?;

        SecretRepository::create_secret_version(
            tx,
            secret.id,
            &new_version_tag,
            &encrypted_payload.sha256sum,
            &encrypted_payload.encrypted_blob,
            encrypted_payload.dek_id,
        )
        .await?;

        SecretRepository::update_secret_proxied(
            tx,
            secret.id,
            &new_version_tag,
            secret.current_version.clone(),
            expire_at,
        )
        .await?;

        Ok(new_version_tag)
    }

    async fn get_secret_value_from_provider(
        state: &Arc<AppState>,
        name: &str,
        vault_connection_public_id: &str,
    ) -> Result<(Zeroizing<String>, i32), AppError> {
        let connection = ConnectionService::get_vault_connection(
            &state.db,
            &state.kms_client,
            vault_connection_public_id,
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

        info!("fetching provider secret");

        let provider = factory.create(connection.config).await?;
        let provider_secret = provider.get_secret(name).await?;

        Ok((provider_secret.value, connection.id))
    }

    /// Helper method to decrypt secret values
    async fn decrypt_secret_value(
        db: &PgPool,
        kms_client: &Arc<KmsClient>,
        encrypted_secret: &str,
        dek_id: i32,
    ) -> Result<Zeroizing<String>, AppError> {
        let decrypted_value_bytes =
            crypto::decrypt(db, kms_client, dek_id, encrypted_secret).await?;
        Ok(Zeroizing::new(
            String::from_utf8(decrypted_value_bytes).map_err(|e| {
                AppError::CryptoError(format!(
                    "Failed to convert decrypted bytes to string: {}",
                    e
                ))
            })?,
        ))
    }

    fn get_next_version_tag(current_tag: &str) -> String {
        if let Some(ending_number) = get_ending_number_regex()
            .captures(current_tag)
            .and_then(|caps| caps.get(0))
        {
            if let Ok(num) = ending_number.as_str().parse::<u32>() {
                let prefix = &current_tag[..ending_number.start()];
                format!("{}{}", prefix, num + 1)
            } else {
                format!("{}-1", current_tag)
            }
        } else {
            format!("{}-1", current_tag)
        }
    }
}
