use crate::errors::AppError;
use crate::validators::{
    get_public_id_regex, get_secret_name_regex, get_version_tag_regex, validate_vault_config,
};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use validator::Validate;
use zeroize::Zeroizing;

// =================================================================
// API Util Structs
// =================================================================
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonPayload<T>(pub T);

impl<T, S> FromRequest<S> for JsonPayload<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => {
                value.validate()?;
                Ok(Self(value))
            }
            Err(rejection) => Err(AppError::JsonExtractionError(rejection)),
        }
    }
}

pub struct VaultConnectionConfig {
    pub integration_type: String,
    pub config: Zeroizing<String>,
    pub ttl: Option<i32>,
}

// =================================================================
// API Request/Response Structs
// =================================================================

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct CreateSecretRequest {
    #[validate(regex(
        path = "get_secret_name_regex()",
        message = "Invalid secret name format"
    ))]
    #[validate(length(
        min = 1,
        max = 255,
        message = "Secret name must be between 1 and 255 characters"
    ))]
    pub name: String,
    #[validate(regex(
        path = "get_public_id_regex()",
        message = "Invalid vault connection ID format"
    ))]
    pub vault_connection_id: Option<String>,
    #[validate(length(min = 1, message = "Secret value cannot be empty"))]
    pub value: String,
    #[validate(regex(
        path = "get_version_tag_regex()",
        message = "Invalid version tag format"
    ))]
    #[validate(length(
        min = 1,
        max = 20,
        message = "Version tag must be between 1 and 20 characters"
    ))]
    pub version_tag: String,
}

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct CreateSecretVersionRequest {
    #[validate(length(min = 1, message = "Secret value cannot be empty"))]
    pub value: String,
    #[validate(regex(
        path = "get_version_tag_regex()",
        message = "Invalid version tag format"
    ))]
    #[validate(length(
        min = 1,
        max = 20,
        message = "Version tag must be between 1 and 20 characters"
    ))]
    pub version_tag: String,
}

#[derive(Serialize, Debug)]
pub struct SecretResponse {
    pub name: String,
    pub value: String,
    pub version_tag: String,
}

#[derive(Serialize, Debug)]
pub struct CreateSecretResponse {
    pub name: String,
    pub version_tag: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Debug)]
pub struct CreateSecretVersionResponse {
    pub name: String,
    pub version_tag: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct CreateVaultConnectionRequest {
    #[validate(regex(
        path = "get_public_id_regex()",
        message = "Public ID must be 8-24 characters, alphanumeric with _ or -, and start/end with alphanumeric."
    ))]
    pub public_id: String,
    #[validate(length(min = 1, message = "Integration type cannot be empty"))]
    pub integration_type: String,
    #[validate(custom(function = "validate_vault_config"))]
    pub config: Zeroizing<String>,
    pub ttl: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateVaultConnectionResponse {
    pub public_id: String,
    pub integration_type: String,
    pub sha256sum: String,
    pub ttl: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct UpdateVaultConnectionRequest {
    #[validate(custom(function = "validate_vault_config"))]
    pub config: Option<Zeroizing<String>>,
    pub ttl: Option<i32>,
    #[validate(length(min = 1))]
    pub integration_type: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateVaultConnectionResponse {
    pub public_id: String,
    pub integration_type: String,
    pub sha256sum: String,
    pub ttl: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Debug)]
pub struct VaultConnectionResponse {
    pub public_id: String,
    pub integration_type: String,
    pub config: String,
    pub sha256sum: String,
    pub ttl: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// =================================================================
// Database Model Structs
// =================================================================

#[derive(FromRow, Debug, Clone)]
pub struct KeyEncryptionKey {
    pub id: i32,
    pub kms_key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow, Debug)]
pub struct DataEncryptionKey {
    pub id: i32,
    pub key_id: String,
    pub kek_id: i32,
    pub encrypted_key: String,
    pub algo: String,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow, Debug)]
pub struct VaultConnection {
    pub id: i32,
    pub public_id: String,
    pub integration_type: String,
    pub sha256sum: String,
    pub encrypted_config: String,
    pub dek_id: i32,
    pub ttl: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow, Debug)]
pub struct Secret {
    pub id: i32,
    pub name: String,
    pub vault_connection_id: Option<i32>,
    pub current_version: Option<String>,
    pub previous_version: Option<String>,
    pub expire_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow, Debug)]
pub struct SecretVersion {
    pub id: i32,
    pub secret_id: i32,
    pub version_tag: String,
    pub sha256sum: Option<String>,
    pub encrypted_secret: String,
    pub dek_id: i32,
    pub deleted: bool,
    pub expire_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}
