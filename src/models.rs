use crate::errors::AppError;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

// =================================================================
// API Util Structs
// =================================================================
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonPayload<T>(pub T);

impl<T, S> FromRequest<S> for JsonPayload<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(AppError::JsonExtractionError(rejection)),
        }
    }
}

// =================================================================
// API Request/Response Structs
// =================================================================

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateSecretRequest {
    pub name: String,
    pub vault_connection_id: Option<String>,
    pub value: String,
    pub version_tag: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateSecretVersionRequest {
    pub value: String,
    pub version_tag: String,
}

#[derive(Serialize, Debug)]
pub struct SecretResponse {
    pub name: String,
    pub value: String,
    pub version_tag: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateVaultConnectionRequest {
    pub public_id: String,
    pub integration_type: String,
    pub config: String,
    pub ttl: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateVaultConnectionRequest {
    pub config: Option<String>,
    pub ttl: Option<i32>,
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
