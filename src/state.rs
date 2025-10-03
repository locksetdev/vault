use aws_sdk_kms::Client as KmsClient;
use p256::ecdsa::VerifyingKey;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub kms_client: Arc<KmsClient>,
    pub auth_verifying_key: Arc<VerifyingKey>,
}
