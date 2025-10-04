use aws_sdk_kms::Client as KmsClient;
use lockset_vault_provider::VaultProviderFactory;
use p256::ecdsa::VerifyingKey;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub kms_client: Arc<KmsClient>,
    pub auth_verifying_key: Arc<VerifyingKey>,
    pub provider_factories: Arc<HashMap<String, Box<dyn VaultProviderFactory + Send + Sync>>>,
}
