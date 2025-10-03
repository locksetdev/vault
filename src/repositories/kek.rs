use crate::errors::AppError;
use crate::models::KeyEncryptionKey;
use sqlx::{PgPool, Postgres, Transaction};

pub struct KekRepository;

impl KekRepository {
    pub async fn get_random_kek(
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<KeyEncryptionKey, AppError> {
        let kek: KeyEncryptionKey =
            sqlx::query_as("SELECT * FROM key_encryption_keys ORDER BY RANDOM()")
                .fetch_one(&mut **tx)
                .await?;

        Ok(kek)
    }

    pub async fn get_kek_by_id(pool: &PgPool, id: i32) -> Result<KeyEncryptionKey, AppError> {
        let kek: KeyEncryptionKey =
            sqlx::query_as("SELECT * FROM key_encryption_keys WHERE id = $1")
                .bind(id)
                .fetch_one(pool)
                .await?;
        Ok(kek)
    }
}
