use crate::errors::AppError;
use crate::models::DataEncryptionKey;
use sqlx::{PgPool, Postgres, Transaction};

pub struct DekRepository;

impl DekRepository {
    pub async fn get_random_dek(
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<DataEncryptionKey, AppError> {
        let dek: DataEncryptionKey =
            sqlx::query_as("SELECT * FROM data_encryption_keys ORDER BY RANDOM() LIMIT 1")
                .fetch_one(&mut **tx)
                .await?;

        Ok(dek)
    }

    pub async fn create_dek(
        tx: &mut Transaction<'_, Postgres>,
        kek_id: i32,
        encrypted_key: String,
    ) -> Result<DataEncryptionKey, AppError> {
        let new_dek: DataEncryptionKey = sqlx::query_as(
            r#"
            INSERT INTO data_encryption_keys (key_id, kek_id, encrypted_key, algo)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(kek_id)
        .bind(encrypted_key)
        .bind("AES-256-GCM")
        .fetch_one(&mut **tx)
        .await?;

        Ok(new_dek)
    }

    pub async fn get_dek_by_id(pool: &PgPool, id: i32) -> Result<DataEncryptionKey, AppError> {
        let dek: DataEncryptionKey =
            sqlx::query_as("SELECT * FROM data_encryption_keys WHERE id = $1")
                .bind(id)
                .fetch_one(pool)
                .await?;
        Ok(dek)
    }
}
