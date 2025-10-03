use crate::errors::AppError;
use crate::models::{CreateVaultConnectionRequest, VaultConnection};
use sqlx::{Postgres, Transaction};

pub struct ConnectionRepository;

impl ConnectionRepository {
    pub async fn create_vault_connection(
        tx: &mut Transaction<'_, Postgres>,
        payload: &CreateVaultConnectionRequest,
        sha256sum: &str,
        encrypted_config: &str,
        dek_id: i32,
    ) -> Result<VaultConnection, AppError> {
        let new_connection: VaultConnection = sqlx::query_as(
            r#"
            INSERT INTO vault_connections (public_id, integration_type, sha256sum, encrypted_config, dek_id, ttl)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
            .bind(&payload.public_id)
            .bind(&payload.integration_type)
            .bind(sha256sum)
            .bind(encrypted_config)
            .bind(dek_id)
            .bind(payload.ttl)
            .fetch_one(&mut **tx)
            .await
            .map_err(|db_err| AppError::from(db_err))?;

        Ok(new_connection)
    }

    pub async fn get_vault_connection_by_public_id(
        db: &sqlx::PgPool,
        public_id: &str,
    ) -> Result<Option<VaultConnection>, AppError> {
        let connection = sqlx::query_as("SELECT * FROM vault_connections WHERE public_id = $1")
            .bind(public_id)
            .fetch_optional(db)
            .await?;
        Ok(connection)
    }

    pub async fn update_vault_connection(
        tx: &mut Transaction<'_, Postgres>,
        public_id: &str,
        encrypted_config: Option<&str>,
        sha256sum: Option<&str>,
        dek_id: Option<i32>,
        ttl: Option<i32>,
        integration_type: Option<&str>,
    ) -> Result<VaultConnection, AppError> {
        let updated_connection = sqlx::query_as(
            r#"
            UPDATE vault_connections
            SET
                encrypted_config = COALESCE($1, encrypted_config),
                sha256sum = COALESCE($2, sha256sum),
                dek_id = COALESCE($3, dek_id),
                ttl = $4,
                integration_type = COALESCE($5, integration_type)
            WHERE public_id = $6
            RETURNING *
            "#,
        )
        .bind(encrypted_config)
        .bind(sha256sum)
        .bind(dek_id)
        .bind(ttl)
        .bind(integration_type)
        .bind(public_id)
        .fetch_one(&mut **tx)
        .await?;

        Ok(updated_connection)
    }

    pub async fn delete_vault_connection(
        db: &sqlx::PgPool,
        public_id: &str,
    ) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM vault_connections WHERE public_id = $1")
            .bind(public_id)
            .execute(db)
            .await?;
        Ok(result.rows_affected())
    }
}
