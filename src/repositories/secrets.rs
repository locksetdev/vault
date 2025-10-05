use crate::errors::AppError;
use crate::models::{Secret, SecretVersion};
use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, Postgres, Transaction};

pub struct SecretRepository;

impl SecretRepository {
    pub async fn create_secret(
        tx: &mut Transaction<'_, Postgres>,
        name: &str,
        vault_connection_id: Option<i32>,
        version_tag: &str,
    ) -> Result<Secret, AppError> {
        let secret = sqlx::query_as(
            r#"
            INSERT INTO secrets (name, vault_connection_id, current_version)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(name)
        .bind(vault_connection_id)
        .bind(version_tag)
        .fetch_one(&mut **tx)
        .await
        .map_err(|db_err| AppError::from(db_err))?;
        Ok(secret)
    }

    pub async fn get_secret_by_name(
        db: &sqlx::PgPool,
        name: &str,
    ) -> Result<Option<Secret>, AppError> {
        let secret = sqlx::query_as("SELECT * FROM secrets WHERE name = $1")
            .bind(name)
            .fetch_optional(db)
            .await?;
        Ok(secret)
    }

    pub async fn get_secret_by_name_for_update(
        tx: &mut Transaction<'_, Postgres>,
        name: &str,
    ) -> Result<Option<Secret>, AppError> {
        let secret = sqlx::query_as("SELECT * FROM secrets WHERE name = $1 FOR UPDATE")
            .bind(name)
            .fetch_optional(&mut **tx)
            .await?;
        Ok(secret)
    }

    pub async fn create_secret_version(
        tx: &mut Transaction<'_, Postgres>,
        secret_id: i32,
        version_tag: &str,
        sha256sum: &str,
        encrypted_secret: &str,
        dek_id: i32,
    ) -> Result<SecretVersion, AppError> {
        let version = sqlx::query_as(
            r#"
            INSERT INTO secret_versions (secret_id, version_tag, sha256sum, encrypted_secret, dek_id)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(secret_id)
        .bind(version_tag)
        .bind(sha256sum)
        .bind(encrypted_secret)
        .bind(dek_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|db_err| AppError::from(db_err))?;
        Ok(version)
    }

    pub async fn get_secret_version_by_tag<'e, E>(
        executor: E,
        secret_id: i32,
        tag: &str,
    ) -> Result<Option<SecretVersion>, AppError>
    where
        E: PgExecutor<'e>,
    {
        let version = sqlx::query_as(
            "SELECT * FROM secret_versions WHERE secret_id = $1 AND version_tag = $2",
        )
        .bind(secret_id)
        .bind(tag)
        .fetch_optional(executor)
        .await?;
        Ok(version)
    }

    pub async fn update_secret_versions(
        tx: &mut Transaction<'_, Postgres>,
        secret_id: i32,
        current_version: &str,
        previous_version: Option<String>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE secrets
            SET current_version = $1, previous_version = $2, updated_at = $3
            WHERE id = $4
            "#,
        )
        .bind(current_version)
        .bind(previous_version)
        .bind(Utc::now())
        .bind(secret_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn update_secret_proxied(
        tx: &mut Transaction<'_, Postgres>,
        secret_id: i32,
        current_version: &str,
        previous_version: Option<String>,
        expire_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE secrets
            SET current_version = $1, previous_version = $2, expire_at = $3, updated_at = $4
            WHERE id = $5
            "#,
        )
        .bind(current_version)
        .bind(previous_version)
        .bind(expire_at)
        .bind(Utc::now())
        .bind(secret_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn update_secret_version_expiry(
        tx: &mut Transaction<'_, Postgres>,
        version_id: i32,
        expire_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE secret_versions
            SET expire_at = $1, updated_at = $2
            WHERE id = $3
            "#,
        )
        .bind(expire_at)
        .bind(Utc::now())
        .bind(version_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn update_secret_expiry(
        tx: &mut Transaction<'_, Postgres>,
        secret_id: i32,
        expire_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE secrets
            SET expire_at = $1, updated_at = $2
            WHERE id = $3
            "#,
        )
        .bind(expire_at)
        .bind(Utc::now())
        .bind(secret_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}
