use crate::errors::AppError;
use crate::repositories::{dek::DekRepository, kek::KekRepository};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;

pub struct EncryptedPayload {
    pub dek_id: i32,
    pub encrypted_blob: String,
    pub sha256sum: String,
}

const NONCE_SIZE: usize = 12; // AES-GCM standard nonce size

/// Encrypts a plaintext value using the envelope encryption strategy.
pub async fn encrypt(
    tx: &mut Transaction<'_, Postgres>,
    kms_client: &Arc<KmsClient>,
    plaintext: &[u8],
) -> Result<EncryptedPayload, AppError> {
    let kek = KekRepository::get_random_kek(tx).await?;

    let data_key_response = kms_client
        .generate_data_key()
        .key_id(kek.kms_key)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
        .send()
        .await
        .map_err(|e| AppError::KmsError(format!("Failed to generate data key from KMS: {}", e)))?;

    let plaintext_dek = data_key_response
        .plaintext()
        .ok_or_else(|| AppError::KmsError("KMS did not return a plaintext data key.".to_string()))?
        .as_ref();
    let encrypted_dek_blob = data_key_response.ciphertext_blob().ok_or_else(|| {
        AppError::KmsError("KMS did not return a ciphertext blob for the data key.".to_string())
    })?;

    let cipher = Aes256Gcm::new_from_slice(plaintext_dek)
        .map_err(|e| AppError::CryptoError(format!("Failed to create AES cipher: {}", e)))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted_value = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AppError::CryptoError(format!("Local encryption failed: {}", e)))?;

    let mut combined_encrypted_value = nonce.to_vec();
    combined_encrypted_value.extend_from_slice(&encrypted_value);
    let encrypted_value_hex = hex::encode(combined_encrypted_value);

    let new_dek = DekRepository::create_dek(tx, kek.id, hex::encode(encrypted_dek_blob)).await?;

    Ok(EncryptedPayload {
        dek_id: new_dek.id,
        encrypted_blob: encrypted_value_hex,
        sha256sum: sha256_hash(plaintext),
    })
}

/// Decrypts an encrypted value using the envelope encryption strategy.
pub async fn decrypt(
    pool: &PgPool,
    kms_client: &Arc<KmsClient>,
    dek_id: i32,
    encrypted_value_hex: &str,
) -> Result<Vec<u8>, AppError> {
    let dek = DekRepository::get_dek_by_id(pool, dek_id).await?;
    let kek = KekRepository::get_kek_by_id(pool, dek.kek_id).await?;

    let encrypted_dek_bytes = hex::decode(dek.encrypted_key).map_err(|e| {
        AppError::CryptoError(format!("Failed to decode encrypted DEK from hex: {}", e))
    })?;
    let encrypted_dek_blob = Blob::new(encrypted_dek_bytes);

    let decrypt_response = kms_client
        .decrypt()
        .key_id(kek.kms_key)
        .ciphertext_blob(encrypted_dek_blob)
        .send()
        .await
        .map_err(|e| AppError::KmsError(format!("Failed to decrypt data key with KMS: {}", e)))?;

    let plaintext_dek = decrypt_response
        .plaintext()
        .ok_or_else(|| {
            AppError::KmsError("KMS did not return a plaintext data key on decrypt.".to_string())
        })?
        .as_ref();

    let combined_encrypted_value = hex::decode(encrypted_value_hex).map_err(|e| {
        AppError::CryptoError(format!("Failed to decode encrypted value from hex: {}", e))
    })?;

    if combined_encrypted_value.len() < NONCE_SIZE {
        return Err(AppError::CryptoError(
            "Invalid encrypted data format.".to_string(),
        ));
    }
    let (nonce_bytes, ciphertext) = combined_encrypted_value.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(plaintext_dek).map_err(|e| {
        AppError::CryptoError(format!("Failed to create AES cipher for decryption: {}", e))
    })?;

    let decrypted_value = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AppError::CryptoError(format!("Local decryption failed: {}", e)))?;

    Ok(decrypted_value)
}

pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}
