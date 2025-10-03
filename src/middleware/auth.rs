use crate::{errors::AppError, state::AppState};
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::Response,
};
use bytes::Bytes;
use ecdsa::{Signature, signature::Verifier};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const MAX_BODY_SIZE: usize = 256 * 1024; // 256kb
const MAX_TIMESTAMP_DIFF_MS: i64 = 5000; // 5 seconds

pub async fn verify_signature(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let (parts, body) = req.into_parts();

    let signature_hex = if let Some(signature) = parts.headers.get("X-Signature") {
        signature
            .to_str()
            .map_err(|_| AppError::InvalidInput("Invalid X-Signature header".to_string()))?
    } else {
        return Err(AppError::Unauthorized);
    };

    let timestamp_str = if let Some(timestamp) = parts.headers.get("X-Timestamp") {
        timestamp
            .to_str()
            .map_err(|_| AppError::InvalidInput("Invalid X-Timestamp header".to_string()))?
    } else {
        return Err(AppError::Unauthorized);
    };

    let timestamp_ms = timestamp_str
        .parse::<i64>()
        .map_err(|_| AppError::InvalidInput("Invalid X-Timestamp format".to_string()))?;

    let now_ms = chrono::Utc::now().timestamp_millis();

    if (now_ms - timestamp_ms).abs() > MAX_TIMESTAMP_DIFF_MS {
        return Err(AppError::InvalidInput(
            "Timestamp is outside of the recv window".to_string(),
        ));
    }

    let signature_bytes = hex::decode(signature_hex)
        .map_err(|_| AppError::InvalidInput("Invalid signature format".to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AppError::InvalidInput("Invalid signature".to_string()))?;

    let body_bytes = if parts.method == Method::GET || parts.method == Method::DELETE {
        Bytes::new()
    } else {
        to_bytes(body, MAX_BODY_SIZE)
            .await
            .map_err(|_| AppError::InvalidInput("Request body too large".to_string()))?
    };

    let new_line = "\n";

    let mut hasher = Sha256::new();
    hasher.update(timestamp_str.as_bytes());
    hasher.update(new_line.as_bytes());
    hasher.update(parts.uri.path().as_bytes());
    hasher.update(new_line.as_bytes());
    hasher.update(&body_bytes);
    let digest = hasher.finalize();

    state
        .auth_verifying_key
        .verify(&digest, &signature)
        .map_err(|_| AppError::Unauthorized)?;

    let req = Request::from_parts(parts, Body::from(body_bytes));

    Ok(next.run(req).await)
}
