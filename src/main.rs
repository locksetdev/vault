mod config;
mod crypto;
mod errors;
mod handlers;
mod middleware;
mod models;
mod repositories;
mod routes;
mod services;
mod state;

use crate::config::AppConfig;
use crate::routes::configure_routes;
use crate::state::AppState;
use axum::{Router, middleware as axum_middleware};
use p256::ecdsa::VerifyingKey;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    AppConfig::load().expect("Failed to load application configuration");

    setup_logging()?;
    let config = AppConfig::instance();
    let db_pool = create_db_pool(&config).await?;

    // Load AWS config and create KMS client
    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms_client = aws_sdk_kms::Client::new(&aws_config);
    info!("AWS KMS client created.");

    // Create verifying key from public key
    let public_key_bytes = hex::decode(&config.auth_public_key)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)?;

    // Create shared application state
    let app_state = Arc::new(AppState {
        db: db_pool,
        kms_client: Arc::new(kms_client),
        auth_verifying_key: Arc::new(verifying_key),
    });

    // Define application routes
    let app = configure_routes(Router::new())
        .layer(axum_middleware::from_fn_with_state(
            app_state.clone(),
            middleware::auth::verify_signature,
        ))
        .layer(axum_middleware::from_fn(middleware::logging::log_requests))
        .with_state(app_state);

    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Starting server on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn create_db_pool(config: &AppConfig) -> Result<Pool<Postgres>, Box<dyn Error>> {
    let db_pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;
    info!("Database connection pool created.");
    Ok(db_pool)
}

fn setup_logging() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    Ok(())
}
