use crate::handlers::connections::ConnectionHandler;
use crate::handlers::secrets::SecretHandler;
use crate::state::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub fn configure_routes(router: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    router
        .route("/v1/secrets", post(SecretHandler::create_secret))
        .route("/v1/secrets/{name}", get(SecretHandler::get_secret))
        .route(
            "/v1/secrets/{name}/versions",
            post(SecretHandler::create_secret_version),
        )
        .route(
            "/v1/secrets/{name}/versions/{tag}",
            get(SecretHandler::get_secret_version),
        )
        .route(
            "/v1/vault-connections",
            post(ConnectionHandler::create_vault_connection),
        )
        .route(
            "/v1/vault-connections/{public_id}",
            get(ConnectionHandler::get_vault_connection)
                .delete(ConnectionHandler::delete_vault_connection),
        )
}
