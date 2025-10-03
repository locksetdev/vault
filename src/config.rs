use std::env;
use std::sync::OnceLock;

static APP_CONFIG: OnceLock<AppConfig> = OnceLock::new();

#[derive(Debug)]
pub struct AppConfig {
    pub database_url: String,
    pub auth_public_key: String,
    pub port: u16,
}

impl AppConfig {
    pub fn load() -> Result<(), String> {
        let database_url = env::var("DB_URI").map_err(|_| "DB_URI must be set".to_string())?;
        let auth_public_key =
            env::var("AUTH_PUBLIC_KEY").map_err(|_| "AUTH_PUBLIC_KEY must be set".to_string())?;
        let port = env::var("PORT")
            .map_err(|_| "PORT must be set".to_string())?
            .parse::<u16>()
            .map_err(|_| "PORT must be a valid u16".to_string())?;

        let config = AppConfig {
            database_url,
            auth_public_key,
            port,
        };

        if APP_CONFIG.set(config).is_err() {
            return Err("Configuration has already been loaded".to_string());
        }

        Ok(())
    }

    pub fn instance() -> &'static AppConfig {
        APP_CONFIG.get().expect("Configuration has not been loaded")
    }
}
