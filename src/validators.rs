use regex::Regex;
use std::sync::OnceLock;
use validator::ValidationError;
use zeroize::Zeroizing;

pub static PUBLIC_ID_REGEX: OnceLock<Regex> = OnceLock::new();
pub static VERSION_TAG_REGEX: OnceLock<Regex> = OnceLock::new();
pub static SECRET_NAME_REGEX: OnceLock<Regex> = OnceLock::new();

pub fn get_public_id_regex() -> &'static Regex {
    PUBLIC_ID_REGEX
        .get_or_init(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{6,22}[a-zA-Z0-9]$").unwrap())
}

pub fn get_version_tag_regex() -> &'static Regex {
    VERSION_TAG_REGEX
        .get_or_init(|| Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9_.-]*[a-zA-Z0-9])?$").unwrap())
}

pub fn get_secret_name_regex() -> &'static Regex {
    SECRET_NAME_REGEX
        .get_or_init(|| Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$").unwrap())
}

pub fn validate_vault_config(config: &Zeroizing<String>) -> Result<(), ValidationError> {
    if config.len() > 4096 {
        return Err(ValidationError::new("config_too_long"));
    }
    Ok(())
}
