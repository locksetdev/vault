use validator::ValidationError;
use zeroize::Zeroizing;

pub fn validate_vault_config(config: &Zeroizing<String>) -> Result<(), ValidationError> {
    if config.len() > 4096 {
        return Err(ValidationError::new("config_too_long"));
    }
    Ok(())
}
