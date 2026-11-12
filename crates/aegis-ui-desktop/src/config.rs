//! Where data lives and how expensive the cryptographic work is.

use aegis_core::pow;
use aegis_core::vault::VaultParams;
use std::path::PathBuf;

/// Everything the engine needs to know about its environment. Nothing in the
/// engine looks at environment variables; tests pass a temporary directory.
#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub vault_params: VaultParams,
    pub pow_bits: u32,
    /// Endpoint pre-filled for new accounts.
    pub default_endpoint: String,
}

impl Config {
    pub fn production(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            vault_params: VaultParams::DESKTOP,
            pow_bits: pow::DEFAULT_BITS,
            default_endpoint: crate::model::DEFAULT_ENDPOINT.to_owned(),
        }
    }
}

/// Default data directory: `%APPDATA%\Aegis`. The only place that reads the environment.
pub fn default_data_dir() -> Result<PathBuf, String> {
    let base = std::env::var_os("APPDATA")
        .ok_or_else(|| "the application data folder is not set".to_owned())?;
    let base = PathBuf::from(base);
    if !base.is_absolute() {
        return Err("the application data folder is not an absolute path".to_owned());
    }
    Ok(base.join("Aegis"))
}
