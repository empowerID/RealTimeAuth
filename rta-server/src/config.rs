// src/config.rs
use config::{Config, ConfigError, File};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenConfig {
    pub max_age_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IdpConfig {
    pub introspection_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IdpProviders {
    pub default: String, // e.g. "azure"
    pub azure: IdpConfig,
    pub okta: IdpConfig,
    pub auth0: IdpConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PdpConfig {
    pub endpoint: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub token: TokenConfig,
    pub redis: RedisConfig,
    pub idp: IdpProviders,
    pub pdp: PdpConfig,
}

impl Settings {
    pub fn new(config_path: &str) -> Result<Self, ConfigError> {
        let s = Config::builder()
            .add_source(File::with_name(config_path))
            .build()?;
        s.try_deserialize()
    }
}
