use std::fs;

use serde::Deserialize;
use tokio::runtime::Handle;

use crate::{RusticaAgentLibraryError, RusticaServer};

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub ca_pem: String,
    pub mtls_cert: String,
    pub mtls_key: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Options {
    pub principals: Option<Vec<String>>,
    pub hosts: Option<Vec<String>>,
    pub kind: Option<String>,
    pub duration: Option<u64>,
    pub authority: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Version {
    version: u64,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub servers: Vec<ServerConfig>,
    pub slot: Option<String>,
    pub key: Option<String>,
    pub options: Option<Options>,
    pub socket: Option<String>,
}

impl Config {
    pub fn parse_servers(&self, handle: Handle) -> Vec<RusticaServer> {
        self.servers
            .iter()
            .map(|x| {
                RusticaServer::new(
                    x.address.clone(),
                    x.ca_pem.clone(),
                    x.mtls_cert.clone(),
                    x.mtls_key.clone(),
                    handle.clone(),
                )
            })
            .collect()
    }
}

/// Parse a RusticaAgent configuration from a path
pub fn parse_config_path(path: &str) -> Result<Config, RusticaAgentLibraryError> {
    let config = fs::read_to_string(path)
        .map_err(|x| RusticaAgentLibraryError::CouldNotReadConfigurationFile(x.to_string()))?;

    parse_config(&config)
}

/// Parse a RusticaAgent configuration from a string
pub fn parse_config(config: &str) -> Result<Config, RusticaAgentLibraryError> {
    match toml::from_str(&config) {
        Err(_) => parse_v1_config(config),
        Ok(Version { version: 2 }) => parse_v2_config(config),
        Ok(Version { version: x }) => {
            return Err(RusticaAgentLibraryError::UnknownConfigurationVersion(x))
        }
    }
}

/// Parses the original format of the RusticaAgent configuration. There is no
/// version field in this format so we will always try this if that is missing.
fn parse_v1_config(config: &str) -> Result<Config, RusticaAgentLibraryError> {
    #[derive(Debug, Deserialize)]
    pub struct ConfigV1 {
        pub server: String,
        pub ca_pem: String,
        pub mtls_cert: String,
        pub mtls_key: String,
        pub slot: Option<String>,
        pub key: Option<String>,
        pub options: Option<Options>,
        pub socket: Option<String>,
    }

    let config_v1: ConfigV1 = match toml::from_str(&config) {
        Ok(t) => t,
        Err(e) => return Err(RusticaAgentLibraryError::BadConfiguration(e.to_string())),
    };

    let server_config = ServerConfig {
        address: config_v1.server,
        ca_pem: config_v1.ca_pem,
        mtls_cert: config_v1.mtls_cert,
        mtls_key: config_v1.mtls_key,
    };

    Ok(Config {
        servers: vec![server_config],
        slot: config_v1.slot,
        key: config_v1.key,
        options: config_v1.options,
        socket: config_v1.socket,
    })
}

fn parse_v2_config(config: &str) -> Result<Config, RusticaAgentLibraryError> {
    match toml::from_str(&config) {
        Ok(t) => Ok(t),
        Err(e) => return Err(RusticaAgentLibraryError::BadConfiguration(e.to_string())),
    }
}