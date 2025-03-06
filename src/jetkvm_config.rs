use anyhow::{Context, Result};
use serde::Deserialize;
use serde::Serialize;
use std::env;
use std::fs;
use std::path::Path;


fn default_cert_path() -> String {
    "cert.pem".to_string()
}


#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JetKvmConfig {
    pub host: String,
    pub port: String,
    pub api: String,
    pub password: String,
    #[serde(default = "default_cert_path")]
    pub ca_cert_path: String,
    #[serde(default)] // Ensures `no_auto_logout` defaults to false if missing
    pub no_auto_logout: bool,
}

impl Default for JetKvmConfig {
    fn default() -> Self {
        Self {
            host: "".into(),
            port: "80".into(),
            api: "/webrtc/session".into(),
            password: "".into(),
            ca_cert_path: "cert.pem".into(),
            no_auto_logout: false,
        }
    }
}

impl JetKvmConfig {
    pub fn load() -> Result<Self> {
        // Define config file locations based on OS
        let mut config_paths = vec![
            "config.toml".to_string(), // First: Check local directory
        ];

        // Check Cargo project root (development mode)
        if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
            config_paths.push(format!("{}/config.toml", manifest_dir));
        }

        // System-wide locations
        #[cfg(target_os = "linux")]
        config_paths.push("/etc/jetkvm_control/config.toml".to_string());

        #[cfg(target_os = "macos")]
        config_paths.push("/etc/jetkvm_control/config.toml".to_string());

        #[cfg(target_os = "windows")]
        if let Ok(appdata) = env::var("APPDATA") {
            config_paths.push(format!("{}/jetkvm_control/config.toml", appdata));
        }

        // Search for the first available config file
        let config_path = config_paths
            .iter()
            .find(|path| Path::new(path).exists())
            .ok_or_else(|| anyhow::anyhow!("No config.toml found in any location"))?;

        println!("✅ Loaded config from: {}", config_path);

        // Read and deserialize the configuration file
        let config_contents =
            fs::read_to_string(config_path).context("Failed to read config file")?;
        let config: JetKvmConfig =
            toml::from_str(&config_contents).context("Failed to parse config.toml")?;

        Ok(config)
    }

    /// Returns the full URL to use for the SDP exchange.
    pub fn session_url(&self) -> String {
        format!("http://{}:{}{}", self.host, self.port, self.api)
    }
}
