use std::path::PathBuf;
use std::time::Duration;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Timeouts {
    pub pake: Option<u64>,
    pub discovery: Option<u64>,
    pub block_transfer: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub default_relay: Option<String>,
    pub default_download_dir: Option<String>,
    pub timeouts: Option<Timeouts>,
}

#[derive(Debug, Clone)]
pub struct ResolvedTimeouts {
    pub pake: Duration,
    pub discovery: Duration,
    pub block_transfer: Duration,
}

impl Default for ResolvedTimeouts {
    fn default() -> Self {
        Self {
            pake: Duration::from_secs(15),
            discovery: Duration::from_secs(20),
            block_transfer: Duration::from_secs(30),
        }
    }
}

impl Config {
    /// Load config from default path (~/.config/wisp/config.toml)
    pub fn load() -> Result<Self> {
        let path = Self::default_path().context("getting default config path")?;
        if path.exists() {
            let toml_str = std::fs::read_to_string(&path)
                .with_context(|| format!("reading config file at {}", path.display()))?;
            let config: Config = toml::from_str(&toml_str)
                .with_context(|| format!("parsing config file at {}", path.display()))?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }

    /// Default configuration path
    pub fn default_path() -> Result<PathBuf> {
        dirs::config_dir()
            .map(|d| d.join("wisp").join("config.toml"))
            .context("could not determine user configuration directory")
    }

    /// Resolve WAN relay URL using precedence rule: CLI > Env > Config File > Default (None)
    pub fn resolve_relay(&self, cli_val: Option<&str>, env_val: Option<&str>) -> Option<String> {
        if let Some(c) = cli_val {
            return Some(c.to_string());
        }
        if let Some(e) = env_val {
            return Some(e.to_string());
        }
        self.default_relay.clone()
    }

    /// Resolve download destination directory using precedence rule: CLI > Config File > Current Dir
    pub fn resolve_download_dir(&self, cli_val: Option<PathBuf>) -> PathBuf {
        if let Some(c) = cli_val {
            return c;
        }
        if let Some(ref d) = self.default_download_dir {
            // Expand home directory if it starts with ~
            let path_str = if d.starts_with("~/") || d == "~" {
                if let Some(home) = dirs::home_dir() {
                    if d == "~" {
                        home.to_string_lossy().to_string()
                    } else {
                        home.join(&d[2..]).to_string_lossy().to_string()
                    }
                } else {
                    d.clone()
                }
            } else {
                d.clone()
            };
            return PathBuf::from(path_str);
        }
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    /// Resolve timeouts using precedence rule: Config File > Default
    pub fn resolve_timeouts(&self) -> ResolvedTimeouts {
        let (p, d, b) = if let Some(ref t) = self.timeouts {
            (
                t.pake.unwrap_or(15),
                t.discovery.unwrap_or(20),
                t.block_transfer.unwrap_or(30),
            )
        } else {
            (15, 20, 30)
        };
        ResolvedTimeouts {
            pake: Duration::from_secs(p),
            discovery: Duration::from_secs(d),
            block_transfer: Duration::from_secs(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_resolution() {
        // No config file, no env, no CLI. Should yield hardcoded defaults.
        let config = Config::default();
        
        let relay = config.resolve_relay(None, None);
        assert_eq!(relay, None); // default is LAN-only (no relay)

        let download_dir = config.resolve_download_dir(None);
        assert_eq!(download_dir, std::env::current_dir().unwrap());

        let timeouts = config.resolve_timeouts();
        assert_eq!(timeouts.pake, Duration::from_secs(15));
        assert_eq!(timeouts.discovery, Duration::from_secs(20));
        assert_eq!(timeouts.block_transfer, Duration::from_secs(30));
    }

    #[test]
    fn test_config_file_parsing() {
        let toml_str = r#"
            default_relay = "https://relay.example.com:7777"
            default_download_dir = "/tmp/downloads"

            [timeouts]
            pake = 10
            discovery = 5
            block_transfer = 60
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.default_relay.as_deref(), Some("https://relay.example.com:7777"));
        assert_eq!(config.default_download_dir.as_deref(), Some("/tmp/downloads"));
        
        let timeouts = config.timeouts.unwrap();
        assert_eq!(timeouts.pake, Some(10));
        assert_eq!(timeouts.discovery, Some(5));
        assert_eq!(timeouts.block_transfer, Some(60));
    }

    #[test]
    fn test_precedence_resolution() {
        let toml_str = r#"
            default_relay = "https://config-relay.com"
            default_download_dir = "/config/downloads"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();

        // 1. CLI > Env > Config
        let relay = config.resolve_relay(Some("https://cli-relay.com"), Some("https://env-relay.com"));
        assert_eq!(relay.as_deref(), Some("https://cli-relay.com"));

        // 2. Env > Config (when CLI is None)
        let relay = config.resolve_relay(None, Some("https://env-relay.com"));
        assert_eq!(relay.as_deref(), Some("https://env-relay.com"));

        // 3. Config (when CLI and Env are None)
        let relay = config.resolve_relay(None, None);
        assert_eq!(relay.as_deref(), Some("https://config-relay.com"));

        // 4. Download Dir precedence: CLI > Config > Current Dir
        let download_dir = config.resolve_download_dir(Some(PathBuf::from("/cli/downloads")));
        assert_eq!(download_dir, PathBuf::from("/cli/downloads"));

        let download_dir = config.resolve_download_dir(None);
        assert_eq!(download_dir, PathBuf::from("/config/downloads"));
    }
}
