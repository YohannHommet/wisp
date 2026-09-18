use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Timeouts {
    pub pake: u64,
    pub discovery: u64,
    pub block_transfer: u64,
    pub wait: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            pake: 15,
            discovery: 20,
            block_transfer: 30,
            wait: 300,
        }
    }
}

impl Timeouts {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("pake", self.pake),
            ("discovery", self.discovery),
            ("block_transfer", self.block_transfer),
            ("wait", self.wait),
        ] {
            if !(1..=3600).contains(&value) {
                bail!("timeout {name} must be between 1 and 3600 seconds");
            }
        }
        Ok(())
    }
    pub(crate) fn io(&self) -> Duration {
        Duration::from_secs(self.block_transfer)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub default_download_dir: Option<PathBuf>,
    pub timeouts: Timeouts,
}

impl Config {
    pub fn default_path() -> Result<PathBuf> {
        Ok(dirs::config_dir()
            .context("cannot determine the configuration directory")?
            .join("wisp/config.toml"))
    }

    pub fn load(path: &Path, required: bool) -> Result<Self> {
        const MAX_CONFIG_SIZE: u64 = 64 * 1024;
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(err) if !required && err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("reading configuration {}", path.display()));
            }
        };
        use std::io::Read;
        let mut text = String::new();
        file.take(MAX_CONFIG_SIZE + 1)
            .read_to_string(&mut text)
            .with_context(|| format!("reading configuration {}", path.display()))?;
        if text.len() > MAX_CONFIG_SIZE as usize {
            bail!("configuration file {} exceeds 64 KiB limit", path.display());
        }
        let config: Self = toml::from_str(&text).with_context(|| format!(
            "invalid configuration {}; Wisp 0.2 supports default_download_dir and timeouts only (remove legacy relay/trusted_peers settings)", path.display()))?;
        config.timeouts.validate()?;
        Ok(config)
    }

    pub fn download_dir(&self, explicit: Option<PathBuf>) -> Result<PathBuf> {
        let Some(path) = explicit.or_else(|| self.default_download_dir.clone()) else {
            return std::env::current_dir().context("cannot determine the current directory");
        };
        if let Ok(rest) = path.strip_prefix("~") {
            return Ok(dirs::home_dir()
                .context("cannot expand ~ without a home directory")?
                .join(rest));
        }
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_optional_config_is_fine_but_broken_or_legacy_config_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        assert!(Config::load(&path, false).is_ok());
        assert!(Config::load(&path, true).is_err());
        for text in [
            "invalid!",
            "default_relay = 'https://example.com'",
            "[timeouts]\npake = 0",
            "[timeouts]\nwait = 999999",
        ] {
            std::fs::write(&path, text).unwrap();
            assert!(Config::load(&path, false).is_err());
        }
    }
    #[test]
    fn config_size_cap_rejects_large_files() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(&path, "a".repeat(65 * 1024)).unwrap();
        assert!(Config::load(&path, true).is_err());
    }
    #[test]
    fn partial_config_keeps_defaults_and_explicit_directory_wins() {
        let config: Config =
            toml::from_str("default_download_dir = 'Downloads'\n[timeouts]\npake = 5").unwrap();
        assert_eq!(config.timeouts.pake, 5);
        assert_eq!(config.timeouts.wait, 300);
        assert_eq!(
            config.download_dir(Some("other".into())).unwrap(),
            PathBuf::from("other")
        );
        assert_eq!(
            config.download_dir(None).unwrap(),
            PathBuf::from("Downloads")
        );
    }
}
