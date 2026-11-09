use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chatterbox::omemo::device_id;
use log::info;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    #[default]
    Dark,
    Light,
    Sepia,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct AppSettings {
    #[serde(default)]
    pub os_notifications_enabled: bool,
    #[serde(default)]
    pub theme: Theme,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Credentials {
    pub server: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl Credentials {
    pub fn new(server: &str, username: &str, password: &str) -> Self {
        Credentials {
            server: server.to_string(),
            username: username.to_string(),
            password: Some(BASE64.encode(password)),
        }
    }

    pub fn get_password(&self) -> Option<String> {
        self.password.as_ref().map(|encoded| {
            String::from_utf8(BASE64.decode(encoded).unwrap_or_default()).unwrap_or_default()
        })
    }
}

pub fn get_config_dir() -> Result<PathBuf> {
    // If OMEMO_DIR_OVERRIDE is set, use it for credentials as well
    if let Some(dir) = device_id::get_omemo_dir_override() {
        return Ok(dir.clone());
    }
    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow!("Could not determine config directory"))?
        .join("chatterbox");

    if !config_dir.exists() {
        fs::create_dir_all(&config_dir)?;
    }

    Ok(config_dir)
}

pub fn save_credentials(credentials: &Credentials) -> Result<()> {
    let config_path = get_config_path()?;
    let file = File::create(config_path)?;
    serde_json::to_writer_pretty(file, credentials)?;

    info!("Credentials saved for {}", credentials.username);
    Ok(())
}

pub fn load_credentials() -> Result<Option<Credentials>> {
    let config_path = get_config_path()?;

    if !config_path.exists() {
        return Ok(None);
    }

    // Store the path as a string for logging before we move the PathBuf
    let config_path_str = config_path.display().to_string();

    let mut file = File::open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let credentials: Credentials = serde_json::from_str(&contents)?;
    info!(
        "Loaded credentials for {} from {}",
        credentials.username, config_path_str
    );

    Ok(Some(credentials))
}

pub fn save_app_settings(settings: &AppSettings) -> Result<()> {
    save_app_settings_to_path(&get_settings_path()?, settings)
}

fn save_app_settings_to_path(config_path: &Path, settings: &AppSettings) -> Result<()> {
    let file = File::create(config_path)?;
    serde_json::to_writer_pretty(file, settings)?;

    info!("Application settings saved");
    Ok(())
}

pub fn load_app_settings() -> Result<AppSettings> {
    load_app_settings_from_path(&get_settings_path()?)
}

fn load_app_settings_from_path(config_path: &Path) -> Result<AppSettings> {
    if !config_path.exists() {
        return Ok(AppSettings::default());
    }

    let mut file = File::open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let settings: AppSettings = serde_json::from_str(&contents)?;
    info!("Application settings loaded");

    Ok(settings)
}

static CONFIG_PATH_OVERRIDE: OnceCell<PathBuf> = OnceCell::new();

fn get_config_path() -> Result<PathBuf> {
    if let Some(path) = CONFIG_PATH_OVERRIDE.get() {
        return Ok(path.clone());
    }
    Ok(get_config_dir()?.join("credentials.json"))
}

fn get_settings_path() -> Result<PathBuf> {
    Ok(get_config_dir()?.join("settings.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_settings_use_the_default_theme() {
        let dir = tempfile::tempdir().unwrap();
        let settings = load_app_settings_from_path(&dir.path().join("settings.json")).unwrap();

        assert_eq!(settings.theme, Theme::Dark);
        assert!(!settings.os_notifications_enabled);
    }

    #[test]
    fn legacy_settings_keep_notifications_and_default_to_dark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, r#"{"os_notifications_enabled":true}"#).unwrap();

        let settings = load_app_settings_from_path(&path).unwrap();

        assert_eq!(settings.theme, Theme::Dark);
        assert!(settings.os_notifications_enabled);
    }

    #[test]
    fn settings_persist_every_theme_without_changing_notifications() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        for (theme, name) in [
            (Theme::Dark, "dark"),
            (Theme::Light, "light"),
            (Theme::Sepia, "sepia"),
        ] {
            let settings = AppSettings {
                os_notifications_enabled: true,
                theme,
            };
            save_app_settings_to_path(&path, &settings).unwrap();

            let saved: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(saved["theme"], name);
            let restored = load_app_settings_from_path(&path).unwrap();
            assert_eq!(restored.theme, theme);
            assert!(restored.os_notifications_enabled);
        }
    }

    #[test]
    fn saving_other_settings_preserves_the_theme() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let settings = AppSettings {
            theme: Theme::Sepia,
            ..AppSettings::default()
        };
        save_app_settings_to_path(&path, &settings).unwrap();
        let mut settings = load_app_settings_from_path(&path).unwrap();
        settings.os_notifications_enabled = true;
        save_app_settings_to_path(&path, &settings).unwrap();

        let restored = load_app_settings_from_path(&path).unwrap();
        assert_eq!(restored.theme, Theme::Sepia);
        assert!(restored.os_notifications_enabled);
    }
}
