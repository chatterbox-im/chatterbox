use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use log::info;
use once_cell::sync::OnceCell;
use chatterbox::omemo::device_id;

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
            String::from_utf8(
                BASE64.decode(encoded).unwrap_or_default()
            ).unwrap_or_default()
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
        .join("rust-xmpp-chat");
    
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
    info!("Loaded credentials for {} from {}", credentials.username, config_path_str);
    
    Ok(Some(credentials))
}

static CONFIG_PATH_OVERRIDE: OnceCell<PathBuf> = OnceCell::new();


fn get_config_path() -> Result<PathBuf> {
    if let Some(path) = CONFIG_PATH_OVERRIDE.get() {
        return Ok(path.clone());
    }
    Ok(get_config_dir()?.join("credentials.json"))
}
