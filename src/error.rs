use serde::{Serialize, Serializer};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(String),
    #[error("envelope format: {0}")]
    Format(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e.to_string())
    }
}

// So a Tauri command can return `hl_core::Error` straight to the webview.
impl Serialize for Error {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
