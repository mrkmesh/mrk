use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Message(String),
    Io(std::io::Error),
    Json(serde_json::Error),
    Crypto(&'static str),
}

impl Error {
    pub fn msg(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
            Self::Io(error) => Display::fmt(error, f),
            Self::Json(error) => Display::fmt(error, f),
            Self::Crypto(message) => write!(f, "cryptographic operation failed: {message}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
