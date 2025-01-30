use std::fmt;

#[derive(Debug)]
pub enum ConversionError {
    InvalidUri,
    UnsupportedProtocol(String),
    ParseError(String),
    SerializationError(String),
    IoError(String),
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidUri => write!(f, "Invalid URI format"),
            Self::UnsupportedProtocol(p) => write!(f, "Unsupported protocol: {}", p),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}