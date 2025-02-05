use std::fmt;

#[derive(Debug)]
pub enum ConversionError {
    InvalidUri,
    UnsupportedProtocol(String),
    ParseError(String),
    SerializationError(String),
    IoError(String),
    UnsupportedFeature(String),
    InvalidVersion(String),
    MissingPassword,
    MissingHost,
    MissingPort,
    MissingUUID,
    MissingIP,
    MissingPublicKey,
    MissingRealityParam(String),
    FailedDecode,
    InvalidVmessFormat,
    InvalidJson,
    MissingField(&'static str),
    InvalidTransportType(String), 
    InvalidDnsObject, 
    MissingServersArray,
    MissingTypeField,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidUri => write!(f, "Invalid URI format"),
            Self::UnsupportedProtocol(p) => write!(f, "Unsupported protocol: {}", p),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::UnsupportedFeature(e) => write!(f, "Unsupported feature: {}", e),
            Self::InvalidVersion(e) => write!(f, "Invalid version: {}", e),
            Self::MissingPassword => write!(f, "Missing password"),
            Self::MissingHost => write!(f, "Missing host"),
            Self::MissingPort => write!(f, "Missing port"),
            Self::MissingUUID => write!(f, "Missing UUID"),
            Self::MissingIP => write!(f, "Missing IP"),
            Self::MissingPublicKey => write!(f, "Missing public key"),
            Self::MissingRealityParam(p) => write!(f, "Missing reality parameter: {}", p),
            Self::FailedDecode => write!(f, "Failed to decode base64"),
            Self::InvalidVmessFormat => write!(f, "Invalid Vmess format"),
            Self::InvalidJson => write!(f, "Invalid JSON"),
            Self::MissingField(field) => write!(f, "Missing field: {}", field),
            Self::InvalidTransportType(t) => write!(f, "Invalid transport type: {}", t),
            Self::InvalidDnsObject => write!(f, "DNS configuration is not a valid object"),
            Self::MissingServersArray => write!(f, "Missing or invalid 'servers' array in DNS configuration"),
            Self::MissingTypeField => write!(f, "Missing type field"),

        }
    }
}