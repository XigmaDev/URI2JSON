use crate::error::ConversionError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TransportConfig {
    TCP,
    Http {
        host: Vec<String>,
        path: String,
        method: String,
        headers: HashMap<String, String>,
        idle_timeout: String,
        ping_timeout: String,
    },
    Websocket {
        path: String,
        headers: HashMap<String, String>,
        max_early_data: u32,
        early_data_header_name: String,
    },
    Quic,
    Grpc {
        #[serde(rename = "service_name")]
        service_name: String,
        #[serde(rename = "idle_timeout")]
        idle_timeout: String,
        #[serde(rename = "ping_timeout")]
        ping_timeout: String,
        #[serde(rename = "permit_without_stream")]
        permit_without_stream: bool,
    },
    Httpupgrade {
        host: String,
        path: String,
        headers: HashMap<String, String>,
    },
}

impl FromStr for TransportConfig {
    type Err = ConversionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(TransportConfig::TCP),
            "http" => Ok(TransportConfig::Http {
                host: Vec::new(),
                path: String::new(),
                method: String::new(),
                headers: HashMap::new(),
                idle_timeout: "15s".to_string(),
                ping_timeout: "15s".to_string(),
            }),
            "ws" | "websocket" => Ok(TransportConfig::Websocket {
                path: String::new(),
                headers: HashMap::new(),
                max_early_data: 0,
                early_data_header_name: String::new(),
            }),
            "quic" => Ok(TransportConfig::Quic),
            "grpc" => Ok(TransportConfig::Grpc {
                service_name: String::new(),
                idle_timeout: "15s".to_string(),
                ping_timeout: "15s".to_string(),
                permit_without_stream: false,
            }),
            "httpupgrade" => Ok(TransportConfig::Httpupgrade {
                host: String::new(),
                path: String::new(),
                headers: HashMap::new(),
            }),
            _ => Err(ConversionError::InvalidTransportType(s.to_string())),
        }
    }
}

impl TransportConfig {
    pub fn to_config(&self) -> Value {
        match self {
            TransportConfig::TCP => json!({}),
            TransportConfig::Http {
                host,
                path,
                method,
                headers,
                idle_timeout,
                ping_timeout,
            } => json!({
                "type": "http",
                "host": host,
                "path": path,
                "method": method,
                "headers": headers,
                "idle_timeout": idle_timeout,
                "ping_timeout": ping_timeout
            }),

            TransportConfig::Websocket {
                path,
                headers,
                max_early_data,
                early_data_header_name,
            } => json!({
                "type": "ws",
                "path": path,
                "headers": headers,
                "max_early_data": max_early_data,
                "early_data_header_name": early_data_header_name
            }),

            TransportConfig::Quic => json!({ "type": "quic" }),

            TransportConfig::Grpc {
                service_name,
                idle_timeout,
                ping_timeout,
                permit_without_stream,
            } => json!({
                "type": "grpc",
                "service_name": service_name,
                "idle_timeout": idle_timeout,
                "ping_timeout": ping_timeout,
                "permit_without_stream": permit_without_stream
            }),

            TransportConfig::Httpupgrade {
                host,
                path,
                headers,
            } => json!({
                "type": "httpupgrade",
                "host": host,
                "path": path,
                "headers": headers
            }),
        }
    }
}
