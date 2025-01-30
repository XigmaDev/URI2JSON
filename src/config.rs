use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use crate::error::ConversionError;
use crate::Protocol;


#[derive(Debug)]
pub struct SingBoxConfig {
    inbounds: Vec<Value>,
    outbounds: Vec<Value>,
}

impl SingBoxConfig {
    pub fn new() -> Self {
        Self {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
        }
    }

    pub fn add_default_inbound(&mut self) {
        self.inbounds.push(json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "::",
            "listen_port": 1080,
            "sniff": true
        }));
    }

    pub fn add_outbound(&mut self, protocol: &Protocol) {
        self.outbounds.push(protocol.to_singbox_outbound());
        self.outbounds.push(json!({
            "type": "direct",
            "tag": "direct"
        }));
    }

    pub fn save_to_file(&self, filename: &str) -> Result<(), ConversionError> {
        let config = json!({
            "inbounds": self.inbounds,
            "outbounds": self.outbounds
        });

        let content = serde_json::to_string_pretty(&config)
            .map_err(|e| ConversionError::SerializationError(e.to_string()))?;

        fs::write(Path::new(filename), content)
            .map_err(|e| ConversionError::IoError(e.to_string()))?;

        Ok(())
    }   
}


