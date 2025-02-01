use serde_json::{json,Map, Value};
use std::fs;
use std::path::Path;
use crate::error::ConversionError;
use crate::Protocol;


#[derive(Debug)]
pub struct SingBoxConfig {
    log: Value,
    dns: Value,
    ntp: Value,
    endpoints: Vec<Value>,
    inbounds: Vec<Value>,
    outbounds: Vec<Value>,
    route: Value,
    experimental: Value,
}

impl SingBoxConfig {
    pub fn new() -> Self {
        Self {
            log: json!({}),
            dns: json!({}),
            ntp: json!({}),
            endpoints: Vec::new(),
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: json!({}),
            experimental: json!({}),
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
        let mut map = Map::new();

        map.insert("log".to_string(), self.log.clone());
        map.insert("dns".to_string(), self.dns.clone());
        map.insert("ntp".to_string(), self.ntp.clone());
        map.insert("endpoints".to_string(), Value::Array(self.endpoints.clone()));
        map.insert("inbounds".to_string(), Value::Array(self.inbounds.clone()));
        map.insert("outbounds".to_string(), Value::Array(self.outbounds.clone()));
        map.insert("route".to_string(), self.route.clone());
        map.insert("experimental".to_string(), self.experimental.clone());

        let content = serde_json::to_string_pretty(&Value::Object(map))
            .map_err(|e| ConversionError::SerializationError(e.to_string()))?;

        fs::write(Path::new(filename), content)
            .map_err(|e| ConversionError::IoError(e.to_string()))?;

        Ok(())
    }  
}



// Optional: Add methods to configure other sections
impl SingBoxConfig {
    // {
    //     "log": {
    //       "disabled": false,
    //       "level": "info",
    //       "output": "box.log",
    //       "timestamp": true
    //     }
    // }
    pub fn set_log_level(&mut self, level: &str) {
        self.log = json!({
            "enabled": true,
            "level": level,
            "timestamp": true
        });
    }


    // {
    //     "dns": {
    //       "servers": [],
    //       "rules": [],
    //       "final": "",
    //       "strategy": "",
    //       "disable_cache": false,
    //       "disable_expire": false,
    //       "independent_cache": false,
    //       "cache_capacity": 0,
    //       "reverse_mapping": false,
    //       "client_subnet": "",
    //       "fakeip": {}
    //     }
    //   }
    pub fn add_dns_server(&mut self, server: &str) {
        self.dns = json!({
            "servers": [server]
        });
    }


    

    // {
    //     "route": {
    //       "rules": [],
    //       "rule_set": [],
    //       "final": "",
    //       "auto_detect_interface": false,
    //       "override_android_vpn": false,
    //       "default_interface": "",
    //       "default_mark": 0,
    //       "default_domain_resolver": "", // or {}
    //       "default_network_strategy": "",
    //       "default_network_type": [],
    //       "default_fallback_network_type": [],
    //       "default_fallback_delay": "",
      
    //       // Removed
      
    //       "geoip": {},
    //       "geosite": {}
    //     }
    //   }

    pub fn set_route(&mut self, rules: Value, rule_set: Value) {
        self.route = json!({
            "rules": rules,
            "rule_set":rule_set,

        });
    }
}
