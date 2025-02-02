use serde_json::{json,Map, Value};
use std::fs;
use std::path::Path;
use crate::error::ConversionError;
use crate::Protocol;


#[derive(Debug)]
pub struct SingBoxConfig {
    log: Value,
    dns: Value,
    //ntp: Value,
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
            dns: json!({
                "servers": [],
                "rules": [],
                "final": "remote"
            }),
            //ntp: json!({}),
            endpoints: Vec::new(),
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: json!({}),
            experimental: json!({}),
        }
    }

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
            "disabled": false,
            "level": level,
            "timestamp": true
        });
    }

    pub fn add_default_inbound(&mut self) {
        self.inbounds.push(json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "::",
            "listen_port": 1080,
            "sniff": true,
            "sniff_override_destination": true,
        }));
    }

    pub fn add_outbound(&mut self, protocol: &Protocol) {
        self.outbounds.push(protocol.to_singbox_outbound());
        self.outbounds.push(json!({
            "type": "direct",
            "tag": "direct"
        }));
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
    //Example:
    // {
    //     "servers": [
    //       {
    //         "tag": "remote",
    //         "address": "8.8.8.8",
    //         "strategy": "prefer_ipv4",
    //         "detour": "proxy"
    //       },
    //       {
    //         "tag": "local",
    //         "address": "223.5.5.5",
    //         "strategy": "prefer_ipv4",
    //         "detour": "direct"
    //       },
    //       {
    //         "tag": "block",
    //         "address": "rcode://success"
    //       }
    //     ],
    //     "rules": [
    //       {
    //         "rule_set": [
    //           "geosite-cn",
    //           "geosite-geolocation-cn"
    //         ],
    //         "server": "local"
    //       },
    //       {
    //         "rule_set": [
    //           "geosite-category-ads-all"
    //         ],
    //         "server": "block"
    //       }
    //     ],
    //     "final": "remote"
    //   }

    pub fn add_dns_server(&mut self, tag: &str, address: &str, strategy: Option<&str>, detour: Option<&str>) {
        let mut server = serde_json::Map::new();
        server.insert("tag".into(), tag.into());
        server.insert("address".into(), address.into());
        
        if let Some(s) = strategy {
            server.insert("strategy".into(), s.into());
        }
        
        if let Some(d) = detour {
            server.insert("detour".into(), d.into());
        }

        if let Value::Object(ref mut dns) = self.dns {
            if let Some(Value::Array(ref mut servers)) = dns.get_mut("servers") {
                servers.push(Value::Object(server));
            }
        }
    }

    pub fn add_dns_rule(&mut self, rule_sets: Vec<&str>, server_tag: &str) {
        let mut rule = serde_json::Map::new();
        rule.insert(
            "rule_set".into(),
            Value::Array(rule_sets.iter().map(|s| Value::String(s.to_string())).collect())
        );
        rule.insert("server".into(), server_tag.into());

        if let Value::Object(ref mut dns) = self.dns {
            if let Some(Value::Array(ref mut rules)) = dns.get_mut("rules") {
                rules.push(Value::Object(rule));
            }
        }
    }

    pub fn set_dns_final(&mut self, final_server: &str) {
        if let Value::Object(ref mut dns) = self.dns {
            dns.insert("final".into(), Value::String(final_server.to_string()));
        }
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




    

    pub fn save_to_file(&self, filename: &str) -> Result<(), ConversionError> {
        let mut map = Map::new();

        map.insert("log".to_string(), self.log.clone());
        map.insert("dns".to_string(), self.dns.clone());
        //map.insert("ntp".to_string(), self.ntp.clone());
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


