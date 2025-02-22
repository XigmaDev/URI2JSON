use crate::error::ConversionError;
use crate::protocol::{ConfigType, Protocol};
use semver::Version;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct SingBoxConfig {
    version: Version,
    log: Value,
    dns: Value,
    endpoints: Vec<Value>,
    inbounds: Vec<Value>,
    outbounds: Vec<Value>,
    route: Value,
    experimental: Value,
}

impl SingBoxConfig {
    pub fn new(version: String) -> Result<Self, ConversionError> {
        let version =
            Version::parse(&version).map_err(|e| ConversionError::InvalidVersion(e.to_string()))?;

        Ok(Self {
            version,
            log: json!({}),
            dns: json!({
                "servers": [],
                "rules": [],
            }),
            endpoints: Vec::new(),
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: json!({}),
            experimental: json!({}),
        })
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
            "level": level,
            "timestamp": true
        });
    }

    pub fn add_mixed_inbound(&mut self) {
        self.inbounds.push(json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "::",
            "listen_port": 2080
        }));
    }

    pub fn add_tun_inbound(&mut self) {
        self.inbounds.push(json!({
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "address": [
                  "172.18.0.1/30"
                ],
                "gso": false,
                "auto_route": true,
                "mtu": 1358,
                "strict_route": true,
                "udp_timeout": "5s",
                "stack": "system",
                "sniff": true,
                "sniff_override_destination": true,
                "sniff_timeout": "300ms",
                "endpoint_independent_nat": true,

        }));
    }

    pub fn add_outbound(&mut self, protocol: Protocol) -> Result<(), ConversionError> {
        match protocol.to_singbox_outbound(&self.version)? {
            ConfigType::Endpoint(endpoint) => {
                self.endpoints.push(endpoint);
            }
            ConfigType::Outbound(outbound) => {
                self.outbounds.push(outbound);
                self.outbounds.push(json!({
                    "type": "direct",
                    "tag": "direct",
                }));
            }
        }
        Ok(())
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

    pub fn add_dns_server(&mut self) {
        if self.version >= Version::new(1, 12, 0) {
            if let Value::Object(ref mut dns) = self.dns {
                let servers = dns
                    .entry("servers")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(ref mut servers) = servers {
                    servers.push(json!({
                        "tag": "remote",
                        "type": "tls",
                        "server": "dns.adguard-dns.com",
                        "domain_resolver": "local"
                    }));
                    servers.push(json!({
                        "tag": "local",
                        "type": "tls",
                        "server": "1.1.1.1"
                    }));
                }
            }
        } else if self.version < Version::new(1, 12, 0) {
            if let Value::Object(ref mut dns) = self.dns {
                let servers = dns
                    .entry("servers")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(ref mut servers) = servers {
                    servers.push(json!({
                        "tag": "remote",
                        "address": "tls://dns.adguard-dns.com",
                        "address_resolver": "local",
                        "strategy": "prefer_ipv4",
                        "detour": "proxy"
                    }));
                    servers.push(json!({
                        "tag": "local",
                        "address": "1.1.1.1",
                        "detour": "direct"
                    }));
                }
            }
        }
    }

    pub fn add_dns_rule(&mut self) {
        if self.version < Version::new(1, 12, 0) {
            if let Value::Object(ref mut dns) = self.dns {
                let rules = dns
                    .entry("rules")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(ref mut rules) = rules {
                    //rules.push(json!({}));
                }
            }
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
    pub fn set_route(&mut self) {
        if self.version >= Version::new(1, 12, 0) {
            self.route = json!({
                "auto_detect_interface": true,
                "override_android_vpn": true,
                "default_domain_resolver": {
                    "server": "local"
                },
                "final":"proxy",
                "rules":json!([
                        {
                            "protocol": "dns",
                            "action": "hijack-dns"
                        },
                        {
                            "ip_is_private": true,
                            "outbound": "direct"
                        },
                        {
                            "rule_set": [
                                "geosite-category-public-tracker",
                                "geosite-category-ads",
                                "geosite-category-ads-all",
                                "geosite-google-ads"
                            ],
                            "action": "reject"
                        },
                        {
                            "inbound": [
                                "mixed-in",
                                "tun-in"
                            ],
                            "action":"route",
                            "outbound": "proxy"
                        }
                    ]),
                "rule_set":json!([
                    {
                        "type": "remote",
                        "format": "binary",
                        "tag": "geosite-category-ads-all",
                        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
                        "download_detour": "direct",
                        "update_interval": "1d"
                    },
                    {
                        "type": "remote",
                        "format": "binary",
                        "tag": "geosite-google-ads",
                        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google-ads.srs",
                        "download_detour": "direct",
                        "update_interval": "1d"
                    },
                    {
                        "type": "remote",
                        "format": "binary",
                        "tag": "geosite-category-ads",
                        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads.srs",
                        "download_detour": "direct",
                        "update_interval": "1d"
                    },
                    {
                        "tag": "geosite-category-public-tracker",
                        "type": "remote",
                        "format": "binary",
                        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-public-tracker.srs",
                        "download_detour": "direct",
                        "update_interval": "1d"
                    }
                ])
            });
        } else {
            self.route = json!({
                "auto_detect_interface": true,
                "override_android_vpn": true,
                "final":"proxy",
                "rules":json!([
                    {
                        "protocol": "dns",
                        "action": "hijack-dns"
                    },
                    {
                        "ip_is_private": true,
                        "outbound": "direct"
                    },
                    {
                        "rule_set": [
                            "geosite-category-public-tracker",
                            "geosite-category-ads",
                            "geosite-category-ads-all",
                            "geosite-google-ads"
                        ],
                        "action": "reject"
                    },
                    {
                        "inbound": [
                            "mixed-in",
                            "tun-in"
                        ],
                        "action": "route",
                        "outbound": "proxy"
                    }
                ]),
                "rule_set":json!([
                    {
                        "type": "remote",
                        "format": "binary",
                        "tag": "geosite-category-ads-all",
                        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
                        "download_detour": "direct",
                        "update_interval": "1d"
                    },
                    {
                        "type": "remote",
                        "format": "binary",
                        "tag": "geosite-google-ads",
                        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google-ads.srs",
                        "download_detour": "direct",
                        "update_interval": "1d"
                    },
                    {
                        "type": "remote",
                        "format": "binary",
                        "tag": "geosite-category-ads",
                        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads.srs",
                        "download_detour": "direct",
                        "update_interval": "1d"
                    },
                    {
                        "tag": "geosite-category-public-tracker",
                        "type": "remote",
                        "format": "binary",
                        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-public-tracker.srs",
                        "download_detour": "direct",
                        "update_interval": "1d"
                    }
                ])
            });
        }
    }

    pub fn add_default_experimental(&mut self) {
        self.experimental = json!({
            "cache_file": {
            "enabled": true
            },
        });
    }

    pub fn save_to_file(&self, filename: &str) -> Result<(), ConversionError> {
        let mut map = Map::new();

        map.insert("log".to_string(), self.log.clone());
        map.insert("dns".to_string(), self.dns.clone());
        if self.version >= semver::Version::new(1, 12, 0) {
            map.insert(
                "endpoints".to_string(),
                Value::Array(self.endpoints.clone()),
            );
        }
        map.insert("inbounds".to_string(), Value::Array(self.inbounds.clone()));
        map.insert(
            "outbounds".to_string(),
            Value::Array(self.outbounds.clone()),
        );
        map.insert("route".to_string(), self.route.clone());
        map.insert("experimental".to_string(), self.experimental.clone());

        let content = serde_json::to_string_pretty(&Value::Object(map))
            .map_err(|e| ConversionError::SerializationError(e.to_string()))?;

        fs::write(Path::new(filename), content)
            .map_err(|e| ConversionError::IoError(e.to_string()))?;

        Ok(())
    }
}
