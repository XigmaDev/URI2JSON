use serde_json::{json, Value};
use url::Url;
use std::collections::HashMap;
use base64::engine::general_purpose;
use base64::Engine;
use semver::Version;
use crate::error::ConversionError;


#[derive(Debug)]
pub enum ConfigType{
    Endpoint(Value),
    Outbound(Value),
}
#[derive(Debug)]
pub enum Protocol {
    Shadowsocks{
        method: String,
        password: String,
        host: String,
        port: u16,
        plugin: Option<String>,
        plugin_opts: Option<String>,
    },
    Vmess{
        uuid: String,
        host: String,
        port: u16,
        alter_id: String,
        security: String,
        transport: TransportConfig,
        tls: TlsConfig,
    },
    Vless{
        uuid: String,
        host: String,
        port: u16,
        flow: Option<String>,
        transport: TransportConfig,
        tls: TlsConfig,
    },
    Trojan{
        password: String,
        host: String,
        port: u16,
        transport: TransportConfig,
        tls: TlsConfig,
    },
    Wireguard{
        private_key: String,
        public_key: String,
        endpoint: String,
        dns: Option<String>,
        mtu: Option<u16>,
        ip: String,
    },
}

#[derive(Debug, Default)]
pub struct TransportConfig {
    network: String,
    path: Option<String>,
    host: Option<String>,
    headers: HashMap<String, String>,
    service_name: Option<String>,
    quic_security: Option<String>,
    key: Option<String>,
    mode: Option<String>,
}


#[derive(Debug, Default)]
pub struct TlsConfig{
    enabled: bool,
    insecure: bool,
    sni: Option<String>,
    alpn:Vec<String>,
    utls: Option<String>,
    reality: Option<RealityConfig>,
}
#[derive(Debug)]
pub struct RealityConfig {
    public_key: String,
    short_id: String,
}



impl Protocol {
    pub fn parse_uri(uri: &str) -> Result<Self, ConversionError> {
        let (scheme, content) = uri
            .split_once("://")
            .ok_or(ConversionError::InvalidUri)?;

        match scheme {
            "ss" => Self::parse_shadowsocks(content),
            "vmess" => Self::parse_vmess(content),
            "vless" => Self::parse_vless(content),
            "trojan" => Self::parse_trojan(content),
            "wireguard" => Self::parse_wireguard(content),
            _ => Err(ConversionError::UnsupportedProtocol(scheme.to_string())),
        }
    }
}


impl Protocol {
    pub fn get_type(&self) -> &str {
        match self {
            Self::Shadowsocks {..} => "Shadowsocks",
            Self::Vmess {..} => "Vmess",
            Self::Vless {..} => "Vless",
            Self::Trojan {..} => "Trojan",
            Self::Wireguard {..} => "Wireguard",
        }
    }

    fn parse_shadowsocks(data: &str) -> Result<Self, ConversionError> {
        let url = Url::parse(&format!("ss://{}", data)).map_err(|_| ConversionError::InvalidUri)?;
        Ok(Self::Shadowsocks{
            method: url.username().to_string(),
            password: url.password().ok_or(ConversionError::MissingPassword)?.to_string(),
            host: url.host_str().ok_or(ConversionError::MissingHost)?.to_string(),
            port: url.port().ok_or(ConversionError::MissingPort)?,
            plugin: url.query_pairs().find(|(k, _)| k == "plugin").map(|(_, v)| v.to_string()),
            plugin_opts: url.query_pairs().find(|(k, _)| k == "plugin-opts").map(|(_, v)| v.to_string()),
        })
    }
    fn parse_vmess(data: &str) -> Result<Self, ConversionError> {
        let decoded = general_purpose::STANDARD.decode(data).map_err(|_| ConversionError::FailedDecode)?;
        let vmess: Value = serde_json::from_slice(&decoded).map_err(|_| ConversionError::InvalidJson)?;
        
        let mut query = vmess.as_object()
            .ok_or(ConversionError::InvalidVmessFormat)?
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
            .collect::<HashMap<String, String>>();

        //parse query params 
        
        let port = vmess["port"].as_u64().ok_or(ConversionError::MissingPort)? as u16;

        Ok(Self::Vmess {
            uuid: vmess["id"].as_str().ok_or(ConversionError::MissingUUID)?.to_string(),
            host: vmess["add"].as_str().ok_or(ConversionError::MissingHost)?.to_string(),
            port,
            alter_id: vmess["aid"].as_str().unwrap_or("0").to_string(),
            security: vmess["security"].as_str().unwrap_or("auto").to_string(),
            transport: parse_transport(&mut query),
            tls: parse_tls(&mut query),
        })
    }

    fn parse_vless(data: &str) -> Result<Self, ConversionError> {
        let url = Url::parse(&format!("vless://{}", data)).map_err(|_| ConversionError::InvalidUri)?;
        let mut query = url.query_pairs()
            .into_owned()
            .collect::<HashMap<String, String>>();
        
        Ok(Self::Vless {
            uuid: url.username().to_string(),
            host: url.host_str().ok_or(ConversionError::MissingHost)?.to_string(),
            port: url.port().ok_or(ConversionError::MissingPort)?,
            flow: query.remove("flow").map(|v| v.to_string()),
            transport: parse_transport(&mut query),
            tls: parse_tls(&mut query),
        })
    }

    fn parse_trojan(data: &str) -> Result<Self, ConversionError> {
        let url = Url::parse(&format!("trojan://{}", data)).map_err(|_| ConversionError::InvalidUri)?;
        let mut query = url.query_pairs()
            .into_owned()
            .collect::<HashMap<String, String>>();
        Ok(Self::Trojan {
            password: url.username().to_string(),
            host: url.host_str().ok_or(ConversionError::MissingHost)?.to_string(),
            port: url.port().ok_or(ConversionError::MissingPort)?,
            transport: parse_transport(&mut query),
            tls: parse_tls(&mut query),
        })
    }

    fn parse_wireguard(data: &str) -> Result<Self, ConversionError> {
        let url = Url::parse(&format!("wireguard://{}", data)).map_err(|_| ConversionError::InvalidUri)?;
        let query = url.query_pairs().collect::<HashMap<_, _>>();
        
        Ok(Self::Wireguard {
            private_key: url.username().to_string(),
            public_key: query.get("publickey").ok_or(ConversionError::MissingPublicKey)?.to_string(),
            endpoint: format!(
                "{}:{}",
                url.host_str().ok_or(ConversionError::MissingHost)?,
                url.port().ok_or(ConversionError::MissingPort)?
            ),
            dns: query.get("dns").map(|s| s.to_string()),
            mtu: query.get("mtu").map(|s| s.parse().unwrap()),
            ip: query.get("ip").ok_or(ConversionError::MissingIP)?.to_string(),
        })
    }


    pub fn to_singbox_outbound(&self, version: &Version) -> Result<ConfigType, ConversionError> {
        match self {
            Self::Wireguard {
                private_key,
                public_key,
                endpoint,
                dns,
                mtu,
                ip,
            } => {
                if version >= &Version::new(1, 11, 0) {
                    Ok(ConfigType::Endpoint(json!({
                        "type": "wireguard",
                        "tag": "wg-endpoint",
                        "local_address": [ip],
                        "private_key": private_key,
                        "peer_public_key": public_key,
                        "server": endpoint,
                        "mtu": mtu,
                        "dns": dns,
                    })))
                } else {
                    Ok(ConfigType::Outbound(json!({
                        "type": "wireguard",
                        "local_address": [ip],
                        "private_key": private_key,
                        "peer_public_key": public_key,
                        "endpoint": endpoint,
                        "mtu": mtu,
                        "dns": dns,
                    })))
                }
            }
            _ => Ok(ConfigType::Outbound(self.to_legacy_singbox_outbound())),
        }
    }


    pub fn to_legacy_singbox_outbound(&self) -> Value {
        match self {
            Self::Shadowsocks {
                method,
                password,
                host,
                port,
                plugin,
                plugin_opts
            } => {
                let mut config = json!({
                "type": "shadowsocks",
                "server": host,
                "server_port": port,
                "method": method,
                "password": password,
            });
            if let Some(plugin) = plugin {
                config["plugin"] = json!(plugin);
                if let Some(opts) = plugin_opts {
                    config["plugin_opts"] = json!(opts);
                }
            }
            config
        }
            Self::Vmess {
                uuid,
                host,
                port,
                alter_id,
                security,
                transport,
                tls,
            } => {
                let mut config =json!({
                    "type": "vmess",
                    "server": host,
                    "server_port": port,
                    "uuid": uuid,
                    "alterId": alter_id,
                    "security": security,
                    "transport": transport.to_config(),
                });

                if tls.enabled {
                    config["tls"] = tls.to_config();
                }
                config
            }

            Self::Vless {
                uuid,
                host,
                port,
                flow,
                transport,
                tls
            } => {
                let mut config = json!({
                    "type": "vless",
                    "tag" : "vless-out",
                    "server": host,
                    "server_port": port,
                    "uuid": uuid,
                    "transport": transport.to_config(),
                });

                if let Some(flow) = flow {
                    config["flow"] = json!(flow);
                }

                if tls.enabled {
                    config["tls"] = tls.to_config();
                }

                config
            }

            Self::Trojan {
                password,
                host,
                port,
                transport,
                tls
            } => {
                let mut config = json!({
                "type": "trojan",
                "server": host,
                "server_port": port,
                "password": password,
                "transport":transport.to_config(),
            });

            if tls.enabled {
                config["tls"] = tls.to_config();
            }
            config
        }
            Self::Wireguard {
                private_key,
                public_key,
                endpoint,
                dns,
                mtu,
                ip,
            } => {
                let config = json!({
                    "type": "wireguard",
                    "local_address": [ip],
                    "private_key": private_key,
                    "peer_public_key": public_key,
                    "endpoint": endpoint,
                    "mtu": mtu,
                    "dns": dns,
                });
                config
            }
        }
    }
    
}



fn parse_transport(query: &mut HashMap<String, String>) -> TransportConfig {
    let mut transport = TransportConfig {
        network: query.remove("type").expect("Missing network type"),
        path: query.remove("path").or_else(|| query.remove("serviceName")),
        host: query.remove("host").or_else(|| query.remove("sni")),
        headers: parse_headers(query.remove("headers")),
        service_name: query.remove("serviceName"),
        quic_security: query.remove("quicSecurity"),
        key: query.remove("key"),
        mode: query.remove("mode"),
    };

    // Handle HTTP upgrade
    if transport.network == "http" {
        if let Some(path) = &transport.path {
            if !path.starts_with('/') {
                transport.path = Some(format!("/{}", path));
            }
        }
    }

    transport
}

fn parse_tls(query: &mut HashMap<String, String>) -> TlsConfig {
    let security = query.remove("security").unwrap_or_default();
    let mut tls = TlsConfig::default();

    if security == "tls" || security == "reality" {
        tls.enabled = true;
        tls.sni = query.remove("sni");
        tls.insecure = false;
        tls.insecure = query.remove("insecure").is_some();
        tls.alpn = query.remove("alpn")
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        if security == "reality" {
            tls.reality = Some(RealityConfig {
                public_key: query.remove("pbk").expect("Missing reality public key"),
                short_id: query.remove("sid").expect("Missing reality short id"),
            });
        }
    }

    tls
}

fn parse_headers(header_str: Option<String>) -> HashMap<String, String> {
    header_str.map(|s| {
        s.split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                match (parts.next(), parts.next()) {
                    (Some(k), Some(v)) => Some((k.to_string(), v.to_string())),
                    _ => None,
                }
            })
            .collect()
    }).unwrap_or_default()
}

impl TransportConfig {
    fn to_config(&self) -> Value {
        match self.network.as_str() {
            "ws" => json!({
                "type": "ws",
                "path": self.path,
                "headers": self.headers,
                "max_early_data": 0,
                "early_data_header_name": ""              
            }),
            "http" => json!({
                "type": "http",
                "path": self.path,
                "host": self.host,
                "method": self.mode,
                "headers": self.headers,
                "idle_timeout": "15s",
                "ping_timeout": "15s"
            }),
            "quic" => json!({
                "type": "quic",
                //No additional encryption support: It's basically duplicate encryption. And Xray-core is not compatible with v2ray-core in here.
            }),
            "grpc" => json!({
                "type": "grpc",
                "service_name": self.service_name,
                "idle_timeout": "15s",
                "ping_timeout": "15s",
                "permit_without_stream": false
            }),
            "httpupgrade" => json!({
                "type": "httpupgrade",
                "host": self.host,
                "path": self.path,
                "headers": self.headers
            }),
            _ => json!({"type": self.network}),
        }
    }
}

impl TlsConfig {
    fn to_config(&self) -> Value {
        let mut config = json!({
            "enabled": self.enabled,
            "server_name": self.sni,
            "alpn": self.alpn
        });

        if let Some(reality) = &self.reality {
            config["reality"] = json!({
                "enabled": true,
                "public_key": reality.public_key,
                "short_id": reality.short_id
            });
        }

        config
    }
}


