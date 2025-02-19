mod tls;
mod transport;
use crate::error::ConversionError;
use base64::engine::general_purpose;
use base64::Engine;
use semver::Version;
use serde_json::{json, Value};
use std::collections::HashMap;
use url::Url;

#[derive(Debug)]
pub enum ConfigType {
    Endpoint(Value),
    Outbound(Value),
}

#[derive(Debug)]
pub enum Protocol {
    Shadowsocks {
        method: String,
        password: String,
        host: String,
        port: u16,
        plugin: Option<String>,
        plugin_opts: Option<String>,
    },
    Vmess {
        uuid: String,
        host: String,
        port: u16,
        alter_id: String,
        security: String,
        transport: transport::TransportConfig,
        tls: tls::TlsConfig,
    },
    Vless {
        uuid: String,
        host: String,
        port: u16,
        flow: Option<String>,
        transport: transport::TransportConfig,
        tls: tls::TlsConfig,
    },
    Trojan {
        password: String,
        host: String,
        port: u16,
        transport: transport::TransportConfig,
        tls: tls::TlsConfig,
    },
    Wireguard {
        private_key: String,
        public_key: String,
        endpoint: String,
        dns: Option<String>,
        mtu: Option<u16>,
        ip: String,
    },
}

impl Protocol {
    pub fn parse_uri(uri: &str) -> Result<Self, ConversionError> {
        let (scheme, content) = uri.split_once("://").ok_or(ConversionError::InvalidUri)?;

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
            Self::Shadowsocks { .. } => "Shadowsocks",
            Self::Vmess { .. } => "Vmess",
            Self::Vless { .. } => "Vless",
            Self::Trojan { .. } => "Trojan",
            Self::Wireguard { .. } => "Wireguard",
        }
    }

    fn parse_shadowsocks(data: &str) -> Result<Self, ConversionError> {
        let url = Url::parse(&format!("ss://{}", data)).map_err(|_| ConversionError::InvalidUri)?;
        Ok(Self::Shadowsocks {
            method: url.username().to_string(),
            password: url
                .password()
                .ok_or(ConversionError::MissingPassword)?
                .to_string(),
            host: url
                .host_str()
                .ok_or(ConversionError::MissingHost)?
                .to_string(),
            port: url.port().ok_or(ConversionError::MissingPort)?,
            plugin: url
                .query_pairs()
                .find(|(k, _)| k == "plugin")
                .map(|(_, v)| v.to_string()),
            plugin_opts: url
                .query_pairs()
                .find(|(k, _)| k == "plugin-opts")
                .map(|(_, v)| v.to_string()),
        })
    }
    fn parse_vmess(data: &str) -> Result<Self, ConversionError> {
        let decoded = general_purpose::STANDARD
            .decode(data)
            .map_err(|_| ConversionError::FailedDecode)?;
        let vmess: Value =
            serde_json::from_slice(&decoded).map_err(|_| ConversionError::InvalidJson)?;

        let mut query = vmess
            .as_object()
            .ok_or(ConversionError::InvalidVmessFormat)?
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
            .collect::<HashMap<String, String>>();

        //parse query params

        let port = vmess["port"].as_u64().ok_or(ConversionError::MissingPort)? as u16;

        Ok(Self::Vmess {
            uuid: vmess["id"]
                .as_str()
                .ok_or(ConversionError::MissingUUID)?
                .to_string(),
            host: vmess["add"]
                .as_str()
                .ok_or(ConversionError::MissingHost)?
                .to_string(),
            port,
            alter_id: vmess["aid"].as_str().unwrap_or("0").to_string(),
            security: vmess["security"].as_str().unwrap_or("auto").to_string(),
            transport: parse_transport(&mut query)?,
            tls: parse_tls(&mut query)?,
        })
    }

    fn parse_vless(data: &str) -> Result<Self, ConversionError> {
        let url =
            Url::parse(&format!("vless://{}", data)).map_err(|_| ConversionError::InvalidUri)?;
        let mut query = url
            .query_pairs()
            .into_owned()
            .collect::<HashMap<String, String>>();

        Ok(Self::Vless {
            uuid: url.username().to_string(),
            host: url
                .host_str()
                .ok_or(ConversionError::MissingHost)?
                .to_string(),
            port: url.port().ok_or(ConversionError::MissingPort)?,
            flow: query.remove("flow").map(|v| v.to_string()),
            transport: parse_transport(&mut query)?,
            tls: parse_tls(&mut query)?,
        })
    }

    fn parse_trojan(data: &str) -> Result<Self, ConversionError> {
        let url =
            Url::parse(&format!("trojan://{}", data)).map_err(|_| ConversionError::InvalidUri)?;
        let mut query = url
            .query_pairs()
            .into_owned()
            .collect::<HashMap<String, String>>();
        Ok(Self::Trojan {
            password: url.username().to_string(),
            host: url
                .host_str()
                .ok_or(ConversionError::MissingHost)?
                .to_string(),
            port: url.port().ok_or(ConversionError::MissingPort)?,
            transport: parse_transport(&mut query)?,
            tls: parse_tls(&mut query)?,
        })
    }

    fn parse_wireguard(data: &str) -> Result<Self, ConversionError> {
        let url = Url::parse(&format!("wireguard://{}", data))
            .map_err(|_| ConversionError::InvalidUri)?;
        let query = url.query_pairs().collect::<HashMap<_, _>>();

        Ok(Self::Wireguard {
            private_key: url.username().to_string(),
            public_key: query
                .get("publickey")
                .ok_or(ConversionError::MissingPublicKey)?
                .to_string(),
            endpoint: format!(
                "{}:{}",
                url.host_str().ok_or(ConversionError::MissingHost)?,
                url.port().ok_or(ConversionError::MissingPort)?
            ),
            dns: query.get("dns").map(|s| s.to_string()),
            mtu: query.get("mtu").map(|s| s.parse().unwrap()),
            ip: query
                .get("ip")
                .ok_or(ConversionError::MissingIP)?
                .to_string(),
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
                    Ok(ConfigType::Outbound(self.to_legacy_singbox_outbound()))
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
                plugin_opts,
            } => {
                let mut config = json!({
                    "type": "shadowsocks",
                    "tag": "proxy",
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
                let mut config = json!({
                    "type": "vmess",
                    "tag": "proxy",
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
                tls,
            } => {
                let mut config = json!({
                    "type": "vless",
                    "tag": "proxy",
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
                tls,
            } => {
                let mut config = json!({
                    "type": "trojan",
                    "tag": "proxy",
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
                    "tag": "proxy",
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

fn parse_transport(
    query: &mut HashMap<String, String>,
) -> Result<transport::TransportConfig, ConversionError> {
    let transport_type = query
        .remove("type")
        .ok_or(ConversionError::MissingField("type"))?
        .to_lowercase();

    match transport_type.as_str() {
        "http" => {
            let host = query
                .remove("host")
                .map(|h| h.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(Vec::new);

            let path = query
                .remove("path")
                .map(|mut p| {
                    if !p.starts_with('/') {
                        p.insert(0, '/');
                    }
                    p
                })
                .unwrap_or_default();

            Ok(transport::TransportConfig::Http {
                host,
                path,
                method: query.remove("method").unwrap_or_else(|| "GET".to_string()),
                headers: parse_headers(query.remove("headers")),
                idle_timeout: query
                    .remove("idle_timeout")
                    .unwrap_or_else(|| "15s".to_string()),
                ping_timeout: query
                    .remove("ping_timeout")
                    .unwrap_or_else(|| "15s".to_string()),
            })
        }
        "ws" | "websocket" => Ok(transport::TransportConfig::Websocket {
            path: query.remove("path").unwrap_or_default(),
            headers: {
                let mut headers = parse_headers(query.remove("headers"));
                if let Some(host) = query.remove("host") {
                    headers.insert("Host".to_string(), host);
                }
                headers
            },
            max_early_data: query
                .remove("max_early_data")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            early_data_header_name: query.remove("early_data_header_name").unwrap_or_default(),
        }),
        "quic" => Ok(transport::TransportConfig::Quic),
        "tcp" => Ok(transport::TransportConfig::TCP),
        "grpc" => Ok(transport::TransportConfig::Grpc {
            service_name: query.remove("service_name").unwrap_or_default(),
            idle_timeout: query
                .remove("idle_timeout")
                .unwrap_or_else(|| "15s".to_string()),
            ping_timeout: query
                .remove("ping_timeout")
                .unwrap_or_else(|| "15s".to_string()),
            permit_without_stream: query
                .remove("permit_without_stream")
                .map(|s| s == "true")
                .unwrap_or(false),
        }),
        "httpupgrade" => {
            let mut path = query.remove("path").unwrap_or_default();
            if !path.is_empty() && !path.starts_with('/') {
                path.insert(0, '/');
            }

            Ok(transport::TransportConfig::Httpupgrade {
                host: query.remove("host").unwrap_or_default(),
                path,
                headers: parse_headers(query.remove("headers")),
            })
        }
        _ => Err(ConversionError::InvalidTransportType(transport_type)),
    }
}

fn parse_tls(query: &mut HashMap<String, String>) -> Result<tls::TlsConfig, ConversionError> {
    let security = query.remove("security").unwrap_or_default();
    let mut tls = tls::TlsConfig::default();

    if security == "tls" || security == "reality" {
        tls.enabled = true;
        tls.sni = query.remove("sni");
        tls.insecure = false;
        tls.insecure = query.remove("insecure").is_some();
        tls.alpn = query
            .remove("alpn")
            .map(|s| {
                s.split(',')
                    .map(|s| s.trim().to_string().to_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        tls.utls = Some(tls::UTlsConfig {
            enabled: true,
            fingerprint: query.remove("fp").unwrap_or("chrome".to_string()),
        });
        if security == "reality" {
            tls.reality = Some(tls::RealityConfig {
                public_key: query
                    .remove("pbk")
                    .ok_or(ConversionError::MissingRealityParam("pbk".to_string()))?,
                short_id: query
                    .remove("sid")
                    .ok_or(ConversionError::MissingRealityParam("sid".to_string()))?,
            });
        }
    }
    Ok(tls)
}

fn parse_headers(header_str: Option<String>) -> HashMap<String, String> {
    header_str
        .map(|s| {
            s.split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    match (parts.next(), parts.next()) {
                        (Some(k), Some(v)) => Some((k.to_string(), v.to_string())),
                        _ => None,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}
