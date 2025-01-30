use std::{collections::HashMap, str::FromStr};
use base64::{Engine as _, engine::general_purpose};

use serde_json::{json, Value};
use url::Url;

#[derive(Debug)]
enum Protocol {
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
        encryption: String,
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
    },
    
}

#[derive(Debug, Default)]
struct TransportConfig {
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
struct TlsConfig{
    enabled: bool,
    sni: Option<String>,
    alpn:Vec<String>,
    certificate: Option<String>,
    reality: Option<RealityConfig>,
}
#[derive(Debug)]
struct RealityConfig {
    public_key: String,
    short_id: String,
}


impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme,content) = s
            .split_once("://")
            .ok_or_else(||"Invalid URI format".to_string())?;

        match scheme {
            "ss" => Self::parse_shadowsocks(content),
            "vmess" => Self::parse_vmess(content),
            "vless" => Self::parse_vless(content),
            "trojan" => Self::parse_trojan(content),
            "wg" => Self::parse_wireguard(content),
            _ => Err(format!("Unsupported protocol: {}", scheme)),
        }
    }
}


impl Protocol {
    fn parse_shadowsocks(data: &str) -> Result<Self, String> {
        let url = Url::parse(&format!("ss://{}", data)).map_err(|e| e.to_string())?;
        Ok(Self::Shadowsocks{
            method: url.username().to_string(),
            password: url.password().ok_or("Missing password")?.to_string(),
            host: url.host_str().ok_or("Missing host")?.to_string(),
            port: url.port().ok_or("Missing port")?,
            plugin: url.query_pairs().find(|(k, _)| k == "plugin").map(|(_, v)| v.to_string()),
            plugin_opts: url.query_pairs().find(|(k, _)| k == "plugin-opts").map(|(_, v)| v.to_string()),
        })
        
    }
    fn parse_vmess(data: &str) -> Result<Self, String> {
        let decoded = general_purpose::STANDARD.decode(data).map_err(|e| e.to_string())?;
        let vmess: Value = serde_json::from_slice(&decoded).map_err(|e| e.to_string())?;
        
        let mut query = vmess.as_object()
            .ok_or("Invalid vmess format")?
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
            .collect::<HashMap<String, String>>();

        //parse query params 
        
        let port = vmess["port"].as_u64().ok_or("Missing port")? as u16;

        Ok(Self::Vmess {
            uuid: vmess["id"].as_str().ok_or("Missing UUID")?.to_string(),
            host: vmess["add"].as_str().ok_or("Missing host")?.to_string(),
            port,
            alter_id: vmess["aid"].as_str().unwrap_or("0").to_string(),
            security: vmess["security"].as_str().unwrap_or("auto").to_string(),
            transport: parse_transport(&mut query),
            tls: parse_tls(&mut query),
        })
    }

    fn parse_vless(data: &str) -> Result<Self, String> {
        let url = Url::parse(&format!("vless://{}", data)).map_err(|e| e.to_string())?;
        let mut query = url.query_pairs()
            .into_owned()
            .collect::<HashMap<String, String>>();
        
        Ok(Self::Vless {
            uuid: url.username().to_string(),
            host: url.host_str().ok_or("Missing host")?.to_string(),
            port: url.port().ok_or("Missing port")?,
            flow: query.remove("flow").map(|v| v.to_string()),
            encryption: query
                .remove("encryption")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string()),
            transport: parse_transport(&mut query),
            tls: parse_tls(&mut query),
        })
    }

    fn parse_trojan(data: &str) -> Result<Self, String> {
        let url = Url::parse(&format!("trojan://{}", data)).map_err(|e| e.to_string())?;
        let mut query = url.query_pairs()
            .into_owned()
            .collect::<HashMap<String, String>>();
        Ok(Self::Trojan {
            password: url.username().to_string(),
            host: url.host_str().ok_or("Missing host")?.to_string(),
            port: url.port().ok_or("Missing port")?,
            transport: parse_transport(&mut query),
            tls: parse_tls(&mut query),
        })
    }

    fn parse_wireguard(data: &str) -> Result<Self, String> {
        let url = Url::parse(&format!("wg://{}", data)).map_err(|e| e.to_string())?;
        let query = url.query_pairs().collect::<HashMap<_, _>>();
        
        Ok(Self::Wireguard {
            private_key: url.username().to_string(),
            public_key: query.get("pubkey").ok_or("Missing public key")?.to_string(),
            endpoint: format!(
                "{}:{}",
                url.host_str().ok_or("Missing host")?,
                url.port().ok_or("Missing port")?
            ),
        })
    }


    fn to_singbox_outbound(&self) -> Value {
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
                //plugin
                //plugin opts
            });
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
                encryption,
                transport,
                tls
            } => {
                let mut config = json!({
                    "type": "vless",
                    "tag" : "vless-out",
                    "server": host,
                    "server_port": port,
                    "uuid": uuid,
                    "encryption": encryption,
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
            } => {
                let mut config = json!({
                    "type": "wireguard",
                    "interface": {
                        "private_key": private_key,
                    },
                    "peer": {
                        "public_key": public_key,
                        "endpoint": endpoint
                    }
                });
                config
            }
        }
    }
    
}



fn parse_transport(query: &mut HashMap<String, String>) -> TransportConfig {
    let mut transport = TransportConfig {
        network: query.remove("type").unwrap_or_else(|| "tcp".to_string()),
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
                "headers": self.headers
            }),
            "http" => json!({
                "type": "http",
                "path": self.path,
                "host": self.host
            }),
            "quic" => json!({
                "type": "quic",
                "security": self.quic_security,
                "key": self.key
            }),
            "grpc" => json!({
                "type": "grpc",
                "service_name": self.service_name
            }),
            "httpupgrade" => json!({
                "type": "httpupgrade",
                "host": self.host,
                "path": self.path
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
                "public_key": reality.public_key,
                "short_id": reality.short_id
            });
        }

        config
    }
}







#[tokio::main]
async fn main() {
    let uri = [
        "vless://1bb5b0c6-87c7-4e22-b95b-bb82bd88ba53@purina.rs:443?encryption=none&security=tls&sni=purina.rs&alpn=h2&fp=chrome&type=ws&host=OpacityAvenueRakingDropout.com&path=ws%2F%3Fed%3D2048#%40ip_routes",
        "vmess://eyJhZGQiOiJzaHN1cy4yNTY3MDkzOTQueHl6IiwiYWlkIjowLCJob3N0Ijoic2hzdXMuMjU2NzA5Mzk0Lnh5eiIsImlkIjoiN2E4ZWMwNDctNjYyYi00YTlmLWI4OWYtZmQ3ZDk3ZWNhOTBmIiwibmV0Ijoid3MiLCJwYXRoIjoiXC9SVnI4QUxGQnNnVGZCQyIsInBvcnQiOjQ0MywicHMiOiJcdTI2OWNcdWZlMGZUZWxlZ3JhbTpASVBfQ0YiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiYXV0byIsInNlY3VyaXR5IjoiYXV0byIsInNraXAtY2VydC12ZXJpZnkiOnRydWUsInNuaSI6IiJ9",
        "trojan://0ab6c98dae3b48e8b9c4a776b6c9c19a@139.59.119.143:443?security=tls&headerType=none&type=tcp&sni=connectwithemployers.online#⚜️Telegram:@IP_CF"
    ];
    for u in &uri {
        match u.parse::<Protocol>() {
            Ok(protocol) => println!("{}", protocol.to_singbox_outbound()),
            Err(e) => eprintln!("Failed to parse {}: {}", u, e),

        }
    }
}
