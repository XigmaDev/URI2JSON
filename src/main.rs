use std::{collections::HashMap, str::FromStr};

use serde_json::{json, Value};
use url::Url;

#[derive(Debug)]
enum Protocol {
    Shadowsocks{
        method: String,
        password: String,
        host: String,
        port: u16,
    },
    Vmess{
        uuid: String,
        host: String,
        port: u16,
        alter_id: String,
        security: String,
    },
    Vless{
        uuid: String,
        host: String,
        port: u16,
        flow: Option<String>,
        encryption: String,
    },
    Trojan{
        password: String,
        host: String,
        port: u16,
    },
    Wireguard{
        private_key: String,
        public_key: String,
        endpoint: String,
    },
    
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
        })
        
    }
    fn parse_vmess(data: &str) -> Result<Self, String> {
        let decoded = base64::decode(data).map_err(|e| e.to_string())?;
        let vmess: Value = serde_json::from_slice(&decoded).map_err(|e| e.to_string())?;
        
        Ok(Self::Vmess {
            uuid: vmess["id"].as_str().ok_or("Missing UUID")?.to_string(),
            host: vmess["add"].as_str().ok_or("Missing host")?.to_string(),
            port: vmess["port"].as_u64().ok_or("Missing port")? as u16,
            alter_id: vmess["aid"].as_str().unwrap_or("0").to_string(),
            security: vmess["security"].as_str().unwrap_or("auto").to_string(),
        })
    }

    fn parse_vless(data: &str) -> Result<Self, String> {
        let url = Url::parse(&format!("vless://{}", data)).map_err(|e| e.to_string())?;
        let mut query = url.query_pairs().collect::<HashMap<_, _>>();
        
        Ok(Self::Vless {
            uuid: url.username().to_string(),
            host: url.host_str().ok_or("Missing host")?.to_string(),
            port: url.port().ok_or("Missing port")?,
            flow: query.remove("flow").map(|v| v.to_string()),
            encryption: query
                .remove("encryption")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string()),
        })
    }

    fn parse_trojan(data: &str) -> Result<Self, String> {
        let url = Url::parse(&format!("trojan://{}", data)).map_err(|e| e.to_string())?;
        Ok(Self::Trojan {
            password: url.username().to_string(),
            host: url.host_str().ok_or("Missing host")?.to_string(),
            port: url.port().ok_or("Missing port")?,
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
            Ok(protocol) => println!("{:?}", protocol),
            Err(e) => eprintln!("Failed to parse {}: {}", u, e),
        }
    }
}
