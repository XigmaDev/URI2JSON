use serde_json::{json, Value};

#[derive(Debug)]
pub struct RealityConfig {
    pub public_key: String,
    pub short_id: String,
}


#[derive(Debug)]
pub struct UTlsConfig {
    pub enabled: bool,
    pub fingerprint: String,
}


#[derive(Debug, Default)]
pub struct TlsConfig{
    pub enabled: bool,
    pub insecure: bool,
    pub sni: Option<String>,
    pub alpn:Vec<String>,
    pub utls: Option<UTlsConfig>,
    pub reality: Option<RealityConfig>,
}



impl TlsConfig {
    pub fn to_config(&self) -> Value {
        let mut config = json!({
            "enabled": self.enabled,
            "server_name": self.sni,
            "alpn": self.alpn,
            "insecure": false,
        });

        if let Some(utls) = &self.utls {
            config["utls"] = json!({
                "enabled": true,
                "fingerptint": utls.fingerprint,
            });
        }

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

