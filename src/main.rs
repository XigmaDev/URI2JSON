mod config;
mod error;
mod protocols;
mod utils;

use serde_json::json;

use crate::protocols::Protocol;

#[tokio::main]
async fn main() {
    let uri = [
        "vless://1bb5b0c6-87c7-4e22-b95b-bb82bd88ba53@purina.rs:443?encryption=none&security=tls&sni=purina.rs&alpn=h2&fp=chrome&type=ws&host=OpacityAvenueRakingDropout.com&path=ws%2F%3Fed%3D2048#%40ip_routes",
        "vmess://eyJhZGQiOiJzaHN1cy4yNTY3MDkzOTQueHl6IiwiYWlkIjowLCJob3N0Ijoic2hzdXMuMjU2NzA5Mzk0Lnh5eiIsImlkIjoiN2E4ZWMwNDctNjYyYi00YTlmLWI4OWYtZmQ3ZDk3ZWNhOTBmIiwibmV0Ijoid3MiLCJwYXRoIjoiXC9SVnI4QUxGQnNnVGZCQyIsInBvcnQiOjQ0MywicHMiOiJcdTI2OWNcdWZlMGZUZWxlZ3JhbTpASVBfQ0YiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiYXV0byIsInNlY3VyaXR5IjoiYXV0byIsInNraXAtY2VydC12ZXJpZnkiOnRydWUsInNuaSI6IiJ9",
        "trojan://0ab6c98dae3b48e8b9c4a776b6c9c19a@139.59.119.143:443?security=tls&headerType=none&type=tcp&sni=connectwithemployers.online#⚜️Telegram:@IP_CF"
    ];
    for u in &uri {
        match u.parse::<Protocol>() {
            Ok(protocol) => {
                let mut config = config::SingBoxConfig::new();
                config.set_log_level("info");
                
                // Add DNS servers
                config.add_dns_server("remote", "8.8.8.8", Some("prefer_ipv4"), Some("proxy"));
                config.add_dns_server("local", "223.5.5.5", Some("prefer_ipv4"), Some("direct"));
                config.add_dns_server("block", "rcode://success", None, None);

                // Add DNS rules
                config.add_dns_rule(vec!["geosite-cn", "geosite-geolocation-cn"], "local");
                config.add_dns_rule(vec!["geosite-category-ads-all"], "block");

                // Set final DNS server
                config.set_dns_final("remote");
                config.add_default_inbound();


                config.add_outbound(&protocol);        
                let filename = format!("config_{}_{}.json", protocol.get_type(), chrono::Local::now().timestamp());
                if let Err(e) = config.save_to_file(&filename) {
                    eprintln!("Failed to save config to file: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Failed to parse {}: {}", u, e);
            }
        }
    }
}

