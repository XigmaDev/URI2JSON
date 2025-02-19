use singbox::config;
use singbox::protocol::Protocol;

#[tokio::main]
async fn main() {
    let version = "1.12.0".to_string();

    let uris = [
        "vless://c39d34d1-8723-42fd-a63d-1c857c76249a@80.240.112.94:443?encryption=none&security=reality&sni=www.google.com&fp=chrome&pbk=mD8V76JrLVJQrQXtyNVgcqwptE9PzcF8nEJe3MyhTDY&sid=f0db85b11110c6&spx=%2Fsearch%3Fq%3Dnews&type=tcp&headerType=none&host=v2line.t.me#%40ip_routes",
        "vmess://eyJhZGQiOiJzaHN1cy4yNTY3MDkzOTQueHl6IiwiYWlkIjowLCJob3N0Ijoic2hzdXMuMjU2NzA5Mzk0Lnh5eiIsImlkIjoiN2E4ZWMwNDctNjYyYi00YTlmLWI4OWYtZmQ3ZDk3ZWNhOTBmIiwibmV0Ijoid3MiLCJwYXRoIjoiXC9SVnI4QUxGQnNnVGZCQyIsInBvcnQiOjQ0MywicHMiOiJcdTI2OWNcdWZlMGZUZWxlZ3JhbTpASVBfQ0YiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiYXV0byIsInNlY3VyaXR5IjoiYXV0byIsInNraXAtY2VydC12ZXJpZnkiOnRydWUsInNuaSI6IiJ9",
    ];

    for uri in uris {
        match Protocol::parse_uri(uri) {
            Ok(protocol) => {
                let mut config = match config::SingBoxConfig::new(version.clone()) {
                    // Replace with actual version
                    Ok(config) => config,
                    Err(e) => {
                        eprintln!("Failed to create config: {}", e);
                        continue;
                    }
                };
                config.set_log_level("info");
                config.add_dns_server("tls", "8.8.8.8", Some("google"), None, None);
                config.add_dns_server("", "223.5.5.5", Some("local"), Some("direct"), None);
                config.add_dns_rule("any", "local");

                config.add_mixed_inbound();
                config.add_tun_inbound();

                if let Err(e) = config.add_outbound(protocol) {
                    eprintln!("Failed to add outbound: {}", e);
                    continue;
                }
                config.set_route();
                config.add_default_experimental();

                let filename = format!(
                    "GeneratedConfig/config_{}.json",
                    chrono::Local::now().format("%Y%m%d%H%M%S")
                );

                if let Err(e) = config.save_to_file(&filename) {
                    eprintln!("Failed to save config to '{}': {}", filename, e);
                }
            }
            Err(e) => {
                eprintln!("Failed to parse URI '{}': {}", uri, e);
            }
        }
    }
}
