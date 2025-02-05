use serde_json::json;
use singbox::protocol::Protocol;
use singbox::config; 


#[tokio::main]
async fn main() {
    let version = "1.11.0".to_string(); 

    let uris = [
        "vless://c39d34d1-8723-42fd-a63d-1c857c76249a@80.240.112.94:443?encryption=none&security=reality&sni=www.google.com&fp=chrome&pbk=mD8V76JrLVJQrQXtyNVgcqwptE9PzcF8nEJe3MyhTDY&sid=f0db85b11110c6&spx=%2Fsearch%3Fq%3Dnews&type=tcp&headerType=none&host=v2line.t.me#%40ip_routes",
        //"vless://462163e1-a73f-41c5-9b6d-59fe69ec21bc@45.138.135.142:3508?encryption=none&security=none&type=tcp&headerType=none#hi-hal733jw",
        // "vmess://eyJhZGQiOiJzaHN1cy4yNTY3MDkzOTQueHl6IiwiYWlkIjowLCJob3N0Ijoic2hzdXMuMjU2NzA5Mzk0Lnh5eiIsImlkIjoiN2E4ZWMwNDctNjYyYi00YTlmLWI4OWYtZmQ3ZDk3ZWNhOTBmIiwibmV0Ijoid3MiLCJwYXRoIjoiXC9SVnI4QUxGQnNnVGZCQyIsInBvcnQiOjQ0MywicHMiOiJcdTI2OWNcdWZlMGZUZWxlZ3JhbTpASVBfQ0YiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiYXV0byIsInNlY3VyaXR5IjoiYXV0byIsInNraXAtY2VydC12ZXJpZnkiOnRydWUsInNuaSI6IiJ9",
    ];

    for uri in uris {
        match Protocol::parse_uri(uri) {
            Ok(protocol) => {
                let mut config = match config::SingBoxConfig::new(version.clone()) { // Replace with actual version
                    Ok(config) => config,
                    Err(e) => {
                        eprintln!("Failed to create config: {}", e);
                        continue;
                    }
                };
                config.set_log_level("info");
                config.add_dns_server("tls", "8.8.8.8", Some("google"), None);
                config.add_dns_server("", "223.5.5.5", Some("local"), Some("direct"));
                config.add_dns_rule("any", "local");

                config.add_default_inbound();
                
                
                if let Err(e) = config.add_outbound(protocol) {
                    eprintln!("Failed to add outbound: {}", e);
                    continue;
                }
                config.set_route(json!([{
                }]),
                    json!([{
                        "tag": "ir",
                        "type": "remote",
                        "format": "source",
                        "url": "https://gist.githubusercontent.com/z4x7k/8604b64ec25e37f0acb1c7f0c9d2a7a8/raw/ir-rule-set.json",
                        "download_detour": "direct"
                }]));

                config.add_default_experimental();

                let filename = format!("GeneratedConfig/config_{}.json",
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

