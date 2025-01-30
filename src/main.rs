mod config;
mod error;
mod protocols;
mod utils;

use protocols::Protocol;


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

