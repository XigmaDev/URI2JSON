use std::time::Duration;
use tokio::{fs, time};

pub fn help_message() -> String {
    r#"
    🚀 *SingBox Config Bot* 🚀
    
    _Convert proxy URIs to SingBox configuration files_
    
    *Commands:*
    /sing `<uri>` - Generate config from URI
    /help - Show this help message
    
    *Supported Protocols:*
    - `ss://` Shadowsocks
    - `vmess://` VMess
    - `vless://` VLESS
    - `trojan://` Trojan
    - `wg://` WireGuard
    
    *Examples:*
    `/sing ss://chacha20-ietf-poly1305:password@example.com:443`
    `/sing vmess://...`
    "#
    .trim()
    .replace("    ", "")
}

pub async fn cleanup_file(filename: &str) {
    time::sleep(Duration::from_secs(30)).await; // Keep file available for 30 seconds
    let _ = fs::remove_file(filename).await;
}
