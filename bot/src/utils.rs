use std::time::Duration;
use tokio::{fs, time};

pub fn help_message() -> String {
    r#"
    🚀 *SingBox Config Bot* 🚀
    _Convert URIs to SingBox configuration files_
    
    *Commands:*
    /sing - Generate config from URI
    /help - Show this help message
    
    *Supported Protocols:*
    - `ss://` Shadowsocks
    - `vmess://` VMess
    - `vless://` VLESS
    - `trojan://` Trojan
    - `wg://` WireGuard
    "#
    .trim()
    .replace("    ", "")
    .to_string()
}

pub async fn cleanup_file(filename: &str) {
    time::sleep(Duration::from_secs(30)).await; // Keep file available for 30 seconds
    let _ = fs::remove_file(filename).await;
}

pub fn escape_markdown_v2(text: &str) -> String {
    // Define the list of reserved MarkdownV2 characters.
    let reserved_chars: [char; 18] = [
        '_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!',
    ];

    let mut escaped = String::with_capacity(text.len());

    for ch in text.chars() {
        if reserved_chars.contains(&ch) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }

    escaped
}

fn is_valid_uri(uri: &str) -> bool {
    uri.starts_with("ss://")
        || uri.starts_with("vless://")
        || uri.starts_with("vmess://")
        || uri.starts_with("wg://")
        || uri.starts_with("trojan://")
        || uri.starts_with("wireguard://")
}
