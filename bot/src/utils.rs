use std::time::Duration;
use tokio::{fs, time};

pub fn welcome_message() -> String {
    r#"
🎉 Welcome to the URI to JSON Bot!

I'm here to help you Convert URI into JSON configurations compatible with SingBox and Xray.

📋 Available Commands:

- /start — Show this welcome message
- /help — Display all available commands
- /singbox <version> <URI> — Process a URI for a specific version
🔍 Supported Versions:

- 1.11.0
- 1.12.0

🚀 Coming Soon:
 - /xray command

Beta Notice:
"We're currently in beta! If you encounter any issues or have feedback, please let us know.
@ip_routes_admin
We appreciate your support!"
    "#
    .trim()
    .replace("    ", "")
    .to_string()
}

pub fn help_message() -> String {
    r#"
    📋 Available commands:
            /start - Show this welcome message
            /help - Show available commands
            /singbox <version> <URI> - Process URI for specific version
    🔍 Supported versions: 1.11.0, 1.12.0
    
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

pub fn is_valid_uri(uri: &str) -> bool {
    uri.starts_with("ss://")
        || uri.starts_with("vless://")
        || uri.starts_with("vmess://")
        || uri.starts_with("wg://")
        || uri.starts_with("trojan://")
        || uri.starts_with("wireguard://")
}
