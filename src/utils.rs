use tokio::fs;

pub fn help_message() -> String {
    r#"
    Supported protocols:
    - ss:// (Shadowsocks)
    - vmess:// (VMess)
    - vless:// (VLESS)
    - trojan:// (Trojan)
    - wg:// (WireGuard)

    Commands:
    /sing <uri> - Generate config and send as file

    Example URIs:
    ss://chacha20-ietf-poly1305:password@example.com:443
    wg://private_key@example.com:51820?pubkey=public_key&ip=10.0.0.2/32
    "#.trim().to_string()
}

pub async fn cleanup_file(filename: &str) {
    let _ = fs::remove_file(filename).await;
}