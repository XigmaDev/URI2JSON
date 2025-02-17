mod utils;

use chrono::Local;
use singbox::config;
use singbox::error::ConversionError;
use singbox::protocol::Protocol;
use std::path::PathBuf;
use teloxide::{prelude::*, types::InputFile, types::Message, utils::command::BotCommands};

extern crate pretty_env_logger;

extern crate log;

#[derive(BotCommands, Clone)]
#[command(rename_rule = "lowercase")]
#[command(description = "Commands:")]
enum Command {
    #[command(description = "Start")]
    Start,
    #[command(description = "Help")]
    Help,
    #[command(description = "Process singbox URI - /singbox <version> <URI>")]
    Singbox(String),
    #[command(description = "Xray Comming Soon")]
    Xray,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    pretty_env_logger::init();
    log::info!("Starting Uri2Json bot...");

    let bot = Bot::from_env();
    bot.set_my_commands(Command::bot_commands())
        .await
        .expect("Failed to set commands");

    let handler = Update::filter_message()
        .filter_command::<Command>()
        .endpoint(schema);

    Dispatcher::builder(bot, handler)
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
}

async fn schema(
    bot: Bot,
    msg: Message,
    cmd: Command,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cmd {
        Command::Singbox(args) => {
            let parts: Vec<&str> = args.splitn(3, ' ').collect();

            if parts.len() < 2 {
                bot.send_message(
                    msg.chat.id,
                    "Invalid format. Use /singbox <version> <URI>\nSupported versions: 1.11.0, 1.12.0",
                )
                .await?;
                return Ok(());
            }
            let version = parts[0];
            let uri = parts[1];

            if !["1.11.0", "1.12.0"].contains(&version) {
                bot.send_message(
                    msg.chat.id,
                    "Unsupported version. Currently supported: 1.11.0, 1.12.0",
                )
                .await?;
                return Ok(());
            }

            if uri.is_empty() {
                bot.send_message(msg.chat.id, "URI cannot be empty").await?;
                return Ok(());
            }

            if !utils::is_valid_uri(uri) {
                bot.send_message(msg.chat.id, "❌ Invalid URI").await?;
                return Ok(());
            }

            match process_uri(version, uri).await {
                Ok(filename) => {
                    let file = InputFile::file(PathBuf::from(&filename));
                    bot.send_document(msg.chat.id, file).await?;
                    utils::cleanup_file(&filename).await;
                }
                Err(e) => {
                    bot.send_message(msg.chat.id, format!("❌ Error processing URI:: {}", e))
                        .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                        .await?;
                }
            }
        }

        Command::Start => {
            let scapedtext = utils::escape_markdown_v2(&utils::welcome_message());
            bot.send_message(msg.chat.id, scapedtext)
                .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                .await?;
        }
        Command::Help => {
            let scapedtext = utils::escape_markdown_v2(&utils::help_message());
            bot.send_message(msg.chat.id, scapedtext)
                .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                .await?;
        }
        Command::Xray => {
            let scapedtext =
                utils::escape_markdown_v2("🚧 Xray support is coming soon. Stay tuned!");
            bot.send_message(msg.chat.id, scapedtext)
                .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                .await?;
        }
    }
    Ok(())
}

async fn process_uri(version: &str, uri: &str) -> Result<String, ConversionError> {
    let protocol = Protocol::parse_uri(uri)?;

    let mut config = match config::SingBoxConfig::new(version.to_string().clone()) {
        Ok(config) => config,
        Err(e) => return Err(ConversionError::Other(e.to_string())),
    };
    config.set_log_level("error");
    config.set_ntp();
    config.add_dns_server("tls", "1.1.1.1", Some("cf"), None, Some("local"));
    config.add_dns_server("", "223.5.5.5", Some("local"), Some("direct"), None);

    config.add_mixed_inbound();
    config.add_tun_inbound();
    if let Err(e) = config.add_outbound(protocol) {
        eprintln!("Failed to add outbound: {}", e);
    }
    config.set_route();
    config.add_default_experimental();

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("singbox_config_{}.json", timestamp);

    if let Err(e) = config.save_to_file(&filename) {
        eprintln!("Failed to save config to '{}': {}", filename, e);
    }

    Ok(filename)
}
