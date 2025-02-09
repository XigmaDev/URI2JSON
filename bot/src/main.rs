mod text;
mod utils;

use chrono::Local;
use serde_json::json;
use singbox::config;
use singbox::error::ConversionError;
use singbox::protocol::Protocol;
use std::path::PathBuf;
use teloxide::{
    dispatching::{
        dialogue::{self, GetChatId, InMemStorage},
        UpdateHandler,
    },
    prelude::*,
    types::{InlineKeyboardButton, InlineKeyboardMarkup, InputFile},
    utils::command::BotCommands,
};

type MyDialogue = Dialogue<State, InMemStorage<State>>;
type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

#[derive(Clone, Default)]
pub enum State {
    #[default]
    Sing,
    ReceiveURI,
    ReceiveInboundType,
    ReceiveCountryGeoType,
    ReceiveConfigType,
}

#[derive(BotCommands, Clone)]
#[command(rename_rule = "lowercase")]
enum Command {
    Help,
    Start,
    Sing,
    Cancel,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    pretty_env_logger::init();
    log::info!("Starting Uri2Json bot...");

    let bot = Bot::from_env();

    Dispatcher::builder(bot, schema())
        .dependencies(dptree::deps![InMemStorage::<State>::new()])
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
}

fn schema() -> UpdateHandler<Box<dyn std::error::Error + Send + Sync + 'static>> {
    use dptree::case;

    let command_handler = teloxide::filter_command::<Command, _>()
        .branch(case![State::Sing].branch(case![Command::Sing].endpoint(sing)))
        .branch(case![Command::Cancel].endpoint(cancel))
        .branch(case![Command::Help].endpoint(help))
        .branch(case![Command::Start].endpoint(start));

    let message_handler = Update::filter_message()
        .branch(command_handler)
        .branch(case![State::Sing].endpoint(receive_uri))
        .branch(dptree::endpoint(invalid_state));

    let callback_query_handler = Update::filter_callback_query()
        .branch(case![State::ReceiveConfigType].endpoint(receive_config_type))
        .branch(case![State::ReceiveInboundType].endpoint(receive_inbound_type))
        .branch(case![State::ReceiveCountryGeoType].endpoint(receive_country_geo_type));

    dialogue::enter::<Update, InMemStorage<State>, State, _>()
        .branch(message_handler)
        .branch(callback_query_handler)
}

async fn sing(bot: Bot, dialogue: MyDialogue, msg: Message) -> HandlerResult {
    bot.send_message(msg.chat.id, text::SING_START_DESC.to_string())
        .await?;
    dialogue.update(State::ReceiveURI).await?;
    Ok(())
}

pub async fn start(bot: Bot, msg: Message) -> HandlerResult {
    bot.send_message(msg.chat.id, text::START_WELCOME_MESSAGE.to_string())
        .parse_mode(teloxide::types::ParseMode::MarkdownV2)
        .await?;
    let scapedtext = utils::escape_markdown_v2(&utils::help_message());
    bot.send_message(msg.chat.id, scapedtext)
        .parse_mode(teloxide::types::ParseMode::MarkdownV2)
        .await?;
    Ok(())
}

pub async fn help(bot: Bot, msg: Message) -> HandlerResult {
    let scapedtext = utils::escape_markdown_v2(&utils::help_message());
    bot.send_message(msg.chat.id, scapedtext)
        .parse_mode(teloxide::types::ParseMode::MarkdownV2)
        .await?;
    Ok(())
}

async fn cancel(bot: Bot, dialogue: MyDialogue, msg: Message) -> HandlerResult {
    bot.send_message(msg.chat.id, text::CANCEL_MESSAGE).await?;
    dialogue.exit().await?;
    Ok(())
}

async fn invalid_state(bot: Bot, msg: Message) -> HandlerResult {
    bot.send_message(
        msg.chat.id,
        "Unable to handle the message. Type /help to see the usage.",
    )
    .await?;
    Ok(())
}

async fn receive_uri(bot: Bot, dialogue: MyDialogue, msg: Message) -> HandlerResult {
    match msg.text().map(ToOwned::to_owned) {
        Some(uri) => {
            let config_types = ["SingBox", "Xray"]
                .map(|config_type| InlineKeyboardButton::callback(config_type, config_type));

            bot.send_message(msg.chat.id, "Select a Config Type:")
                .reply_markup(InlineKeyboardMarkup::new([config_types]))
                .await?;
            dialogue.update(State::ReceiveConfigType).await?;
        }
        None => {
            bot.send_message(msg.chat.id, "Please, send me your sing-box/xray uri")
                .await?;
        }
    }
    Ok(())
}

async fn receive_inbound_type(bot: Bot, dialogue: MyDialogue, msg: Message) -> HandlerResult {
    match msg.text().map(ToOwned::to_owned) {
        Some(uri) => {
            let inbounds =
                ["Mixed", "TUN"].map(|inbound| InlineKeyboardButton::callback(inbound, inbound));

            bot.send_message(msg.chat.id, "Select a Inbound Type:")
                .reply_markup(InlineKeyboardMarkup::new([inbounds]))
                .await?;
            dialogue.update(State::ReceiveCountryGeoType).await?;
        }
        None => {
            bot.send_message(msg.chat.id, "Please, send me your sing-box/xray uri")
                .await?;
        }
    }
    Ok(())
}

async fn receive_country_geo_type(bot: Bot, dialogue: MyDialogue, msg: Message) -> HandlerResult {
    match msg.text().map(ToOwned::to_owned) {
        Some(uri) => {
            let countrys =
                ["Mixed", "TUN"].map(|country| InlineKeyboardButton::callback(country, country));

            bot.send_message(msg.chat.id, "Select a Inbound Type:")
                .reply_markup(InlineKeyboardMarkup::new([countrys]))
                .await?;
            dialogue.update(State::ReceiveConfigType).await?;
        }
        None => {
            bot.send_message(msg.chat.id, "Please, send me your sing-box/xray uri")
                .await?;
        }
    }
    Ok(())
}

async fn receive_config_type(
    bot: Bot,
    dialogue: MyDialogue,
    uri: String,
    q: CallbackQuery,
    msg: Message,
) -> HandlerResult {
    if let Some(config_type) = &q.data {
        if config_type == "SingBox" {
            bot.send_message(msg.chat.id, "Config");
        } else {
            bot.send_message(msg.chat.id, "❌ Error: Unsupported config type")
                .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                .await?;
        }
    }
    Ok(())
}

pub async fn handle_sing(bot: Bot, msg: Message, uri: String) -> ResponseResult<()> {
    match process_uri(&uri).await {
        Ok(filename) => {
            let file = InputFile::file(PathBuf::from(&filename));
            bot.send_document(msg.chat.id, file).await?;
            utils::cleanup_file(&filename).await;
        }
        Err(e) => {
            bot.send_message(msg.chat.id, format!("❌ Error: {}", e))
                .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                .await?;
        }
    }
    Ok(())
}

async fn process_uri(uri: &str) -> Result<String, ConversionError> {
    let version = "1.11.0".to_string();

    let protocol = Protocol::parse_uri(uri)?;

    let mut config = match config::SingBoxConfig::new(version.clone()) {
        Ok(config) => config,
        Err(e) => return Err(ConversionError::Other(e.to_string())),
    };
    config.set_log_level("info");
    config.add_dns_server("tls", "8.8.8.8", Some("google"), None);
    config.add_dns_server("", "223.5.5.5", Some("local"), Some("direct"));
    config.add_dns_rule("any", "local");

    config.add_mixed_inbound();
    config.add_tun_inbound();
    if let Err(e) = config.add_outbound(protocol) {
        eprintln!("Failed to add outbound: {}", e);
    }
    config.set_route(
        json!([
            {
                "inbound": [
                    "tun-in",
                    "mixed-in"
                ],
                "source_ip_cidr": [
                    "172.18.0.1/32",
                    "fdfe:dcba:9876::1/126"
                ],
                "ip_cidr": [
                    "172.18.0.2/32"
                ],
                "protocol": "dns",
                "outbound": "dns-out"
            },
            {
                "rule_set": [
                    "geosite-category-public-tracker",
                    "geosite-category-ads",
                    "geosite-category-ads-all",
                    "geosite-google-ads"
                ],
                "outbound": "block"
            },
            {
                "inbound": [
                    "mixed-in",
                    "tun-in"
                ],
                "outbound": "direct"
            }
        ]),
        json!([
            {
                "type": "remote",
                "format": "binary",
                "tag": "geosite-category-ads-all",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
                "download_detour": "direct",
                "update_interval": "1d"
            },
            {
                "type": "remote",
                "format": "binary",
                "tag": "geosite-google-ads",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google-ads.srs",
                "download_detour": "direct",
                "update_interval": "1d"
            },
            {
                "type": "remote",
                "format": "binary",
                "tag": "geosite-category-ads",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads.srs",
                "download_detour": "direct",
                "update_interval": "1d"
            },
            {
                "tag": "geosite-category-public-tracker",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-public-tracker.srs",
                "download_detour": "direct",
                "update_interval": "1d"
            }
        ])
    );
    config.add_default_experimental();

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("singbox_config_{}.json", timestamp);

    if let Err(e) = config.save_to_file(&filename) {
        eprintln!("Failed to save config to '{}': {}", filename, e);
    }

    Ok(filename)
}
