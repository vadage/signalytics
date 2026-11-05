use crate::cleanup::run_cleanup;
use crate::client::derive_key;
use crate::http::run_http_server;
use crate::models::TlsFingerprint;
use crate::udp_listener::run_udp_listener;
use crate::worker::process_batches;
use anyhow::Context;
use std::env::var as env_var;
use tracing::{info, warn};

mod cleanup;
mod client;
mod db;
mod http;
mod models;
mod parser;
mod udp_listener;
mod worker;

const DEFAULT_LOG_LEVEL: &str = "info";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let log_level = env_var("LOG_LEVEL").unwrap_or_else(|_| DEFAULT_LOG_LEVEL.into());
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(log_level)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    let database_url = match env_var("DATABASE_URL_FILE") {
        Ok(path) => std::fs::read_to_string(path)?.trim().into(),
        Err(_) => env_var("DATABASE_URL")?,
    };

    let prefix_hash_secret = match env_var("PREFIX_HASH_KEY_FILE") {
        Ok(path) => Some(std::fs::read_to_string(path)?.trim().to_owned()),
        Err(_) => env_var("PREFIX_HASH_KEY").ok(),
    };
    let prefix_hash_key = prefix_hash_secret
        .filter(|secret| !secret.is_empty())
        .map(|secret| derive_key(&secret));
    if prefix_hash_key.is_none() {
        warn!("PREFIX_HASH_KEY is not set, client counting is disabled");
    }

    let retention_days = match env_var("RETENTION_DAYS") {
        Ok(days) => Some(days.parse::<u32>().context("Invalid RETENTION_DAYS")?),
        Err(_) => None,
    };

    info!("Connecting to database");
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await?;

    info!("Running migrations...");
    sqlx::migrate!().run(&pool).await?;
    info!("Migrations complete");

    let (tx, rx) = tokio::sync::mpsc::channel::<TlsFingerprint>(20_000);

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:9000").await?;
    info!(addr = ?socket.local_addr()?, "Listening for UDP packets");
    tokio::spawn(run_udp_listener(socket, tx, prefix_hash_key));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9000").await?;
    info!(addr = ?listener.local_addr()?, "Listening for HTTP requests");
    tokio::spawn(run_http_server(listener, pool.clone(), retention_days));

    if let Some(days) = retention_days {
        tokio::spawn(run_cleanup(pool.clone(), days));
    }

    process_batches(pool, rx).await;

    Ok(())
}
