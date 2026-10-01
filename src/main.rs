use crate::models::TlsFingerprint;
use crate::udp_listener::run_udp_listener;
use crate::worker::process_batches;
use std::env::var as env_var;
use tracing::info;

mod db;
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
    tokio::spawn(run_udp_listener(socket, tx));

    process_batches(pool, rx).await;

    Ok(())
}
