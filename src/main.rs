use crate::models::TlsFingerprint;
use crate::udp_listener::run_upd_listener;
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

    info!("Connecting to database");
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(16)
        .connect(&env_var("DATABASE_URL")?)
        .await?;

    info!("Running migrations...");
    sqlx::migrate!().run(&pool).await?;
    info!("Migrations complete");

    let (tx, rx) = tokio::sync::mpsc::channel::<TlsFingerprint>(20_000);

    tokio::spawn(run_upd_listener(tx));

    process_batches(pool, rx).await;

    Ok(())
}
