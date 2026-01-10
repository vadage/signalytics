use crate::models::TlsFingerprint;
use crate::udp_listener::{process_batches, run_upd_listener};

mod db;
mod models;
mod udp_listener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Starting...");
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(16)
        .connect(&std::env::var("DATABASE_URL")?)
        .await?;

    println!("Connected to database, applying migrations.");
    sqlx::migrate!("./migrations").run(&pool).await?;

    let (tx, rx) = tokio::sync::mpsc::channel::<TlsFingerprint>(20_000);

    tokio::spawn(run_upd_listener(tx));

    process_batches(pool, rx).await;

    Ok(())
}
