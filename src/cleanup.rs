use crate::db::delete_expired;
use sqlx::MySqlPool;
use std::time::Duration;
use tracing::{error, info};

pub async fn run_cleanup(pool: MySqlPool, retention_days: u32) {
    let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));

    loop {
        interval.tick().await;
        match delete_expired(&pool, retention_days).await {
            Ok(rows) => info!(rows, retention_days, "Deleted expired daily rows"),
            Err(e) => error!(error = ?e, "Failed to delete expired daily rows"),
        }
    }
}
