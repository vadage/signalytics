use crate::db::flush_batch;
use crate::models::TlsFingerprint;
use tokio::sync::mpsc::Receiver;
use tracing::error;

const BATCH_SIZE: usize = 1000;

async fn flush(pool: &sqlx::MySqlPool, buffer: &mut Vec<TlsFingerprint>) {
    let batch = std::mem::replace(buffer, Vec::with_capacity(BATCH_SIZE));
    if let Err(e) = flush_batch(pool, batch).await {
        error!(error = ?e, "Failed to flush batch");
    }
}

pub async fn process_batches(pool: sqlx::MySqlPool, mut rx: Receiver<TlsFingerprint>) {
    let mut buffer = Vec::with_capacity(BATCH_SIZE);
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

    loop {
        tokio::select! {
            Some(fingerprint) = rx.recv() => {
                buffer.push(fingerprint);
                if buffer.len() >= BATCH_SIZE {
                    flush(&pool, &mut buffer).await;
                    interval.reset();
                }
            }
            _ = interval.tick() => {
                if !buffer.is_empty() {
                    flush(&pool, &mut buffer).await;
                }
            }
        }
    }
}
