use crate::db::flush_batch;
use crate::models::TlsFingerprint;
use tokio::sync::mpsc::Receiver;

pub async fn process_batches(pool: sqlx::MySqlPool, mut rx: Receiver<TlsFingerprint>) {
    let batch_size = 100;
    let mut buffer = Vec::with_capacity(batch_size);
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(50));

    loop {
        tokio::select! {
            Some(fingerprint) = rx.recv() => {
                buffer.push(fingerprint);
                if buffer.len() >= batch_size {
                    let b = std::mem::replace(&mut buffer, Vec::with_capacity(batch_size));
                    let p = pool.clone();
                    tokio::spawn(async move { let _ = flush_batch(&p, b).await; });
                }
            }
            _ = interval.tick() => {
                if !buffer.is_empty() {
                    let b = std::mem::replace(&mut buffer, Vec::with_capacity(batch_size));
                    let p = pool.clone();
                    tokio::spawn(async move { let _ = flush_batch(&p, b).await; });
                }
            }
        }
    }
}
