use crate::db::flush_batch;
use crate::models::TlsFingerprint;
use crate::parser::parse_fingerprint;
use tokio::sync::mpsc::{Receiver, Sender};

pub async fn run_upd_listener(tx: Sender<TlsFingerprint>) {
    let mut buf = [0u8; 1024];
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:9000").await.unwrap();
    println!("Listening on {}", socket.local_addr().unwrap());

    loop {
        let (len, _addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(_) => continue,
        };

        let fingerprint: TlsFingerprint = match parse_fingerprint(&buf[..len]) {
            Ok(fingerprint) => fingerprint,
            Err(_) => continue,
        };

        let _ = tx.try_send(fingerprint);
    }
}

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
