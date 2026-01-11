use crate::models::TlsFingerprint;
use crate::parser::parse_fingerprint;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info, warn};

pub async fn run_upd_listener(tx: Sender<TlsFingerprint>) {
    let mut buf = [0u8; 1024];
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:9000").await.unwrap();
    info!(addr = ?socket.local_addr().unwrap(), "Listening for UDP packets");

    loop {
        let (len, _addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                warn!(error = ?e, "Error receiving UDP packet, continuing");
                continue;
            }
        };

        let fingerprint: TlsFingerprint = match parse_fingerprint(&buf[..len]) {
            Ok(fingerprint) => fingerprint,
            Err(e) => {
                debug!(error = ?e, "Failed to parse fingerprint, skipping packet");
                continue;
            }
        };

        if let Err(e) = tx.try_send(fingerprint) {
            error!(error = ?e, "Channel full, dropping fingerprint");
        }
    }
}
