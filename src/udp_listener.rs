use crate::models::TlsFingerprint;
use crate::parser::parse_fingerprint;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, warn};

pub async fn run_udp_listener(socket: UdpSocket, tx: Sender<TlsFingerprint>) {
    let mut buf = [0u8; 4096];

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
