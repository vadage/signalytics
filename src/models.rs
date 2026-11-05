use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TlsFingerprint {
    pub tls_client_ciphers_sha1: String,
}
