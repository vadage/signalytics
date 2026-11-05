use crate::client::prefix_hash;
use serde::Deserialize;

const MAX_HOST_LEN: usize = 255;

// Empty strings mean the web server had no value, e.g. a missing header.
#[derive(Deserialize, Debug, Default, PartialEq)]
pub struct LogLine {
    pub tls_client_ciphers_sha1: String,
    #[serde(default)]
    pub client_ip: String,
    #[serde(default)]
    pub client_asn: String,
    #[serde(default)]
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Client {
    pub prefix_hash: [u8; 8],
    pub asn: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TlsFingerprint {
    pub tls_client_ciphers_sha1: String,
    pub client: Option<Client>,
    pub host: Option<String>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(default)]
pub struct FingerprintParams {
    pub days: u32,
    pub min_days: u32,
    pub min_hits: u64,
    pub min_prefixes: u32,
    pub min_asns: u32,
    pub min_hosts: u32,
    pub limit: u32,
    pub min_count: usize,
}

impl Default for FingerprintParams {
    fn default() -> Self {
        Self {
            days: 30,
            min_days: 7,
            min_hits: 5,
            min_prefixes: 0,
            min_asns: 0,
            min_hosts: 0,
            limit: 50,
            min_count: 10,
        }
    }
}

impl LogLine {
    pub fn into_fingerprint(self, key: Option<&[u8; 32]>) -> TlsFingerprint {
        let client = key
            .and_then(|key| prefix_hash(key, &self.client_ip))
            .map(|prefix_hash| Client {
                prefix_hash,
                asn: self.client_asn.parse().ok(),
            });

        let host = self.host.trim().to_lowercase();
        let host = (!host.is_empty() && host.len() <= MAX_HOST_LEN).then_some(host);

        TlsFingerprint {
            tls_client_ciphers_sha1: self.tls_client_ciphers_sha1,
            client,
            host,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::derive_key;

    fn full_line() -> LogLine {
        LogLine {
            tls_client_ciphers_sha1: "a".into(),
            client_ip: "203.0.113.1".into(),
            client_asn: "64496".into(),
            host: " Example.COM ".into(),
        }
    }

    #[test]
    fn test_into_fingerprint_cipher_only() {
        let line = LogLine {
            tls_client_ciphers_sha1: "a".into(),
            ..Default::default()
        };
        let expected = TlsFingerprint {
            tls_client_ciphers_sha1: "a".into(),
            client: None,
            host: None,
        };
        assert_eq!(line.into_fingerprint(Some(&derive_key("k"))), expected);
    }

    #[test]
    fn test_into_fingerprint_full() {
        let key = derive_key("k");
        let fingerprint = full_line().into_fingerprint(Some(&key));
        let expected_client = Client {
            prefix_hash: prefix_hash(&key, "203.0.113.1").unwrap(),
            asn: Some(64496),
        };
        assert_eq!(fingerprint.client, Some(expected_client));
        assert_eq!(fingerprint.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_into_fingerprint_without_key() {
        assert_eq!(full_line().into_fingerprint(None).client, None);
    }

    #[test]
    fn test_into_fingerprint_invalid_asn() {
        let line = LogLine {
            client_asn: "abc".into(),
            ..full_line()
        };
        let client = line.into_fingerprint(Some(&derive_key("k"))).client;
        assert_eq!(client.unwrap().asn, None);
    }

    #[test]
    fn test_into_fingerprint_host_too_long() {
        let line = LogLine {
            host: "a".repeat(MAX_HOST_LEN + 1),
            ..full_line()
        };
        assert_eq!(line.into_fingerprint(None).host, None);
    }
}
