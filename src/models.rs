use serde::Deserialize;
use serde::de::Error;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TlsFingerprint {
    pub tls_client_ciphers_sha1: String,
    pub tls_client_extensions_sha1: String,
    #[serde(deserialize_with = "from_string")]
    pub tls_client_hello_length: i64,
}

fn from_string<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <&str>::deserialize(deserializer)?;
    value
        .parse::<i64>()
        .map_err(|e| D::Error::custom(format!("Failed to parse '{value}': {e}")))
}
