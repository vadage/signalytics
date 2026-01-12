use serde::de::Error;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TlsFingerprint {
    pub tls_client_ciphers_sha1: String,
    pub tls_client_extensions_sha1: String,
    #[serde(deserialize_with = "from_string")]
    pub tls_client_hello_length: i64,
}

fn from_string<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = String::deserialize(deserializer)?;
    value
        .parse::<T>()
        .map_err(|e| D::Error::custom(format!("Failed to parse '{value}': {e}")))
}
