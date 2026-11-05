use std::net::IpAddr;

pub fn derive_key(secret: &str) -> [u8; 32] {
    blake3::derive_key("signalytics client prefix", secret.as_bytes())
}

pub fn prefix_hash(key: &[u8; 32], ip: &str) -> Option<[u8; 8]> {
    let prefix = match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(ip) => ip.octets()[..3].to_vec(),
        IpAddr::V6(ip) => ip.octets()[..6].to_vec(),
    };

    let hash = blake3::keyed_hash(key, &prefix);
    hash.as_bytes()[..8].try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        derive_key("secret")
    }

    #[test]
    fn test_prefix_hash_same_ipv4_prefix() {
        assert_eq!(
            prefix_hash(&key(), "203.0.113.1"),
            prefix_hash(&key(), "203.0.113.200")
        );
        assert!(prefix_hash(&key(), "203.0.113.1").is_some());
    }

    #[test]
    fn test_prefix_hash_different_ipv4_prefix() {
        assert_ne!(
            prefix_hash(&key(), "203.0.113.1"),
            prefix_hash(&key(), "203.0.114.1")
        );
    }

    #[test]
    fn test_prefix_hash_same_ipv6_prefix() {
        assert_eq!(
            prefix_hash(&key(), "2001:db8:1::1"),
            prefix_hash(&key(), "2001:db8:1:ffff::2")
        );
        assert!(prefix_hash(&key(), "2001:db8:1::1").is_some());
    }

    #[test]
    fn test_prefix_hash_different_ipv6_prefix() {
        assert_ne!(
            prefix_hash(&key(), "2001:db8:1::1"),
            prefix_hash(&key(), "2001:db8:2::1")
        );
    }

    #[test]
    fn test_prefix_hash_invalid() {
        assert_eq!(prefix_hash(&key(), ""), None);
        assert_eq!(prefix_hash(&key(), "not an ip"), None);
    }

    #[test]
    fn test_prefix_hash_depends_on_key() {
        assert_ne!(
            prefix_hash(&key(), "203.0.113.1"),
            prefix_hash(&derive_key("other"), "203.0.113.1")
        );
    }
}
