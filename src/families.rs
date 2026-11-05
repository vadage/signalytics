use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::collections::HashSet;

const FAMILIES_JSON: &str = include_str!("cipher_families.json");

// RFC 8701, section 2.
const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

#[derive(Deserialize)]
struct Family {
    name: String,
    ciphers: Vec<String>,
}

/// Returns (hash, family name) for every GREASE variant of every family.
pub fn load() -> anyhow::Result<Vec<(String, String)>> {
    parse(FAMILIES_JSON)
}

fn parse(json: &str) -> anyhow::Result<Vec<(String, String)>> {
    let families: Vec<Family> =
        serde_json::from_str(json).context("Invalid cipher families JSON")?;
    if families.is_empty() {
        bail!("No cipher families defined");
    }

    let mut names = HashSet::new();
    let mut pairs = Vec::with_capacity(families.len() * GREASE_VALUES.len());
    for family in families {
        if !names.insert(family.name.clone()) {
            bail!("Duplicate cipher family {}", family.name);
        }
        if family.ciphers.is_empty() {
            bail!("Cipher family {} has no ciphers", family.name);
        }
        let ciphers = family
            .ciphers
            .iter()
            .map(|cipher| u16::from_str_radix(cipher, 16))
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("Invalid cipher in family {}", family.name))?;

        for grease in GREASE_VALUES {
            pairs.push((hash(grease, &ciphers), family.name.clone()));
        }
    }

    Ok(pairs)
}

fn hash(grease: u16, ciphers: &[u16]) -> String {
    let mut hasher = Sha1::new();
    for value in std::iter::once(&grease).chain(ciphers) {
        hasher.update(value.to_be_bytes());
    }
    STANDARD.encode(hasher.finalize())
}

/// Replaces family names with all their hashes; sorted by hash so the result only changes when the set changes.
pub fn expand(fingerprints: Vec<String>, families: &[(String, String)]) -> Vec<String> {
    let mut hashes = Vec::new();
    for fingerprint in fingerprints {
        let before = hashes.len();
        hashes.extend(
            families
                .iter()
                .filter(|(_, name)| *name == fingerprint)
                .map(|(hash, _)| hash.clone()),
        );
        if hashes.len() == before {
            hashes.push(fingerprint);
        }
    }
    hashes.sort();
    hashes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn family_hash(name: &str, grease: u16) -> String {
        let families = serde_json::from_str::<Vec<Family>>(FAMILIES_JSON).unwrap();
        let family = families.iter().find(|f| f.name == name).unwrap();
        let ciphers: Vec<u16> = family
            .ciphers
            .iter()
            .map(|c| u16::from_str_radix(c, 16).unwrap())
            .collect();
        hash(grease, &ciphers)
    }

    #[test]
    fn test_known_hashes() {
        assert_eq!(
            family_hash("chromium", 0x0a0a),
            "pdGcErBTDt22TM3jTvj6A2k54tY="
        );
        assert_eq!(
            family_hash("chromium-tls13", 0xaaaa),
            "Kl1NzpQr5uPyKg4UM2V2PU+p6O8="
        );
        assert_eq!(
            family_hash("webkit", 0xbaba),
            "dwqq4Ws5CxH9EVsX7bwdl7KIWus="
        );
        assert_eq!(
            family_hash("webkit-tls13", 0xfafa),
            "r41uzXJdxMO1kG5HoXGHJSNyElw="
        );
        assert_eq!(
            family_hash("webkit-legacy", 0xdada),
            "vAFumPvJuT3f+HNRjb+3nlOjMZc="
        );
    }

    #[test]
    fn test_grease_values() {
        assert_eq!(GREASE_VALUES[0], 0x0a0a);
        assert_eq!(GREASE_VALUES[10], 0xaaaa);
        assert_eq!(GREASE_VALUES[15], 0xfafa);
    }

    #[test]
    fn test_load_embedded() {
        let pairs = load().unwrap();
        assert_eq!(pairs.len(), 5 * 16);
        let distinct: HashSet<_> = pairs.iter().map(|(hash, _)| hash).collect();
        assert_eq!(distinct.len(), pairs.len());
    }

    #[test]
    fn test_parse_rejects_invalid() {
        assert!(parse("[]").is_err());
        assert!(parse("not json").is_err());
        assert!(parse(r#"[{"name": "a", "ciphers": []}]"#).is_err());
        assert!(parse(r#"[{"name": "a", "ciphers": ["zzzz"]}]"#).is_err());
        assert!(
            parse(r#"[{"name": "a", "ciphers": ["1301"]}, {"name": "a", "ciphers": ["1302"]}]"#)
                .is_err()
        );
    }

    #[test]
    fn test_expand() {
        let families = vec![
            ("h1".to_owned(), "fam".to_owned()),
            ("h0".to_owned(), "fam".to_owned()),
        ];
        let input = vec!["z".to_owned(), "fam".to_owned(), "a".to_owned()];
        assert_eq!(expand(input, &families), vec!["a", "h0", "h1", "z"]);
    }
}
