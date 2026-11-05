use crate::models::LogLine;

pub fn parse_fingerprint(buf: &[u8]) -> anyhow::Result<LogLine> {
    let input = std::str::from_utf8(buf)?;
    let payload = syslog_loose::parse_message(input, syslog_loose::Variant::Either);
    let msg = payload.msg;

    let fingerprint = serde_json::from_str(msg)?;
    Ok(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fingerprint_json() {
        let expected = LogLine {
            tls_client_ciphers_sha1: "GXSPDLP4G3X+prK73a4wBuOaHRc=".into(),
            ..Default::default()
        };
        let input = br#"
        {
            "tls_client_ciphers_sha1": "GXSPDLP4G3X+prK73a4wBuOaHRc=",
            "tls_client_extensions_sha1": "OWFiM2I5ZDc0YWI0YWYzZmFkMGU0ZjhlYjhiYmVkMjgxNTU5YTU2Mg==",
            "tls_client_hello_length": "508"
        }
        "#;

        let actual = parse_fingerprint(input).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parse_fingerprint_rfc_3164() {
        let expected = LogLine {
            tls_client_ciphers_sha1: "GXSPDLP4G3X+prK73a4wBuOaHRc=".into(),
            ..Default::default()
        };
        let input = br#"
        <134>Jan 12 12:34:56 localhost nginx:
        {
            "tls_client_ciphers_sha1": "GXSPDLP4G3X+prK73a4wBuOaHRc=",
            "tls_client_extensions_sha1": "OWFiM2I5ZDc0YWI0YWYzZmFkMGU0ZjhlYjhiYmVkMjgxNTU5YTU2Mg==",
            "tls_client_hello_length": "508"
        }
        "#;

        let actual = parse_fingerprint(input).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parse_fingerprint_rfc_5424() {
        let expected = LogLine {
            tls_client_ciphers_sha1: "GXSPDLP4G3X+prK73a4wBuOaHRc=".into(),
            ..Default::default()
        };
        let input = br#"
        <134>1 2026-01-12T12:34:56.789Z localhost nginx 12345 access -
        {
            "tls_client_ciphers_sha1": "GXSPDLP4G3X+prK73a4wBuOaHRc=",
            "tls_client_extensions_sha1": "OWFiM2I5ZDc0YWI0YWYzZmFkMGU0ZjhlYjhiYmVkMjgxNTU5YTU2Mg==",
            "tls_client_hello_length": "508"
        }
        "#;

        let actual = parse_fingerprint(input).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parse_fingerprint_client_fields() {
        let expected = LogLine {
            tls_client_ciphers_sha1: "GXSPDLP4G3X+prK73a4wBuOaHRc=".into(),
            client_ip: "203.0.113.1".into(),
            client_asn: "64496".into(),
            host: "example.com".into(),
        };
        let input = br#"
        {
            "tls_client_ciphers_sha1": "GXSPDLP4G3X+prK73a4wBuOaHRc=",
            "client_ip": "203.0.113.1",
            "client_asn": "64496",
            "host": "example.com"
        }
        "#;

        let actual = parse_fingerprint(input).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parse_fingerprint_invalid() {
        let input = br#"
        {
            "level": "info",
        }
        "#;

        let result = parse_fingerprint(input);

        assert!(result.is_err());
    }
}
