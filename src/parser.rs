use crate::models::TlsFingerprint;

pub fn parse_fingerprint(buf: &[u8]) -> anyhow::Result<TlsFingerprint> {
    let input = std::str::from_utf8(buf)?;
    let payload = syslog_loose::parse_message(input, syslog_loose::Variant::Either);
    let msg = payload.msg;

    let fingerprint = serde_json::from_str(msg)?;
    Ok(fingerprint)
}
