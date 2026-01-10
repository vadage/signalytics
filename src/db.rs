use crate::models::TlsFingerprint;

pub async fn flush_batch(
    pool: &sqlx::Pool<sqlx::MySql>,
    buffer: Vec<TlsFingerprint>,
) -> anyhow::Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }

    let mut tx = pool.begin().await?;

    let values = vec!["(?, ?, ?)"; buffer.len()];
    let sql = format!(
        "INSERT INTO tls_fingerprints (tls_client_ciphers_sha1, tls_client_extensions_sha1, tls_client_hello_length) VALUES {} ON DUPLICATE KEY UPDATE hit_count = hit_count + 1, last_seen = CURRENT_TIMESTAMP",
        values.join(", ")
    );
    let mut query = sqlx::query(&sql);
    for fingerprint in buffer.iter() {
        query = query
            .bind(&fingerprint.tls_client_ciphers_sha1)
            .bind(&fingerprint.tls_client_extensions_sha1)
            .bind(fingerprint.tls_client_hello_length);
    }

    query.execute(&mut *tx).await?;

    let values_stats = vec!["(CURRENT_DATE, ?, ?, ?, 1)"; buffer.len()];
    let sql_stats = format!(
        "INSERT INTO tls_fingerprint_daily_stats (stat_date, tls_client_ciphers_sha1, tls_client_extensions_sha1, tls_client_hello_length, request_count) VALUES {} ON DUPLICATE KEY UPDATE request_count = request_count + 1",
        values_stats.join(", ")
    );
    let mut query_stats = sqlx::query(&sql_stats);
    for fingerprint in buffer.iter() {
        query_stats = query_stats
            .bind(&fingerprint.tls_client_ciphers_sha1)
            .bind(&fingerprint.tls_client_extensions_sha1)
            .bind(fingerprint.tls_client_hello_length);
    }

    query_stats.execute(&mut *tx).await?;

    tx.commit().await?;
    Ok(())
}
