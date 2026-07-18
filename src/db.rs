use crate::models::TlsFingerprint;
use std::collections::HashMap;

fn insert_sql(rows: usize) -> String {
    let values = vec!["(?, ?, ?, ?)"; rows];
    format!(
        "INSERT INTO tls_fingerprints (tls_client_ciphers_sha1, tls_client_extensions_sha1, tls_client_hello_length, hit_count) VALUES {} AS new ON DUPLICATE KEY UPDATE hit_count = tls_fingerprints.hit_count + new.hit_count, last_seen = CURRENT_TIMESTAMP",
        values.join(", ")
    )
}

fn stats_sql(rows: usize) -> String {
    let values = vec!["(CURRENT_DATE, ?, ?, ?, ?)"; rows];
    format!(
        "INSERT INTO tls_fingerprint_daily_stats (stat_date, tls_client_ciphers_sha1, tls_client_extensions_sha1, tls_client_hello_length, request_count) VALUES {} AS new ON DUPLICATE KEY UPDATE request_count = tls_fingerprint_daily_stats.request_count + new.request_count",
        values.join(", ")
    )
}

/// Sorted so concurrent flushes acquire row locks in the same order, avoiding upsert deadlocks.
fn aggregate(buffer: Vec<TlsFingerprint>) -> Vec<(TlsFingerprint, u64)> {
    let mut counts: HashMap<TlsFingerprint, u64> = HashMap::new();
    for fingerprint in buffer {
        *counts.entry(fingerprint).or_insert(0) += 1;
    }

    let mut rows: Vec<(TlsFingerprint, u64)> = counts.into_iter().collect();
    rows.sort();
    rows
}

pub async fn flush_batch(
    pool: &sqlx::Pool<sqlx::MySql>,
    buffer: Vec<TlsFingerprint>,
) -> anyhow::Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }

    let rows = aggregate(buffer);

    let mut tx = pool.begin().await?;

    let sql = insert_sql(rows.len());
    let sql_stats = stats_sql(rows.len());
    let mut query = sqlx::query(&sql);
    let mut query_stats = sqlx::query(&sql_stats);
    for (fingerprint, count) in &rows {
        query = query
            .bind(&fingerprint.tls_client_ciphers_sha1)
            .bind(&fingerprint.tls_client_extensions_sha1)
            .bind(fingerprint.tls_client_hello_length)
            .bind(*count as i64);
        query_stats = query_stats
            .bind(&fingerprint.tls_client_ciphers_sha1)
            .bind(&fingerprint.tls_client_extensions_sha1)
            .bind(fingerprint.tls_client_hello_length)
            .bind(*count as i64);
    }
    query.execute(&mut *tx).await?;
    query_stats.execute(&mut *tx).await?;

    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(ciphers: &str, extensions: &str, len: i64) -> TlsFingerprint {
        TlsFingerprint {
            tls_client_ciphers_sha1: ciphers.into(),
            tls_client_extensions_sha1: extensions.into(),
            tls_client_hello_length: len,
        }
    }

    #[test]
    fn test_aggregate_counts_duplicates() {
        let buffer = vec![fp("a", "x", 1); 5];
        let result = aggregate(buffer);
        assert_eq!(result, vec![(fp("a", "x", 1), 5)]);
    }

    #[test]
    fn test_aggregate_sorts_and_counts_mixed() {
        let buffer = vec![
            fp("b", "y", 2),
            fp("a", "x", 1),
            fp("b", "y", 2),
            fp("a", "z", 1),
            fp("a", "x", 1),
            fp("a", "x", 1),
        ];
        let result = aggregate(buffer);
        assert_eq!(
            result,
            vec![
                (fp("a", "x", 1), 3),
                (fp("a", "z", 1), 1),
                (fp("b", "y", 2), 2)
            ]
        );
    }

    #[test]
    fn test_aggregate_empty() {
        assert_eq!(aggregate(vec![]), vec![]);
    }
}
