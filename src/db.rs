use crate::models::TlsFingerprint;
use sqlx::AssertSqlSafe;
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

/// Sorted by hash so the result only changes when the set changes.
const TOP_CIPHERS_SQL: &str = "SELECT tls_client_ciphers_sha1 FROM (
    SELECT tls_client_ciphers_sha1, SUM(request_count) AS hits
    FROM tls_fingerprint_daily_stats
    WHERE stat_date >= CURDATE() - INTERVAL ? DAY
    GROUP BY tls_client_ciphers_sha1
    HAVING COUNT(DISTINCT stat_date) >= ? AND hits > ?
    ORDER BY hits DESC, tls_client_ciphers_sha1
    LIMIT ?
) fp
ORDER BY tls_client_ciphers_sha1";

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
    pool: &sqlx::MySqlPool,
    buffer: Vec<TlsFingerprint>,
) -> anyhow::Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }

    let rows = aggregate(buffer);

    let mut tx = pool.begin().await?;

    let mut query = sqlx::query(AssertSqlSafe(insert_sql(rows.len())));
    let mut query_stats = sqlx::query(AssertSqlSafe(stats_sql(rows.len())));
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

pub async fn top_ciphers(
    pool: &sqlx::MySqlPool,
    days: u32,
    min_days: u32,
    min_hits: u64,
    limit: u32,
) -> anyhow::Result<Vec<String>> {
    let ciphers = sqlx::query_scalar(TOP_CIPHERS_SQL)
        .bind(days)
        .bind(min_days)
        .bind(min_hits)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(ciphers)
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
