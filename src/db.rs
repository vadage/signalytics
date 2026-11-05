use crate::models::{Client, FingerprintParams, TlsFingerprint};
use sqlx::AssertSqlSafe;
use std::collections::{BTreeMap, BTreeSet};

fn insert_sql(rows: usize) -> String {
    let values = vec!["(?, ?)"; rows];
    format!(
        "INSERT INTO tls_fingerprints (tls_client_ciphers_sha1, hit_count) VALUES {} AS new ON DUPLICATE KEY UPDATE hit_count = tls_fingerprints.hit_count + new.hit_count, last_seen = CURRENT_TIMESTAMP",
        values.join(", ")
    )
}

fn stats_sql(rows: usize) -> String {
    let values = vec!["(CURRENT_DATE, ?, ?)"; rows];
    format!(
        "INSERT INTO tls_fingerprint_daily_stats (stat_date, tls_client_ciphers_sha1, request_count) VALUES {} AS new ON DUPLICATE KEY UPDATE request_count = tls_fingerprint_daily_stats.request_count + new.request_count",
        values.join(", ")
    )
}

fn clients_sql(rows: usize) -> String {
    let values = vec!["(CURRENT_DATE, ?, ?, ?)"; rows];
    format!(
        "INSERT IGNORE INTO tls_fingerprint_daily_clients (stat_date, tls_client_ciphers_sha1, client_prefix_hash, client_asn) VALUES {}",
        values.join(", ")
    )
}

fn hosts_sql(rows: usize) -> String {
    let values = vec!["(CURRENT_DATE, ?, ?)"; rows];
    format!(
        "INSERT IGNORE INTO tls_fingerprint_daily_hosts (stat_date, tls_client_ciphers_sha1, host) VALUES {}",
        values.join(", ")
    )
}

const TOP_CIPHERS_SQL: &str = "SELECT s.tls_client_ciphers_sha1
    FROM (
        SELECT tls_client_ciphers_sha1, COUNT(DISTINCT stat_date) AS days, SUM(request_count) AS hits
        FROM tls_fingerprint_daily_stats
        WHERE stat_date > CURDATE() - INTERVAL ? DAY
        GROUP BY tls_client_ciphers_sha1
    ) s
    LEFT JOIN (
        SELECT tls_client_ciphers_sha1, COUNT(DISTINCT client_prefix_hash) AS prefixes, COUNT(DISTINCT client_asn) AS asns
        FROM tls_fingerprint_daily_clients
        WHERE stat_date > CURDATE() - INTERVAL ? DAY
        GROUP BY tls_client_ciphers_sha1
    ) c USING (tls_client_ciphers_sha1)
    LEFT JOIN (
        SELECT tls_client_ciphers_sha1, COUNT(DISTINCT host) AS hosts
        FROM tls_fingerprint_daily_hosts
        WHERE stat_date > CURDATE() - INTERVAL ? DAY
        GROUP BY tls_client_ciphers_sha1
    ) h USING (tls_client_ciphers_sha1)
    WHERE s.days >= ? AND s.hits > ?
        AND COALESCE(c.prefixes, 0) >= ? AND COALESCE(c.asns, 0) >= ? AND COALESCE(h.hosts, 0) >= ?
    ORDER BY s.hits DESC, s.tls_client_ciphers_sha1
    LIMIT ?";

const DAILY_TABLES: [&str; 3] = [
    "tls_fingerprint_daily_stats",
    "tls_fingerprint_daily_clients",
    "tls_fingerprint_daily_hosts",
];

/// Sorted so concurrent flushes acquire row locks in the same order, avoiding upsert deadlocks.
fn aggregate(buffer: &[TlsFingerprint]) -> Vec<(&str, u64)> {
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for fingerprint in buffer {
        *counts
            .entry(&fingerprint.tls_client_ciphers_sha1)
            .or_insert(0) += 1;
    }

    counts.into_iter().collect()
}

/// One row per cipher and prefix; if a prefix shows up with several ASNs, the first seen wins.
fn distinct_clients(buffer: &[TlsFingerprint]) -> Vec<(&str, &Client)> {
    let mut clients: BTreeMap<(&str, [u8; 8]), &Client> = BTreeMap::new();
    for fingerprint in buffer {
        if let Some(client) = &fingerprint.client {
            clients
                .entry((&fingerprint.tls_client_ciphers_sha1, client.prefix_hash))
                .or_insert(client);
        }
    }

    clients
        .into_iter()
        .map(|((ciphers, _), client)| (ciphers, client))
        .collect()
}

fn distinct_hosts(buffer: &[TlsFingerprint]) -> Vec<(&str, &str)> {
    let hosts: BTreeSet<(&str, &str)> = buffer
        .iter()
        .filter_map(|f| Some((f.tls_client_ciphers_sha1.as_str(), f.host.as_deref()?)))
        .collect();

    hosts.into_iter().collect()
}

pub async fn flush_batch(
    pool: &sqlx::MySqlPool,
    buffer: Vec<TlsFingerprint>,
) -> anyhow::Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }

    let rows = aggregate(&buffer);
    let clients = distinct_clients(&buffer);
    let hosts = distinct_hosts(&buffer);

    let mut tx = pool.begin().await?;

    let mut query = sqlx::query(AssertSqlSafe(insert_sql(rows.len())));
    let mut query_stats = sqlx::query(AssertSqlSafe(stats_sql(rows.len())));
    for (ciphers, count) in &rows {
        query = query.bind(ciphers).bind(*count as i64);
        query_stats = query_stats.bind(ciphers).bind(*count as i64);
    }
    query.execute(&mut *tx).await?;
    query_stats.execute(&mut *tx).await?;

    if !clients.is_empty() {
        let mut query = sqlx::query(AssertSqlSafe(clients_sql(clients.len())));
        for (ciphers, client) in &clients {
            query = query
                .bind(ciphers)
                .bind(client.prefix_hash.as_slice())
                .bind(client.asn);
        }
        query.execute(&mut *tx).await?;
    }

    if !hosts.is_empty() {
        let mut query = sqlx::query(AssertSqlSafe(hosts_sql(hosts.len())));
        for (ciphers, host) in &hosts {
            query = query.bind(ciphers).bind(host);
        }
        query.execute(&mut *tx).await?;
    }

    tx.commit().await?;
    Ok(())
}

pub async fn top_ciphers(
    pool: &sqlx::MySqlPool,
    params: &FingerprintParams,
) -> anyhow::Result<Vec<String>> {
    let mut ciphers: Vec<String> = sqlx::query_scalar(TOP_CIPHERS_SQL)
        .bind(params.days)
        .bind(params.days)
        .bind(params.days)
        .bind(params.min_days)
        .bind(params.min_hits)
        .bind(params.min_prefixes)
        .bind(params.min_asns)
        .bind(params.min_hosts)
        .bind(params.limit)
        .fetch_all(pool)
        .await?;
    // Sorted by hash so the result only changes when the set changes.
    ciphers.sort();
    Ok(ciphers)
}

pub async fn delete_expired(pool: &sqlx::MySqlPool, retention_days: u32) -> anyhow::Result<u64> {
    let mut deleted = 0;
    for table in DAILY_TABLES {
        let sql = format!("DELETE FROM {table} WHERE stat_date < CURDATE() - INTERVAL ? DAY");
        let result = sqlx::query(AssertSqlSafe(sql))
            .bind(retention_days)
            .execute(pool)
            .await?;
        deleted += result.rows_affected();
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(ciphers: &str) -> TlsFingerprint {
        TlsFingerprint {
            tls_client_ciphers_sha1: ciphers.into(),
            client: None,
            host: None,
        }
    }

    fn fp_client(ciphers: &str, prefix: u8, asn: Option<u32>) -> TlsFingerprint {
        TlsFingerprint {
            client: Some(Client {
                prefix_hash: [prefix; 8],
                asn,
            }),
            ..fp(ciphers)
        }
    }

    fn fp_host(ciphers: &str, host: &str) -> TlsFingerprint {
        TlsFingerprint {
            host: Some(host.into()),
            ..fp(ciphers)
        }
    }

    #[test]
    fn test_aggregate_counts_duplicates() {
        let buffer = vec![fp("a"); 5];
        let result = aggregate(&buffer);
        assert_eq!(result, vec![("a", 5)]);
    }

    #[test]
    fn test_aggregate_sorts_and_counts_mixed() {
        let buffer = vec![fp("b"), fp("a"), fp("b"), fp("c"), fp("a"), fp("a")];
        let result = aggregate(&buffer);
        assert_eq!(result, vec![("a", 3), ("b", 2), ("c", 1)]);
    }

    #[test]
    fn test_aggregate_empty() {
        assert_eq!(aggregate(&[]), vec![]);
    }

    #[test]
    fn test_distinct_clients_dedupes_and_sorts() {
        let buffer = vec![
            fp_client("b", 1, Some(10)),
            fp_client("a", 2, Some(20)),
            fp_client("a", 2, Some(20)),
            fp_client("a", 1, None),
            fp("a"),
        ];
        let result = distinct_clients(&buffer);
        let actual: Vec<_> = result.iter().map(|(c, k)| (*c, k.prefix_hash[0])).collect();
        assert_eq!(actual, vec![("a", 1), ("a", 2), ("b", 1)]);
    }

    #[test]
    fn test_distinct_clients_keeps_one_asn_per_prefix() {
        let buffer = vec![fp_client("a", 1, Some(10)), fp_client("a", 1, Some(20))];
        let result = distinct_clients(&buffer);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1.asn, Some(10));
    }

    #[test]
    fn test_distinct_hosts_dedupes_and_sorts() {
        let buffer = vec![
            fp_host("b", "x.com"),
            fp_host("a", "y.com"),
            fp_host("a", "x.com"),
            fp_host("a", "y.com"),
            fp("a"),
        ];
        assert_eq!(
            distinct_hosts(&buffer),
            vec![("a", "x.com"), ("a", "y.com"), ("b", "x.com")]
        );
    }

    #[test]
    fn test_distinct_empty() {
        assert!(distinct_clients(&[fp("a")]).is_empty());
        assert!(distinct_hosts(&[fp("a")]).is_empty());
    }
}
