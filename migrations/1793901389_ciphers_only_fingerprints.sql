-- Merge rows into cipher-only keys; the extensions hash and hello length vary per connection.

DROP TABLE IF EXISTS tls_fingerprints_new;
DROP TABLE IF EXISTS tls_fingerprint_daily_stats_new;

CREATE TABLE tls_fingerprints_new (
    tls_client_ciphers_sha1 VARCHAR(64) NOT NULL PRIMARY KEY,

    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    hit_count BIGINT UNSIGNED NOT NULL DEFAULT 1
);

INSERT INTO tls_fingerprints_new (tls_client_ciphers_sha1, first_seen, last_seen, hit_count)
SELECT tls_client_ciphers_sha1, MIN(first_seen), MAX(last_seen), SUM(hit_count)
FROM tls_fingerprints
GROUP BY tls_client_ciphers_sha1;

CREATE TABLE tls_fingerprint_daily_stats_new (
    stat_date DATE NOT NULL,
    tls_client_ciphers_sha1 VARCHAR(64) NOT NULL,

    request_count BIGINT UNSIGNED NOT NULL,

    PRIMARY KEY (stat_date, tls_client_ciphers_sha1)
);

INSERT INTO tls_fingerprint_daily_stats_new (stat_date, tls_client_ciphers_sha1, request_count)
SELECT stat_date, tls_client_ciphers_sha1, SUM(request_count)
FROM tls_fingerprint_daily_stats
GROUP BY stat_date, tls_client_ciphers_sha1;

RENAME TABLE
    tls_fingerprints TO tls_fingerprints_old,
    tls_fingerprints_new TO tls_fingerprints,
    tls_fingerprint_daily_stats TO tls_fingerprint_daily_stats_old,
    tls_fingerprint_daily_stats_new TO tls_fingerprint_daily_stats;

DROP TABLE tls_fingerprints_old;
DROP TABLE tls_fingerprint_daily_stats_old;
