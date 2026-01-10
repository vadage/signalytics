CREATE TABLE IF NOT EXISTS tls_fingerprints (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,

    tls_client_ciphers_sha1 VARCHAR(64) NOT NULL,
    tls_client_extensions_sha1 VARCHAR(64) NOT NULL,
    tls_client_hello_length INT UNSIGNED NOT NULL,

    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    hit_count BIGINT UNSIGNED NOT NULL DEFAULT 1,

    UNIQUE KEY unique_tls_fingerprint (tls_client_ciphers_sha1, tls_client_extensions_sha1, tls_client_hello_length)
);

CREATE TABLE tls_fingerprint_daily_stats (
    stat_date DATE NOT NULL,

    tls_client_ciphers_sha1 VARCHAR(64) NOT NULL,
    tls_client_extensions_sha1 VARCHAR(64) NOT NULL,
    tls_client_hello_length INT UNSIGNED NOT NULL,

    request_count BIGINT UNSIGNED NOT NULL,

    PRIMARY KEY (
        stat_date,
        tls_client_ciphers_sha1,
        tls_client_extensions_sha1,
        tls_client_hello_length
    )
);
