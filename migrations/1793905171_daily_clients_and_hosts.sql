CREATE TABLE tls_fingerprint_daily_clients (
    stat_date DATE NOT NULL,
    tls_client_ciphers_sha1 VARCHAR(64) NOT NULL,
    client_prefix_hash BINARY(8) NOT NULL,
    client_asn INT UNSIGNED NULL,

    PRIMARY KEY (stat_date, tls_client_ciphers_sha1, client_prefix_hash)
);

CREATE TABLE tls_fingerprint_daily_hosts (
    stat_date DATE NOT NULL,
    tls_client_ciphers_sha1 VARCHAR(64) NOT NULL,
    host VARCHAR(255) NOT NULL,

    PRIMARY KEY (stat_date, tls_client_ciphers_sha1, host)
);
