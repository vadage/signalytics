# Signalytics
A microservice for collecting aggregated TLS fingerprints from HTTP logs.

To gain analytical insights on TLS signals / fingerprints, that hit your server, so you can act on trends on your firewall.

## Features
* Aggregates TLS cipher fingerprints per day.
    * The fields can be provided by Cloudflare on the Free tier. [See their Docs](https://developers.cloudflare.com/rules/transform/request-header-modification/reference/fields-functions/).
* Batch writes to MySQL for efficient storage.
* Example integration included for [Caddy](conf/Caddyfile) and [Nginx](conf/nginx.conf).
* Accept logs via UDP on port ``9000``.
* Export current fingerprints and serve health checks via HTTP on TCP port ``9000``.
* Easily extensible for other webservers via JSON formatting.
* Syslog support for both RFC 3164 and RFC 5424.

## Getting started

### Prerequisites
* Docker / Docker Compose

### Local Development
```shell
git clone https://github.com/vadage/signalytics.git
cd signalytics
docker compose up -d
```

Example for testing with cURL:
```shell
curl 'http://localhost:8080/' \
    --header 'X-TLS-Client-Ciphers-SHA1: GXSPDLP4G3X+prK73a4wBuOaHRc=' \
    --header 'CF-Connecting-IP: 203.0.113.1' \
    --header 'X-Client-ASN: 64496'
```

### Production
Make sure to only forward the values from trusted sources.
```shell
docker run \
  -e DATABASE_URL="mysql://user:password@host:port/dbname" \
  ghcr.io/vadage/signalytics:latest
```
**Additional options**

| Option                 | Default | Description                                                                              |
|------------------------|---------|------------------------------------------------------------------------------------------|
| `DATABASE_URL_FILE`    |         | Path to a file containing the database URL. Takes precedence over `DATABASE_URL`.        |
| `PREFIX_HASH_KEY`      |         | Secret for hashing client networks. Clients aren't counted without it. Keep it stable.   |
| `PREFIX_HASH_KEY_FILE` |         | Path to a file containing the secret. Takes precedence over `PREFIX_HASH_KEY`.           |
| `RETENTION_DAYS`       |         | Deletes daily rows older than this, at startup and every 24 hours. Off unless set.       |
| `LOG_LEVEL`            | info    | Sets the verbosity of logs. Can be `off`, `trace`, `debug`, `info`, `warn`, `error`.     |

Changing `PREFIX_HASH_KEY` makes the same network count twice until the old rows age out.
`RETENTION_DAYS` should be at least the `days` you query. Lifetime totals are never deleted.

### HTTP endpoints
| Endpoint            | Description                                                    |
|---------------------|----------------------------------------------------------------|
| `GET /`, `/healthz` | Health check. Responds with `200` once the service is running. |
| `GET /fingerprints` | Most common cipher fingerprints, e.g. to build firewall rules. |

**`/fingerprints` query parameters**

| Parameter      | Default | Description                                                         |
|----------------|---------|---------------------------------------------------------------------|
| `days`         | 30      | Number of days to look back.                                        |
| `min_days`     | 7       | Only include fingerprints seen on at least this many distinct days. |
| `min_hits`     | 5       | Only include fingerprints with more requests than this.             |
| `min_prefixes` | 0       | Only include fingerprints seen from at least this many networks.    |
| `min_asns`     | 0       | Only include fingerprints seen from at least this many ASNs.        |
| `min_hosts`    | 0       | Only include fingerprints seen on at least this many hosts.         |
| `limit`        | 50      | Maximum number of fingerprints, most requested first.               |
| `min_count`    | 10      | Responds with `503` if fewer fingerprints are found.                |

The fingerprints are sorted, so the response only changes when the set of fingerprints changes.
```json
{
  "tls_client_ciphers_sha1": ["GXSPDLP4G3X+prK73a4wBuOaHRc="]
}
```

**Cipher families**

Chrome and Safari prepend a random GREASE value ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701)) to their cipher list, so one browser shows up as 16 different hashes.
The families in [`src/cipher_families.json`](src/cipher_families.json) are grouped, and the thresholds apply to the family as a whole.
`limit` and `min_count` count a family as one fingerprint. When a family qualifies, all 16 of its hashes are exported, so the response can contain up to 15 extra hashes per family.
Editing the file requires a rebuild.

### JSON log format
The log has to contain at least this structure. It's recommended to use a small payload for higher throughput and reliability.
```json
{
  "tls_client_ciphers_sha1":"GXSPDLP4G3X+prK73a4wBuOaHRc="
}
```

Optional fields for client counting. Missing or empty values are skipped, the request still counts towards the fingerprint.
```json
{
  "tls_client_ciphers_sha1":"GXSPDLP4G3X+prK73a4wBuOaHRc=",
  "client_ip":"203.0.113.1",
  "client_asn":"64496",
  "host":"example.com"
}
```

| Field        | Used for                                                                                     |
|--------------|----------------------------------------------------------------------------------------------|
| `client_ip`  | `min_prefixes`. Reduced to its /24 (IPv4) or /48 (IPv6) and hashed. Never stored as is.      |
| `client_asn` | `min_asns`. E.g. from a Cloudflare transform rule header with `ip.src.asnum`.                |
| `host`       | `min_hosts`. Use a value from your own config like `$server_name`, not the client's `Host`.  |

## License
[MIT License](LICENSE)
