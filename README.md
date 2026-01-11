# Signalytics
A microservice for collecting aggregated TLS fingerprints from HTTP logs.

To gain analytical insights on TLS signals / fingerprints, that hit your server, so you can act on trends on your firewall.

## Features
* Aggregates TLS fingerprints: ciphers, extensions and ClientHello length.
    * The fields can be provided by Cloudflare on the Free tier. [See their Docs](https://developers.cloudflare.com/rules/transform/request-header-modification/reference/fields-functions/).
* Batch writes to MySQL for efficient storage.
* Example integration included for [Caddy](conf/Caddyfile) and [Nginx](conf/nginx.conf).
* Accept logs via UDP on port ``9000``.
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
    --header 'X-TLS-Client-Extensions-SHA1: OWFiM2I5ZDc0YWI0YWYzZmFkMGU0ZjhlYjhiYmVkMjgxNTU5YTU2Mg==' \
    --header 'X-TLS-Client-Hello-Length: 508'
```

### Production
Make sure to only forward the values from trusted sources.
```shell
docker run \
  -e DATABASE_URL="mysql://user:password@host:port/dbname" \
  ghcr.io/vadage/signalytics:latest
```
**Additional options**

| Option      | Default | Description                                                                          |
|-------------|---------|--------------------------------------------------------------------------------------|
| `LOG_LEVEL` | info    | Sets the verbosity of logs. Can be `off`, `trace`, `debug`, `info`, `warn`, `error`. |

### JSON log format
The log has to contain at least this structure. It's recommended to use a small payload for higher throughput and reliability.
```json
{
  "tls_client_ciphers_sha1":"GXSPDLP4G3X+prK73a4wBuOaHRc=",
  "tls_client_extensions_sha1":"OWFiM2I5ZDc0YWI0YWYzZmFkMGU0ZjhlYjhiYmVkMjgxNTU5YTU2Mg==",
  "tls_client_hello_length":"508"
}
```

## License
[MIT License](LICENSE)
