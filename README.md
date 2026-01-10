# Signalytics
A microservice for collecting aggregated TLS fingerprints from HTTP logs.

To gain analytical insights on TLS signals / fingerprints, that hit 

## Features
* Aggregates TLS fingerprints: ciphers, extensions and ClientHello length.
    * The fields can be provided by Cloudflare on the Free tier. [See their Docs](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/?field-category=SSL%2FTLS).
* Batch writes to MySQL for efficient storage.
* Example integration with Caddy logs included in [conf/Caddyfile](conf/Caddyfile)
* Accept logs via UDP on port ``9000``
* Easily extensible for other webservers via JSON formatting.

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
```shell
docker run \
  -e DATABASE_URL="mysql://user:password@host:port/dbname" \
  ghcr.io/vadage/signalytics:latest
```

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
