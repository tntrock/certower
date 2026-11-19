# Certower

**Self-hosted control tower for TLS certificates.** Discover every certificate
you run, issue and renew them over ACME from any CA, and deploy them to servers
and appliances automatically, with multi-tenant access control.

[繁體中文](README.zh-TW.md)

![Certificates in Certower](docs/images/certificates-dark.png)

> Status: early development. Not ready for production use.

## Why

Public TLS certificate lifetimes are shrinking: 200 days from March 2026,
100 days from March 2027, and 47 days from March 2029. Manual renewal does not
scale to that. Certower automates the whole lifecycle and shows you what it
can't automate yet.

## Features

- **Discovery**: scan endpoints, find unmanaged certificates, and flag expiry,
  weak keys, over-long validity, and distrusted roots.
- **Any ACME CA**: Let's Encrypt, ZeroSSL, Google Trust Services, Sectigo,
  GlobalSign, DigiCert, TWCA, and others, with External Account Binding.
  DNS-01 through 150+ DNS providers.
- **Agents that keep keys local**: private keys are generated on the host and
  never leave it. Every deployment is verified against the live endpoint and
  rolled back on failure.
- **Organizations, projects, and roles**, with policy guardrails on names,
  CAs, and key types, OIDC single sign-on, and an audit log.
- **Notifications** by email and webhook (Slack, Mattermost, Google Chat,
  Discord, or signed JSON): expiry warnings, failures, discovery alerts.
- **Plugins** for issuers, DNS providers, deployers, and notifiers.
- **Web UI** in English and Traditional Chinese.

## Documentation

- [Architecture](docs/architecture.md)
- [REST API](docs/api.md)
- [Agent](docs/agent.md): install, nginx deployment, security model
- [Discovery and notifications](docs/discovery-and-notifications.md)
- [Data model](docs/data-model.md)
- [CA support](docs/ca-support.md)
- [Testing issuance](docs/testing-issuance.md): Pebble tests, and trying Let's Encrypt with Cloudflare DNS

## Quick start

Requires Go 1.26+ and Node.js 22+.

```sh
(cd web && npm ci && npm run build)   # the web UI is embedded in the binary
go build -o bin/ ./cmd/...
./bin/certower bootstrap -email admin@example.com   # prints a generated password
./bin/certower serve                                 # web UI and API on http://localhost:8080
```

Use PostgreSQL 15+ with `-db postgres://user:pass@host/certower` or
`CERTOWER_DB`. Then see the [API reference](docs/api.md#issuing-a-certificate)
to set up an issuer and request your first certificate.

On first start the server creates `certower.kek`, the key that encrypts
stored private keys and credentials. **Back it up and restrict access to
it**: without it, stored secrets cannot be decrypted. On Windows the file
mode is not enforced, so keep it in a directory only the service account
can read. Set its location with `-kek-file` or `CERTOWER_KEK_FILE`.

## Development

```sh
# Web UI with hot reload against a server on :8080:
(cd web && npm run dev)
# Or a server with sample data at http://127.0.0.1:18090
# (admin@example.com / "demo password 123"):
CERTOWER_DEMO=127.0.0.1:18090 go test ./internal/e2e -run TestDemoServer -timeout 0

go test ./...   # ACME tests need Pebble, see docs/testing-issuance.md
# Also run the store tests against PostgreSQL (needs an empty database):
CERTOWER_TEST_POSTGRES=postgres://... go test ./internal/store
```

## License

[GNU Affero General Public License v3.0](LICENSE). If you run a modified
version of Certower as a network service, you must make your source available
to its users.
