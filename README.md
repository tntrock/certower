# Certower

[![CI](https://github.com/tntrock/certower/actions/workflows/ci.yml/badge.svg)](https://github.com/tntrock/certower/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tntrock/certower/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/tntrock/certower/security/code-scanning)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/tntrock/certower/badge)](https://scorecard.dev/viewer/?uri=github.com/tntrock/certower)
[![Go Report Card](https://goreportcard.com/badge/github.com/tntrock/certower)](https://goreportcard.com/report/github.com/tntrock/certower)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-7-3178C6?logo=typescript&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?logo=sqlite&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15%2B-4169E1?logo=postgresql&logoColor=white)
![ACME](https://img.shields.io/badge/ACME-RFC%208555%20%2B%20ARI-003A70?logo=letsencrypt&logoColor=white)

**Self-hosted control tower for TLS certificates.** Discover every certificate
you run, issue and renew them over ACME from any CA, and deploy them to servers
and appliances automatically, with multi-tenant access control.

English | [繁體中文](README.zh-TW.md) | [简体中文](README.zh-CN.md)

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
- **Web UI** in English, Traditional Chinese (繁體中文) and Simplified Chinese (简体中文), chosen from the browser language.

## Documentation

- [User guide](docs/user-guide.md): requesting, renewing and deploying certificates, discovery, notifications
- [Administrator guide](docs/admin-guide.md): install (container, Windows, Linux), configuration, HTTPS, backup, upgrade
- [Architecture](docs/architecture.md)
- [REST API](docs/api.md)
- [Authentication](docs/authentication.md): single sign-on (OIDC), login rate limiting, proxies
- [Agent](docs/agent.md): install, nginx deployment, security model
- [Discovery and notifications](docs/discovery-and-notifications.md)
- [Data model](docs/data-model.md)
- [CA support](docs/ca-support.md)
- [Testing issuance](docs/testing-issuance.md): Pebble tests, and trying Let's Encrypt with Cloudflare DNS

## Quick start

**Container:**

```sh
docker run -d --name certower -p 8080:8080 -p 8443:8443 -v certower-data:/data ghcr.io/tntrock/certower:latest
docker exec certower certower bootstrap -email you@example.com   # prints a generated password
```

Open http://localhost:8080 and sign in.

**Other ways to install**, from the [releases page](https://github.com/tntrock/certower/releases):

| Platform | Package |
|---|---|
| Windows | `.msi` installer, runs as a Windows service |
| Debian, Ubuntu | `.deb` with a systemd service |
| RHEL, Rocky, Fedora | `.rpm` with a systemd service |
| Any | `.tar.gz` / `.zip` binaries; Docker Compose files in [`deploy/`](deploy) |

Then follow the [administrator guide](docs/admin-guide.md) (HTTPS, backups,
the key-encryption key) and the [user guide](docs/user-guide.md#quick-start)
(your first certificate).

**From source** (Go 1.26+, Node.js 22+):

```sh
(cd web && npm ci && npm run build)   # the web UI is embedded in the binary
go build -o bin/ ./cmd/...
./bin/certower bootstrap -email admin@example.com
./bin/certower serve
```

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

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0](LICENSE). If you run a modified
version of Certower as a network service, you must make your source available
to its users.
