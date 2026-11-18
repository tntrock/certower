# Certower

**Self-hosted control tower for TLS certificates.** Discover every certificate
you run, issue and renew them over ACME from any CA, and deploy them to servers
and appliances automatically, with multi-tenant access control.

[繁體中文](README.zh-TW.md)

> Status: early development. Not ready for production use.

## Why

Public TLS certificate lifetimes are shrinking: 200 days from March 2026,
100 days from March 2027, and 47 days from March 2029. Manual renewal does not
scale to that. Certower automates the whole lifecycle and shows you what it
can't automate yet.

## Features (planned for v0.1)

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
- **Plugins** for issuers, DNS providers, deployers, and notifiers.

## Documentation

- [Architecture](docs/architecture.md)
- [Data model](docs/data-model.md)
- [CA support](docs/ca-support.md)

## Building

Requires Go 1.24+.

```sh
go build -o bin/ ./cmd/...
./bin/certower serve -listen :8080
```

```sh
go test ./...
```

## License

[GNU Affero General Public License v3.0](LICENSE). If you run a modified
version of Certower as a network service, you must make your source available
to its users.
