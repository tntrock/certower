# Certower Architecture

Certower is a self-hosted control plane for the full TLS certificate lifecycle:
discover → inventory → issue → deploy → verify → renew → revoke.

It is designed around the CA/Browser Forum validity reductions
(200 days from 2026-03-15, 100 days from 2027-03-15, 47 days from 2029-03-15):
at those lifetimes, renewal and deployment must be fully automated.

## Components

```
                 ┌───────────────────────────────────────────┐
  Web UI / CLI ─►│              certower (server)            │
  REST API       │                                           │
                 │  API ─ AuthN (local, OIDC) ─ AuthZ (RBAC) │
                 │  Inventory     Scheduler    Policy engine │
                 │  Discovery     Job runner   Audit log     │
                 │  Plugins: Issuer · DNS · Deployer · Notify│
                 │  Store: PostgreSQL | SQLite               │
                 │  Secrets: envelope encryption (pluggable  │
                 │           KEK: local file, Vault, KMS)    │
                 └──────────────┬────────────────────────────┘
                                │ HTTPS + JSON, mutual TLS, agent-initiated
             ┌──────────────────┼────────────────────────┐
             ▼                  ▼                        ▼
     certower-agent      certower-agent          server-side connectors
     (Linux: nginx,      (Windows: IIS,          (F5, FortiGate, cloud LBs,
      apache, files)      cert store)             k8s, key vaults)
```

### Server (`cmd/certower`)

A single Go binary that embeds the web UI. Runs with SQLite for evaluation and
PostgreSQL for production.

### Agent (`cmd/certower-agent`)

A single static binary installed on hosts. It talks to the server over
HTTPS and JSON with mutual TLS (see [agent.md](agent.md)). gRPC was the
first plan; plain HTTPS needs no code generation, passes through ordinary
corporate proxies, and is as secure with mutual TLS. The agent:

1. Enrolls with a one-time token, pins the server's private agent CA by
   fingerprint, and receives its own client certificate from that CA.
2. Keeps an outbound connection to the server. It never listens for inbound
   connections, so no firewall rules are needed toward hosts.
3. **Generates private keys locally** and sends only CSRs. Private keys for
   agent targets never leave the host.
4. Installs the issued certificate, reloads the service, then **verifies the
   live endpoint serves the new certificate** before reporting success. If
   verification fails, it rolls back.
5. Only writes to directories and runs commands that its own local
   configuration allows, so a compromised server cannot take over hosts.

### Connectors

Some targets cannot run an agent (appliances, managed cloud services). Their
Deployer plugins run inside the server. For these targets the server generates
the key and stores it encrypted.

## Plugins

All integrations sit behind four interfaces in [`pkg/plugin`](../pkg/plugin):

| Kind      | Responsibility                                  | Examples |
|-----------|-------------------------------------------------|----------|
| Issuer    | Obtain, revoke, and query renewal info for certs | Generic ACME (+EAB), step-ca, Vault PKI, AD CS, manual |
| DNS       | Solve ACME DNS-01 challenges                    | lego's 150+ providers |
| Deployer  | Install a cert on a target and verify it        | nginx, apache, IIS, Java keystore, k8s secret, F5 |
| Notifier  | Deliver events to humans/systems                | Email, webhook, Slack, Teams, Telegram |

Built-in plugins are compiled into the binary. Out-of-tree plugins run as
separate processes over gRPC (HashiCorp go-plugin model), so they can be
written in any language and shipped independently.

Every plugin declares a JSON Schema for its configuration. The UI renders
config forms from that schema, so adding a plugin needs no frontend changes.

### No per-CA code

Commercial CAs (TWCA, GlobalSign, DigiCert, Sectigo, …) are supported through
the generic ACME issuer with External Account Binding. CA-specific knowledge is
kept as *presets* (directory URL, whether EAB is required, docs link), not
code. When a CA moves its endpoint, only the preset changes. See
[ca-support.md](ca-support.md).

CAs without ACME use the **manual issuer**: Certower still generates the key
and CSR, notifies a person to submit it, accepts the uploaded certificate, and
deploys it automatically.

## Multi-tenancy and authorization

```
Organization
 └─ Project
     ├─ Certificates, Targets, Agents
     ├─ Issuers / DNS credentials (or inherited from the org)
     └─ Members → Role
```

Roles: `org_admin`, `project_admin`, `operator`, `viewer`, `auditor`.
See [`internal/rbac`](../internal/rbac).

- A role bound at the organization applies to all of its projects. A role bound
  to a project applies only to that project.
- **Secrets are use-only**: an operator can reference a DNS credential to issue
  a certificate, but nobody can read it back through the API.
- **Policy guardrails** ([`internal/policy`](../internal/policy)) limit what
  each project may request: allowed name patterns, issuers, key algorithms, and
  maximum validity.
- OIDC group claims map to project roles, so membership is managed in the IdP.
- Project-scoped API tokens are available for CI/CD.
- Every mutating call is written to an append-only audit log.

## Renewal

Renewal is scheduled by ACME Renewal Information (ARI, RFC 9773) when the CA
offers it. Otherwise renewal starts when one third of the lifetime remains.
For a 47-day certificate that leaves about 15 days to retry failures.

## Discovery

The scanner connects to configured hosts/ports (and later CIDR ranges and CT
logs for owned domains), records every certificate it finds, and links it to
the inventory. Unmanaged certificates are flagged. Built-in rules
([`internal/discovery`](../internal/discovery)) also flag expiry, weak keys,
SHA-1 signatures, validity over the CA/B limit, and certificates from roots
browsers have stopped trusting, such as Chunghwa Telecom certificates issued
after 2025-07-31 (distrusted from Chrome 139).

## Roadmap

- **v0.1**: server (SQLite/Postgres) + UI, local auth + OIDC, RBAC, generic ACME
  issuer with EAB, DNS-01 via lego, Linux agent (nginx, apache, files), email
  and webhook notifications, host-list discovery.
- **v0.2**: Windows agent (IIS, cert store), Java keystore, k8s deployer, ARI.
- **v0.3**: appliance connectors (F5, FortiGate), cloud LB/key vault
  connectors, CT-log discovery, out-of-tree plugins.
- **Later**: ACME server mode, so existing certbot or Caddy clients point at
  Certower and it proxies to the real CA with policy enforced.
