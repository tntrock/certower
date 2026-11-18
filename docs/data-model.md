# Data Model

The schema lives in
[`internal/store/migrations/postgres`](../internal/store/migrations/postgres).
The SQLite migrations mirror it, using JSON text in place of arrays and JSONB.

```mermaid
erDiagram
    organizations ||--o{ projects : has
    organizations ||--o{ role_bindings : grants
    projects ||--o{ role_bindings : grants
    users ||--o{ role_bindings : "bound to"
    service_accounts ||--o{ role_bindings : "bound to"
    service_accounts ||--o{ api_tokens : authenticates
    projects ||--o{ service_accounts : owns

    organizations ||--o{ secrets : holds
    organizations ||--o{ plugin_configs : configures
    projects ||--o| policies : "restricted by"

    projects ||--o{ agents : enrolls
    projects ||--o{ targets : has
    agents ||--o{ targets : serves
    plugin_configs ||--o{ targets : "deployer for"

    projects ||--o{ certificates : manages
    plugin_configs ||--o{ certificates : "issuer / dns for"
    certificates ||--o{ certificate_targets : "deployed to"
    targets ||--o{ certificate_targets : receives
    certificates ||--o{ certificate_versions : "issued as"
    certificate_versions ||--o{ deployments : "rolled out by"
    targets ||--o{ deployments : "rolled out to"

    organizations ||--o{ discovery_endpoints : scans
    discovery_endpoints ||--o{ discovered_certificates : serves
    certificate_versions |o--o{ discovered_certificates : "matches"
```

## Key ideas

- **`certificates` holds desired state** (names, key type, issuer, targets).
  Each issuance is one row in **`certificate_versions`**. Renewal creates a new
  version and leaves the old one for history and rollback.
- **`renew_after`** is computed at issuance from ARI, or from
  `renew_before_ratio` when the CA has no ARI. The scheduler only has to query
  `renew_after < now()`.
- **`key_location = 'agent'`** means the private key exists only on the host.
  The server stores the chain, never the key. `key_secret_id` is set only for
  server-side connectors.
- **`plugin_configs`** stores every configured Issuer, DNS provider, Deployer
  and Notifier. A NULL `project_id` makes the config shared across the
  organization, such as one TWCA account used by all projects.
- **`discovered_certificates.version_id`** links what is actually being served
  to what Certower issued. NULL means an unmanaged certificate.
- **`audit_log`** is append-only. Revoke UPDATE and DELETE from the app's
  database role.
