# Security policy

Certower holds private keys and CA and DNS credentials, so we take reports
seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub private vulnerability reporting](https://github.com/tntrock/certower/security/advisories/new).

Include the version or commit, how to reproduce, and the impact you expect.
We aim to acknowledge reports within 3 business days and to agree on a
disclosure date with you once a fix is ready. We credit reporters in the
advisory unless you prefer otherwise.

## Supported versions

Certower is in early development. Fixes go to the `main` branch and the
latest release only.

## Scope

In scope: the server, the agent, the web UI, and the documented deployment
setups. Especially interesting: privilege escalation across organizations,
projects, or roles; secret or private key disclosure; agent API
authentication; SSRF through discovery scanning or notifications.

Out of scope: findings that require an already-compromised host or
administrator account, and missing hardening on deployments that ignore the
documentation (for example, serving the UI over plain HTTP without
`-secure-cookies`).
