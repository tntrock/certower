# Certower administrator guide

[繁體中文](zh-TW/admin-guide.md) | [简体中文](zh-CN/admin-guide.md)

This guide is for the people who install and run Certower: installing,
configuring, securing, backing up, upgrading, and troubleshooting. For
day-to-day use (requesting certificates, deploying them, discovery), see
the [user guide](user-guide.md).

> Certower is in early development. Try it, but do not rely on it alone for
> production certificates yet.

- [How Certower fits together](#how-certower-fits-together)
- [Requirements](#requirements)
- [Install](#install)
- [First steps after installing](#first-steps-after-installing)
- [Configuration reference](#configuration-reference)
- [HTTPS and reverse proxies](#https-and-reverse-proxies)
- [Database](#database)
- [The key-encryption key](#the-key-encryption-key)
- [Backup and restore](#backup-and-restore)
- [Upgrading](#upgrading)
- [Users and access](#users-and-access)
- [Installing agents](#installing-agents)
- [Monitoring and logs](#monitoring-and-logs)
- [Security checklist](#security-checklist)
- [Troubleshooting](#troubleshooting)
- [Uninstalling](#uninstalling)

## How Certower fits together

```
             browsers, API clients                      agents on your hosts
                     │ HTTPS (via your reverse proxy)          │ mutual TLS, outbound
                     ▼                                         ▼
          ┌──────────────────── certower serve ───────────────────────┐
          │ web UI + REST API :8080          agent API :8443           │
          │ issuance engine, scheduler, discovery scanner, notifiers  │
          └──────┬───────────────────────────┬────────────────────────┘
                 │                           │
        SQLite or PostgreSQL        certower.kek (encrypts stored keys
        (all state)                  and credentials)
                 │
                 └──► ACME CAs, DNS providers, webhooks, SMTP (outbound)
```

- **Server** (`certower`): one process with the web UI, the API, and the
  background engine that issues, renews, scans, and notifies.
- **Agent** (`certower-agent`, optional): runs on the hosts where
  certificates are used. It generates private keys there, so they never
  leave the host, and installs certificates into services such as nginx.
  Agents connect out to the server; the server never connects to them.
- **Database**: SQLite (a single file, fine for most installations) or
  PostgreSQL.
- **Key-encryption key (KEK)**: a file that encrypts every private key and
  credential stored in the database. See [below](#the-key-encryption-key).

## Requirements

| | |
|---|---|
| OS | Linux (amd64, arm64), Windows Server 2019+ / Windows 10+ (amd64), or any container runtime. macOS binaries exist for testing. |
| CPU / memory | 1 vCPU and 256 MB are plenty for thousands of certificates. |
| Disk | Under 1 GB for most installations. |
| Inbound | 8080 (web UI and API; put HTTPS in front of it). 8443 (agent API) only if you use agents. |
| Outbound | HTTPS to your CAs and DNS provider APIs; DNS (53) to check DNS-01 records; your SMTP server or webhooks; the endpoints you scan. |

## Install

Pick one. All of them run the same program.

### Container (Docker, Podman, Kubernetes)

```sh
docker run -d --name certower --restart unless-stopped \
  -p 8080:8080 -p 8443:8443 \
  -v certower-data:/data \
  -e CERTOWER_AGENT_URL=https://certower.example.com:8443 \
  ghcr.io/tntrock/certower:latest

docker exec certower certower bootstrap -email you@example.com
```

The image is distroless (no shell), runs as an unprivileged user (UID
65532), and keeps its database and KEK in the `/data` volume. Images are
published for `linux/amd64` and `linux/arm64`, tagged with the version
(`0.1.0`, `0.1`) and `latest`. Pin a version in production.

Docker Compose files are in [`deploy/`](../deploy):
[`docker-compose.yml`](../deploy/docker-compose.yml) (SQLite) and
[`docker-compose.postgres.yml`](../deploy/docker-compose.postgres.yml).

### Debian, Ubuntu, RHEL, Rocky, Fedora

Download the `.deb` or `.rpm` for your architecture from the
[releases page](https://github.com/tntrock/certower/releases), then:

```sh
sudo apt install ./certower_0.1.0_amd64.deb      # Debian, Ubuntu
sudo dnf install ./certower_0.1.0_amd64.rpm      # RHEL, Rocky, Fedora

sudo -u certower certower bootstrap -config /etc/certower/certower.env -email you@example.com
```

The package creates a `certower` system user, installs a hardened systemd
service, and starts it.

| Path | Purpose |
|---|---|
| `/usr/bin/certower` | the program |
| `/etc/certower/certower.env` | settings (owner `root:certower`, mode 0640) |
| `/var/lib/certower/` | database and KEK (mode 0750) |
| `certower.service` | `systemctl status certower`, logs in `journalctl -u certower` |

### Windows

Download `certower_<version>_windows_amd64.msi` from the releases page and
run it, or install silently:

```powershell
msiexec /i certower_0.1.0_windows_amd64.msi /qn
& "C:\Program Files\Certower\certower.exe" bootstrap -config C:\ProgramData\Certower\certower.env -email you@example.com
```

The installer:

- installs `C:\Program Files\Certower\certower.exe` and adds it to `PATH`;
- creates `C:\ProgramData\Certower\` with access for SYSTEM and
  Administrators only, holding `certower.env` (settings), the database,
  the KEK, and `certower.log`;
- registers and starts the **Certower** service (automatic start, restarts
  on failure).

After changing `certower.env`, run `Restart-Service Certower`. Open the
ports in Windows Firewall if other machines need them:

```powershell
New-NetFirewallRule -DisplayName "Certower" -Direction Inbound -Protocol TCP -LocalPort 8080,8443 -Action Allow
```

### Plain binaries

Archives for Linux, Windows, and macOS are on the releases page. Run
`certower serve` in the directory where it should keep its data, or point
it at a settings file with `-config`. Verify downloads with
`checksums.txt`, or with GitHub's build provenance:

```sh
gh attestation verify certower_0.1.0_linux_amd64.tar.gz --repo tntrock/certower
```

### From source

Requires Go 1.26+ and Node.js 22+:

```sh
git clone https://github.com/tntrock/certower && cd certower
(cd web && npm ci && npm run build)
go build -o bin/ ./cmd/...
```

## First steps after installing

1. **Create the first administrator** with `certower bootstrap -email ...`
   (commands above). It prints a generated password once.
2. Open `http://<server>:8080` and sign in. Change the password from the
   sidebar (**Change password**).
3. **Create an organization** (only instance administrators can) and a
   **project** inside it.
4. Give people access: add their accounts under **Users** (or set up
   [single sign-on](authentication.md)), then grant roles under **Members**.
5. Follow the [user guide](user-guide.md#quick-start) to add a CA and a DNS
   provider and request the first certificate.
6. Before relying on it: put it [behind HTTPS](#https-and-reverse-proxies)
   and [back up the KEK](#the-key-encryption-key).

## Configuration reference

Every setting can be a command-line flag or an environment variable. A
settings file (`-config <file>` or `CERTOWER_CONFIG=<file>`) holds
`KEY=VALUE` lines of the same variables; the Linux and Windows packages
use one. Precedence: flag, then environment, then the file.

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `CERTOWER_DB` | `-db` | `sqlite:certower.db` | `sqlite:<path>` or `postgres://user:pass@host/db?sslmode=...` |
| `CERTOWER_KEK_FILE` | `-kek-file` | `certower.kek` | Key-encryption key; created if missing |
| `CERTOWER_LISTEN` | `-listen` | `:8080` | Web UI and API address |
| `CERTOWER_AGENT_LISTEN` | `-agent-listen` | `:8443` | Agent API address; empty disables agents |
| `CERTOWER_AGENT_URL` | `-agent-url` | `https://<hostname>:8443` | Agent API URL as agents reach it (shown in enrollment commands) |
| `CERTOWER_PUBLIC_URL` | `-public-url` | | Public web address, for links in notifications and the SSO callback |
| `CERTOWER_SECURE_COOKIES` | `-secure-cookies` | `false` | Mark the session cookie Secure. Set `true` behind HTTPS |
| `CERTOWER_TRUSTED_PROXIES` | `-trusted-proxies` | | Proxies (IPs or CIDRs) whose `X-Forwarded-For` is trusted |
| `CERTOWER_LOG_FILE` | `-log-file` | stderr | Append logs to a file (the Windows service uses this) |
| `CERTOWER_DNS_RESOLVERS` | `-dns-resolvers` | system | DNS servers for checking DNS-01 records, e.g. `1.1.1.1,8.8.8.8` |
| `CERTOWER_DNS_CHECK` | `-dns-check` | `auto` | `auto`, `authoritative`, or `recursive` |
| | `-workers` | `4` | Concurrent background jobs |
| | `-discovery-allow-link-local` | `false` | Let discovery scan 169.254.0.0/16 (off to block cloud metadata probing) |
| `CERTOWER_OIDC_*` | `-oidc-*` | | Single sign-on; see [authentication](authentication.md) |

Run `certower serve -h` for the full list. Agent settings are in the
[agent guide](agent.md).

## HTTPS and reverse proxies

Certower serves plain HTTP on 8080 and expects TLS in front of it. Put a
reverse proxy there and set:

```sh
CERTOWER_PUBLIC_URL=https://certower.example.com
CERTOWER_SECURE_COOKIES=true
CERTOWER_TRUSTED_PROXIES=127.0.0.1     # the proxy's address as Certower sees it
```

nginx example:

```nginx
server {
    listen 443 ssl;
    server_name certower.example.com;
    ssl_certificate     /etc/certower/certs/certower.example.com/fullchain.pem;
    ssl_certificate_key /etc/certower/certs/certower.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Caddy does it in one line: `certower.example.com { reverse_proxy 127.0.0.1:8080 }`.

**Do not put the agent port (8443) behind a TLS-terminating proxy.** Agents
authenticate with client certificates (mutual TLS) against Certower's own
agent CA, so the connection must reach Certower directly or through a
TCP (layer 4) pass-through. Agents check the server by the CA fingerprint
in their enrollment command, not by a public certificate.

Certower can issue the certificate for its own proxy; just keep a way to
reach it if that certificate ever lapses.

`CERTOWER_TRUSTED_PROXIES` matters for the audit log and the login rate
limit: without it, every request appears to come from the proxy, and
one attacker's failed logins would lock out everyone behind it.

## Database

**SQLite** (default) needs nothing else and handles a single server with
thousands of certificates. Keep the database on local disk, not a network
share.

**PostgreSQL 15+** is better when you already operate PostgreSQL, want
managed backups, or run more than one Certower process:

```sh
CERTOWER_DB=postgres://certower:PASSWORD@db.example.com:5432/certower?sslmode=verify-full
```

URL-encode special characters in the password (`@` as `%40`, `/` as `%2F`).
Create the database and an owner role; Certower creates its tables.

Schema migrations run automatically at startup. There is no migration
tool to run by hand, and no data migration between SQLite and PostgreSQL
yet: choose before you start.

## The key-encryption key

Every private key and credential (CA account keys, EAB secrets, DNS API
tokens, webhook URLs, SMTP passwords) is encrypted in the database with
keys that are themselves encrypted by the KEK in `certower.kek`.

- **Back it up**, separately from database backups, somewhere only
  administrators can read (a password manager or a secrets vault).
- **If you lose it**, the encrypted data cannot be recovered. Certificates,
  settings, and history remain, but you must re-enter every credential,
  and certificates whose keys were kept on the server must be reissued.
- **If it leaks** together with a database copy, every stored secret is
  exposed: rotate the CA, DNS, and notification credentials.
- The file is created on first start with mode 0600 (Linux) or inside the
  locked-down data folder (Windows installer).

## Backup and restore

Back up the **database** and the **KEK**. Agents keep their own keys on
their hosts, so they need no server-side backup.

**SQLite.** Copying the file while Certower runs can produce an inconsistent
copy. Either stop it briefly:

```sh
sudo systemctl stop certower
sudo cp -a /var/lib/certower/certower.db /backup/certower-$(date +%F).db
sudo systemctl start certower
```

or take a filesystem/volume snapshot. In a container, stop it and back up
the volume (`docker run --rm -v certower-data:/data -v $PWD:/b alpine tar czf /b/certower.tgz -C /data .`).

**PostgreSQL.** `pg_dump -Fc certower > certower.dump` while running.

**Restore**: stop Certower, put back the database and the matching KEK,
start it. A database restored without its KEK cannot decrypt secrets.

## Upgrading

1. Read the release notes.
2. Back up the database and KEK.
3. Upgrade:
   - Container: `docker pull ghcr.io/tntrock/certower:<version>` and recreate
     the container with the same volume.
   - Packages: install the new `.deb`/`.rpm`; the service restarts.
   - Windows: run the new `.msi`; it replaces the old version and keeps
     `C:\ProgramData\Certower`.
4. Migrations run at startup. Check `certower version` and the logs.

Downgrades are not supported once a newer version has migrated the
database: restore the backup instead.

## Users and access

**Instance administrators** (created by `bootstrap`, or promoted on the
**Users** page) can create organizations and manage accounts. Their power
inside an organization still comes from roles, though they can grant
themselves any.

On **Users** (sidebar, *Instance* section) an instance administrator can:

- create a password account (the dialog suggests a strong password);
- reset a password, disable or re-enable an account, and grant or remove
  instance administration. Disabling or resetting signs the person out
  everywhere. You cannot disable or demote yourself.

People change their own password from the sidebar. Passwords are at least
12 characters and stored with Argon2id. Ten failed sign-ins in 15 minutes
lock an account for a while; thirty lock a source address.

**Single sign-on** with Google, Microsoft Entra ID, Okta, Keycloak, or any
OpenID Connect provider: see [authentication](authentication.md). With
`CERTOWER_OIDC_AUTO_CREATE=true` accounts are created on first sign-in;
you can grant roles to identity provider groups so access follows your
directory.

Roles are granted per organization or project; see the
[user guide](user-guide.md#roles). Automation uses **service accounts**
with API tokens, created through the [API](api.md).

## Installing agents

Agents are needed only when keys should stay on the hosts (or for
automatic deployment). On the server, make sure port 8443 is reachable
from those hosts and `CERTOWER_AGENT_URL` is the address they use.

In the UI, open a project's **Agents & targets** page and choose
**Add agent**. It shows an enrollment command with a one-time token. On
the host:

**Debian/Ubuntu/RHEL**:

```sh
sudo apt install ./certower-agent_0.1.0_amd64.deb     # or dnf install ...rpm
sudo certower-agent enroll -server https://certower.example.com:8443 -token cwe_... -ca-sha256 ...
sudo systemctl start certower-agent
```

**Windows**:

```powershell
msiexec /i certower-agent_0.1.0_windows_amd64.msi /qn
certower-agent enroll -server https://certower.example.com:8443 -token cwe_... -ca-sha256 ...
Set-Service CertowerAgent -StartupType Automatic; Start-Service CertowerAgent
```

Before starting it, review `agent.json` in the state directory
(`/var/lib/certower-agent` or `C:\ProgramData\Certower\agent`): it lists the
directories the agent may write and the commands it may run. The server
cannot make the agent do anything outside those lists. Details, deployers,
and the security model: [agent guide](agent.md).

## Monitoring and logs

- **Health**: `GET /healthz` returns `ok`. `certower healthcheck` checks the
  local server (the container image uses it).
- **Logs**: `journalctl -u certower`, `docker logs certower`, or
  `C:\ProgramData\Certower\certower.log` on Windows. Failed logins, job
  retries, and issuance errors are logged at WARN.
- **Notifications**: add a notifier (email, or a webhook to Slack, Mattermost,
  Google Chat, Discord) for `cert.issue_failed`, `cert.expiring`, and
  `cert.deploy_failed` so failures reach someone. See
  [notifications](discovery-and-notifications.md#notifications).
- **Jobs** page in each project shows retries and their errors.
- **Audit log** records every change with who, when, and from where.

## Security checklist

- [ ] HTTPS in front of the UI, `CERTOWER_SECURE_COOKIES=true`,
      `CERTOWER_PUBLIC_URL` set.
- [ ] `CERTOWER_TRUSTED_PROXIES` set to exactly your proxies.
- [ ] Port 8080 not exposed directly to the internet; 8443 only to agent
      networks.
- [ ] KEK backed up separately from the database.
- [ ] The bootstrap password changed; few instance administrators.
- [ ] Single sign-on with `-oidc-allowed-domains`, if you use it.
- [ ] Notifications for failures and expiry configured.
- [ ] Agents' `allowedPaths` and `allowedCommands` reviewed on each host.
- [ ] Releases verified with checksums or `gh attestation verify`.
- [ ] Subscribed to [security advisories](https://github.com/tntrock/certower/security/advisories)
      (Watch → Custom → Security alerts).

## Troubleshooting

| Symptom | What to check |
|---|---|
| Service does not start | Logs (above). Common causes: port in use, database path not writable, unreadable `certower.env`. |
| "value was sealed with key ..., but key ... is loaded" or "decryption failed" | The KEK does not match the database. Restore the matching `certower.kek`. |
| Issuance stays in *Failing* with DNS errors | The DNS provider token's permissions (Cloudflare: Zone:Read and DNS:Edit for the zone). If the server cannot reach authoritative DNS servers, set `CERTOWER_DNS_RESOLVERS` to resolvers it can reach, or `CERTOWER_DNS_CHECK=recursive`. |
| "rateLimited" from Let's Encrypt | Test with the *Let's Encrypt (staging)* preset first; production limits are per domain per week. |
| Sign-in says too many attempts | Wait 15 minutes, or have an administrator reset the password. Behind a proxy, check `CERTOWER_TRUSTED_PROXIES`. |
| SSO error on the login page | The message names the cause; see [authentication](authentication.md#how-sign-in-maps-to-accounts). |
| Agent shows *Offline* | On the host: `journalctl -u certower-agent` or `agent.log`. Can it reach `CERTOWER_AGENT_URL`? Is 8443 passed through without TLS termination? |
| Deployment *Failed* | The certificate page shows the agent's message, e.g. `nginx -t` output or a path outside `allowedPaths`. |

Ask questions or report bugs on
[GitHub issues](https://github.com/tntrock/certower/issues); report
vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).

## Uninstalling

- Container: `docker rm -f certower`; delete the volume only if you are sure.
- Packages: `sudo apt remove certower` / `sudo dnf remove certower`. Data in
  `/var/lib/certower` and `/etc/certower` is kept; delete it yourself.
- Windows: *Settings → Apps → Certower Server → Uninstall*, or
  `msiexec /x certower_0.1.0_windows_amd64.msi /qn`. `C:\ProgramData\Certower`
  is kept.

Uninstalling does not revoke certificates; they stay valid until they
expire.
