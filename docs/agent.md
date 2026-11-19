# certower-agent

The agent runs on each host whose services use certificates. It:

- **generates private keys on the host**. They never leave it; the server
  only ever sees CSRs and public certificates.
- asks the server which certificates it holds and where they go, sends a CSR
  when one is due, and installs the issued certificate.
- **checks the live service** serves the new certificate after reloading, and
  restores the previous files if anything fails.
- only ever connects out to the server. Nothing listens on the host.

## How it talks to the server

The agent connects to the server's agent API (default port 8443) over HTTPS
with mutual TLS:

- The server's TLS certificate comes from a private **agent CA** that Certower
  creates on first start. When you enroll an agent, you give it the CA's
  SHA-256 fingerprint, and from then on it trusts only that CA. No public CA
  is involved, and server hostnames do not matter.
- Each agent gets its own client certificate from the agent CA at enrollment.
  It lasts 90 days and the agent renews it automatically when 30 days remain.
  Deleting the agent in Certower stops its certificate from working
  immediately.

## Install and enroll

1. In Certower, create an agent in a project:

   ```sh
   curl -X POST https://certower.example.com/api/v1/orgs/acme/projects/web/agents \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"name": "web-01"}'
   ```

   The response contains a one-time token (valid 24 hours by default) and the
   complete `command` to run on the host.

   In the web UI: **Agents & targets → Add agent**.

2. On the host, install the agent. The easiest way is the package from the
   [releases page](https://github.com/tntrock/certower/releases), which also
   installs the service: `certower-agent_<version>_amd64.deb` / `.rpm`, or
   `certower-agent_<version>_windows_amd64.msi` (see the
   [administrator guide](admin-guide.md#installing-agents)). Otherwise copy
   the `certower-agent` binary to `/usr/local/bin`. Then run the enroll
   command as root:

   ```sh
   certower-agent enroll -server https://certower.example.com:8443 \
     -token cwe_... -ca-sha256 3f2a... -allow-path /etc/certower
   ```

3. Review `/var/lib/certower-agent/agent.json` (see below), then start the
   service. With the packages: `sudo systemctl start certower-agent`, or on
   Windows `Set-Service CertowerAgent -StartupType Automatic; Start-Service CertowerAgent`.
   With a plain binary, create the unit yourself:

   ```ini
   # /etc/systemd/system/certower-agent.service
   [Unit]
   Description=Certower agent
   After=network-online.target
   Wants=network-online.target

   [Service]
   ExecStart=/usr/local/bin/certower-agent run
   Restart=always
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

   ```sh
   systemctl daemon-reload && systemctl enable --now certower-agent
   ```

The state directory is `/var/lib/certower-agent` on Linux and
`%ProgramData%\Certower\agent` on Windows. Change it with `-state` or
`CERTOWER_AGENT_STATE`.

## What the server may make the agent do

`agent.json` holds two allow-lists that only someone on the host can change:

```json
{
  "allowedPaths": ["/etc/certower"],
  "allowedCommands": [
    ["nginx", "-t"],
    ["nginx", "-s", "reload"],
    ["systemctl", "reload", "nginx"]
  ]
}
```

- Certificates and keys are written only inside `allowedPaths`. The check
  resolves symbolic links, so a link inside an allowed directory cannot
  point outside it.
- Commands run only if they match an entry exactly, program and arguments.
  They are executed directly, never through a shell.

So even someone in full control of the Certower server cannot use the agent
to overwrite arbitrary files or run arbitrary commands on your hosts.

## Deploying to nginx

1. Create a certificate whose key lives on the agent:

   ```json
   POST /api/v1/orgs/acme/projects/web/certificates
   {"name": "www", "names": ["www.example.com"], "issuer": "letsencrypt",
    "dns": "cloudflare", "keyLocation": "agent"}
   ```

2. Create a target on the agent and attach the certificate:

   ```json
   POST /api/v1/orgs/acme/projects/web/targets
   {"name": "web-01-nginx", "agent": "web-01", "deployer": "nginx",
    "settings": {"fullchainPath": "/etc/certower/www/fullchain.pem",
                 "keyPath": "/etc/certower/www/privkey.pem",
                 "verifyServerName": "www.example.com"}}

   POST /api/v1/orgs/acme/projects/web/certificates/www/targets
   {"target": "web-01-nginx"}
   ```

3. Point nginx at the files:

   ```nginx
   ssl_certificate     /etc/certower/www/fullchain.pem;
   ssl_certificate_key /etc/certower/www/privkey.pem;
   ```

On its next sync (every 30 seconds) the agent generates a key, the server
issues the certificate, and the agent writes the files, runs `nginx -t`, runs
`nginx -s reload`, and connects to `127.0.0.1:443` to confirm nginx serves the
new certificate. If the test, the reload or the check fails, it puts the
previous files back and reloads again. Watch the outcome with:

```sh
GET /api/v1/orgs/acme/projects/web/certificates/www/deployments
```

Failed deployments are retried after 2, 4, 8 … minutes, up to hourly.

### Deployer settings

| Setting | `files` | `nginx` |
|---|---|---|
| `fullchainPath` | leaf + intermediates | required |
| `certPath` | leaf only | optional |
| `chainPath` | intermediates only | optional |
| `keyPath` | required (written with mode 0600) | required |
| `testCommand` | none | `["nginx", "-t"]` |
| `reloadCommand` | none | `["nginx", "-s", "reload"]` |
| `verifyEndpoint` | none (not verified) | `127.0.0.1:443` |
| `verifyServerName` | | first certificate name |

`files` needs `certPath` or `fullchainPath`. Use it for any service that
reads certificate files, with the reload command it needs.

## Renewal

The server tells the agent when a certificate is due: inside the CA's ARI
window, when a third of its lifetime remains, after a manual `/renew`, or
after a revocation. The agent then generates a **new key** and sends a CSR.
Keys stay in the state directory (`keys/`) for 30 days after they stop
being used. If the host loses its keys, for example after a rebuild, the
agent requests a new certificate on its own.
