# Certower user guide

[繁體中文](zh-TW/user-guide.md) | [简体中文](zh-CN/user-guide.md)

This guide is for the people who use Certower every day: requesting and
renewing certificates, deploying them to servers, finding certificates
nobody manages, and getting alerts. Installing and running the server is
covered in the [administrator guide](admin-guide.md).

- [Quick start](#quick-start)
- [Concepts](#concepts)
- [Signing in](#signing-in)
- [Roles](#roles)
- [Connecting a CA and a DNS provider](#connecting-a-ca-and-a-dns-provider)
- [Requesting a certificate](#requesting-a-certificate)
- [Working with a certificate](#working-with-a-certificate)
- [Deploying with agents](#deploying-with-agents)
- [Discovery: finding certificates you don't manage](#discovery-finding-certificates-you-dont-manage)
- [Notifications](#notifications)
- [Policy](#policy)
- [Members](#members)
- [Audit log and jobs](#audit-log-and-jobs)
- [FAQ](#faq)

## Quick start

From nothing to an automatically renewed certificate, assuming your DNS is
on Cloudflare:

1. Sign in, pick your organization and project in the sidebar.
2. **Integrations → Add integration → Issuer**: choose
   *Let's Encrypt (staging)* for a first test, enter a contact email, and
   agree to the terms.
3. **Add integration → DNS**: choose *cloudflare* and paste an API token
   with *Zone:Read* and *DNS:Edit* for your zone.
4. **Certificates → New certificate**: a name such as `www`, the domain
   names (one per line), the issuer and DNS provider you just added.
   Keep the key *On the Certower server*. **Request certificate**.
5. Within a minute or two the certificate is *Active*. Download the chain,
   or deploy it with an [agent](#deploying-with-agents).
6. Once it works, add a *Let's Encrypt* (production) issuer and switch to
   it. Certower renews on its own from now on.

## Concepts

| Term | Meaning |
|---|---|
| **Organization** | A company or department. Holds projects, shared integrations, discovery, and members. |
| **Project** | A group of certificates managed together, e.g. "Web services" or "ERP". Permissions and policy apply per project. |
| **Certificate** | What you want to exist: names, issuer, key type, where the key lives. Certower issues it and keeps renewing it. Each issuance is a **version**. |
| **Issuer** | An account at a certificate authority (CA) that speaks ACME: Let's Encrypt, ZeroSSL, Google Trust Services, Sectigo, GlobalSign, DigiCert, TWCA, and others. |
| **DNS provider** | Credentials Certower uses to create the temporary DNS record that proves you control a domain (DNS-01). |
| **Integration** | An issuer, DNS provider, or notifier configuration. Organization integrations are shared by every project; project integrations are private to one project. |
| **Agent** | A small program on your server that keeps private keys there and installs certificates into services such as nginx. |
| **Target** | A place on an agent's host where a certificate is installed, e.g. "the nginx on web-01". |
| **Policy** | Limits on what a project may request: domains, CAs, key types, wildcards, validity. |

## Signing in

Sign in with your email and password, or with the single sign-on button
(*Sign in with …*) if your administrator set one up. The language follows
your browser; change it with the selector on the sign-in page or at the
bottom of the sidebar (English, 繁體中文, 简体中文).

- **Change your password**: sidebar → **Change password**. Your other
  sessions are signed out.
- **Forgot your password**: ask an instance administrator to reset it.
- After repeated wrong passwords, sign-in is blocked for a few minutes.
- A session lasts 12 hours.

## Roles

What you can do depends on the roles you hold in an organization or
project. A role on the organization applies to all its projects.

| Role | Can |
|---|---|
| **Viewer** (`viewer`) | See certificates and discovery results. |
| **Operator** (`operator`) | Viewer, plus request, renew, revoke, and deploy certificates, using the configured integrations. |
| **Project admin** (`project_admin`) | Operator, plus manage integrations and their secrets, agents and targets, discovery endpoints, members, and API tokens; read the audit log. |
| **Organization admin** (`org_admin`) | Project admin for every project, plus create projects and set policy. |
| **Auditor** (`auditor`) | Viewer, plus read the audit log. |

No role can export private keys; that permission must be granted
explicitly through a custom role. **Instance administrators** additionally
manage user accounts and create organizations.

## Connecting a CA and a DNS provider

Open **Integrations** (shared by the organization) or a project's
**Project integrations** (that project only; a project integration with the
same name overrides the shared one). Choose **Add integration**.

### Issuer (CA)

| Field | Notes |
|---|---|
| CA preset | Pick your CA; the ACME address is filled in. *Custom* for any other ACME CA. |
| Contact email | The CA sends account notices here. |
| External Account Binding | Required by ZeroSSL, Google Trust Services, Sectigo, GlobalSign, DigiCert, and TWCA. Copy the *Key ID* and *HMAC key* from your CA account. |
| I agree to the CA's terms | Required. |
| Default ACME profile | Optional, e.g. `shortlived` at Let's Encrypt. |

The account key is generated for you. Secrets are encrypted and cannot be
viewed again after saving; to change one, type a new value.

Taiwan users: TWCA supports ACME with External Account Binding. Chunghwa
Telecom (HiPKI/ePKI) certificates issued after 2025-07-31 are distrusted by
Chrome and have no public ACME service; [discovery](#discovery-finding-certificates-you-dont-manage)
flags them. See [CA support](ca-support.md).

### DNS provider

Certower proves domain control with DNS-01: it adds a TXT record, waits
until it is visible, and removes it afterwards. This works for wildcard
certificates and for servers not reachable from the internet.

For Cloudflare, create an API token (*My Profile → API Tokens → Create
Token → Edit zone DNS*) limited to the zones you need, with *Zone:Read* and
*DNS:Edit*.

## Requesting a certificate

**Certificates → New certificate**:

| Field | Notes |
|---|---|
| Name | Short identifier, e.g. `www`. |
| Domain names | One per line. The first becomes the subject. `*.example.com` needs wildcards allowed by policy. |
| Issuer, DNS provider | From your integrations. |
| Key type | ECDSA P-256 is the modern default; choose RSA 2048+ for old clients. |
| Where is the private key kept? | **On the Certower server**: encrypted, issued at once, downloadable as files. **On an agent's host**: generated on that host and never leaves it; issued when you attach a target. |
| ACME profile | Optional; *CA default* otherwise. |
| Owner email | Who is responsible; shown on the certificate. |

States you will see:

| State | Meaning |
|---|---|
| **Pending** | Not issued yet (or waiting for a target, for agent keys). |
| **Active** | Has a valid certificate. |
| **Failing** | The last attempt failed and will be retried, with growing delays (1 minute up to 6 hours). The page shows the error. |
| **Needs attention** | Issuance stopped until someone fixes the cause, e.g. a policy violation, a rejected request, or missing settings. |

## Working with a certificate

Open a certificate to see its names, key, current version, renewal time,
history, and deployments.

- **Renewal is automatic**: inside the window the CA suggests (ARI), or when
  a third of the lifetime remains. *Renews* shows when.
- **Renew now**: queue a renewal immediately, e.g. after changing names.
- **Download chain**: the certificate and intermediates as PEM.
- **Revoke**: asks the CA to revoke the current version, with a reason
  (use *Key compromise* if the key may have leaked). Certower then issues a
  replacement automatically.
- **Delete**: Certower stops managing the certificate and erases its stored
  key. This does **not** revoke it; revoke first if needed.

## Deploying with agents

With an agent, keys are generated on your server and certificates are
installed and reloaded automatically at every renewal.

1. **Agents & targets → Add agent**: give it a name (e.g. the host name).
   Copy the enrollment command; the token works once.
2. Your administrator (or you, with root on the host) installs the agent and
   runs the command; see the [administrator guide](admin-guide.md#installing-agents).
   The agent shows as *Online*.
3. **New target** on that agent:
   - **nginx**: paths for the full chain and the key. Certower writes
     them, runs `nginx -t`, reloads nginx, and checks that `127.0.0.1:443`
     serves the new certificate; if not, it restores the old files.
   - **files (any service)**: writes the files, optionally runs a reload
     command allowed on the host.
4. On the certificate page, **Attach target**. The *Deployments* section
   shows each target's state and any error.

The host's `agent.json` decides which directories the agent may write and
which commands it may run, so a target pointing elsewhere fails with a
clear message. Details: [agent guide](agent.md).

## Discovery: finding certificates you don't manage

**Discovery** checks what your servers actually present, including
certificates bought by hand, forgotten appliances, and certificates from
other teams.

1. **Add endpoints**: one per line, `host` or `host:port` (default 443).
   Choose a project (its members see them and its notifiers get alerts) or
   the whole organization.
2. Certower scans right away and then every 12 hours. **Scan now** rescans.
3. Filter by *With problems* or *Unmanaged*. Click a row for details.

| Finding | Meaning |
|---|---|
| Expired / Expiring soon / Not yet valid | Validity problems. |
| Distrusted root CA | Chains to a root browsers no longer trust for new certificates, e.g. Chunghwa Telecom after 2025-07-31. |
| Name mismatch | The certificate does not cover the host name. |
| Untrusted chain | Missing intermediate, self-signed, or private CA. |
| SHA-1 signature, Weak key | Outdated cryptography. |
| Validity too long | Longer than the CA/Browser Forum limit at its issue date (200 days from 2026-03-15, 100 days from 2027-03-15, 47 days from 2029-03-15). |

*Managed* means the certificate served is one Certower issued.

## Notifications

**Integrations → Add integration → Notifications**:

- **webhook**: format *json* (signed, for your own systems), *slack* (also
  Mattermost and Google Chat), or *discord*.
- **email**: your SMTP server, sender, and recipients.

Each notifier can be limited to some events and a minimum severity. Use
**Send test** to check it. Events:

| Event | When |
|---|---|
| Certificate issued | After every issuance or renewal. |
| Issuance failed | An attempt failed, or issuance stopped. |
| Expiring | 21, 14, 7, 3, and 1 days before expiry, and on expiry. |
| Deployment failed | An agent could not install or verify a certificate. |
| Discovery finding | A scan found a critical problem. |

Details and the webhook signature format:
[discovery and notifications](discovery-and-notifications.md).

## Policy

Organization administrators set each project's **Policy**:

- **Allowed domain names**: e.g. `*.example.com` allows every name under
  example.com. Empty allows any.
- **Allowed issuers**: integration names. Empty allows any.
- **Allowed key types**.
- **Allow wildcard certificates**: off by default.
- **Maximum validity (days)**.

Requests outside the policy are refused with the reason, and existing
certificates that no longer comply stop renewing until fixed.

## Members

**Members** (organization) and **Project members** grant roles:

- **User (email)**: the person must already have an account.
- **Identity provider group**: everyone in that SSO group gets the role,
  following your directory automatically.
- **Service account** (projects): for automation with API tokens.

You can only grant roles whose permissions you hold yourself.

## Audit log and jobs

- **Audit log** (organization): every change, with who made it, when, and
  from which address. Requires *Project admin*, *Organization admin*, or
  *Auditor*.
- **Jobs** (project): the background work queue: issuance, renewals,
  notifications, scans, with attempts and the last error.

## FAQ

**Can Certower renew certificates from my current paid CA?** If the CA
offers ACME (most do now, usually with External Account Binding), yes.
Otherwise Certower can still track it through discovery.

**What happens if Certower is down for a day?** Nothing visible:
certificates are renewed weeks before they expire, and renewals resume
when it is back.

**Where are private keys?** For server-kept keys, encrypted in Certower's
database. For agent-kept keys, only on that host.

**Can I use the API?** Yes. Everything in the UI is in the
[REST API](api.md), with service account tokens for automation.
