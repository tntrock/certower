# Authentication

Certower accepts three kinds of credentials:

- **Password sessions** for people, through the web UI or `POST /api/v1/auth/login`.
- **Single sign-on** through any OpenID Connect provider (Google, Microsoft
  Entra ID, Okta, Keycloak, Authentik, ...).
- **API tokens** (`cwt_...`) for service accounts. See [the API](api.md).

## Login rate limiting

Failed password logins are counted per account and per client address in a
sliding 15-minute window:

| Key | Limit |
|---|---|
| Account (email) | 10 failures |
| Client address (IPv6 grouped by /64) | 30 failures |

Over either limit, login answers `429 Too Many Requests` with `Retry-After`,
even for the right password. A successful login clears the account's count.
Counts live in memory, per server process.

Behind a reverse proxy, every request comes from the proxy's address. Tell
Certower which proxies to trust so it reads the client address from
`X-Forwarded-For`:

```sh
certower serve -trusted-proxies 10.0.0.0/8,192.0.2.10
# or CERTOWER_TRUSTED_PROXIES=10.0.0.0/8,192.0.2.10
```

Only list proxies you run. An untrusted peer's `X-Forwarded-For` is ignored.

## Single sign-on (OpenID Connect)

1. Register Certower with your provider as a confidential web application,
   with redirect URI `https://certower.example.com/api/v1/auth/oidc/callback`.
2. Start the server:

   ```sh
   export CERTOWER_OIDC_CLIENT_SECRET=...   # never passed as a flag
   certower serve \
     -public-url https://certower.example.com \
     -oidc-issuer https://accounts.google.com \
     -oidc-client-id 1234.apps.googleusercontent.com \
     -oidc-name Google \
     -oidc-allowed-domains example.com \
     -secure-cookies
   ```

The login page then shows **Sign in with Google**.

| Flag (env) | Meaning |
|---|---|
| `-oidc-issuer` (`CERTOWER_OIDC_ISSUER`) | Issuer URL; enables SSO. Needs `-public-url`. |
| `-oidc-client-id` (`CERTOWER_OIDC_CLIENT_ID`) | Client ID. |
| `CERTOWER_OIDC_CLIENT_SECRET` | Client secret, from the environment only. |
| `-oidc-name` | Button label. Default `SSO`. |
| `-oidc-scopes` | Default `openid,email,profile`. Add the scope your provider needs for groups. |
| `-oidc-groups-claim` | ID token claim listing groups. Default `groups`. |
| `-oidc-allowed-domains` | Email domains allowed to sign in. Empty allows any. |
| `-oidc-auto-create` | Create accounts on first sign-in. Off: an administrator creates the user first. |
| `-oidc-insecure-skip-email-verified` | Accept emails without `email_verified: true`. See below. |

### How sign-in maps to accounts

1. An account already linked to the provider's subject (`iss` + `sub`) signs
   in, even if its email changed at the provider.
2. Otherwise, an account with the same **verified** email is linked to the
   subject. An account already linked to a different subject is refused, so
   a second identity with the same email cannot take it over.
3. Otherwise, with `-oidc-auto-create`, a new account is created with no
   roles and no password. Without it, sign-in is refused.

Disabled accounts are refused. SSO-only accounts have no password, so
password login never works for them.

Because step 2 links by email, only trust providers that verify email
addresses. Some (notably Microsoft Entra ID) omit `email_verified`; use
`-oidc-insecure-skip-email-verified` only if you know the provider verifies
the addresses it issues, and combine it with `-oidc-allowed-domains`.

### Groups

Role bindings can name an identity provider group instead of a user
(**Members → Add → Identity provider group** in the UI). The groups in the
ID token are recorded with the session, so a change at the provider takes
effect at the next sign-in. Sessions last 12 hours.

### Flow security

The authorization code flow uses PKCE (S256), a `state` value and an ID
token `nonce`, all kept in a 10-minute HttpOnly cookie scoped to the
callback path. The ID token's signature, issuer, audience and expiry are
checked against the provider's published keys. The session cookie itself is
`SameSite=Strict`.
