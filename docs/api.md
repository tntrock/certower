# REST API

All endpoints are under `/api/v1` and exchange JSON. Errors look like:

```json
{"error": {"code": "forbidden", "message": "missing permission policy.manage"}}
```

## Authentication

| Credential | How to get it | How to send it |
|---|---|---|
| Session (`cws_…`) | `POST /auth/login` | `Authorization: Bearer <token>`, or the `certower_session` cookie set by login |
| API token (`cwt_…`) | `POST …/service-accounts/{sa}/tokens` | `Authorization: Bearer <token>` |

Requests authenticated by cookie that change state must use
`Content-Type: application/json`. Together with `SameSite=Strict` this blocks
cross-site request forgery.

The first administrator is created on the command line:

```sh
certower bootstrap -email admin@example.com
```

## Authorization

- **Instance administrators** (`isSuperuser`) create organizations and users
  and can do everything except export private keys.
- Everyone else acts through **role bindings** on an organization or a
  project. See [architecture.md](architecture.md#multi-tenancy-and-authorization).
- Callers with no binding in an organization or project get `404`, not `403`,
  so its existence is not revealed.
- You can only grant or revoke a role whose permissions you hold yourself in
  that scope.

## Endpoints

| Method | Path | Permission |
|---|---|---|
| POST | `/auth/login` | none |
| POST | `/auth/logout` | authenticated |
| GET | `/me` | authenticated |
| GET, POST | `/users` | instance admin |
| GET | `/orgs` | lists orgs you belong to |
| POST | `/orgs` | instance admin |
| GET | `/orgs/{org}` | any binding in the org |
| GET | `/orgs/{org}/audit?project=&before=&limit=` | `audit.read` |
| GET | `/orgs/{org}/roles` | any binding in the org |
| POST | `/orgs/{org}/roles` | `member.manage` (org level) |
| GET, POST | `/orgs/{org}/bindings` | `member.manage` (org level) |
| DELETE | `/orgs/{org}/bindings/{id}` | `member.manage` (org level) |
| GET | `/orgs/{org}/projects` | lists projects you can read |
| POST | `/orgs/{org}/projects` | `project.manage` |
| GET | `/orgs/{org}/projects/{project}` | `cert.read` |
| DELETE | `/orgs/{org}/projects/{project}` | `project.manage` |
| GET | `/orgs/{org}/projects/{project}/policy` | `cert.read` |
| PUT | `/orgs/{org}/projects/{project}/policy` | `policy.manage` (org level) |
| GET, POST | `/orgs/{org}/projects/{project}/bindings` | `member.manage` |
| DELETE | `/orgs/{org}/projects/{project}/bindings/{id}` | `member.manage` |
| GET, POST | `/orgs/{org}/projects/{project}/service-accounts` | `token.manage` |
| DELETE | `/orgs/{org}/projects/{project}/service-accounts/{sa}` | `token.manage` |
| POST | `/orgs/{org}/projects/{project}/service-accounts/{sa}/tokens` | `token.manage` |

Unauthenticated: `GET /healthz`, `GET /api/v1/version`, `GET /api/v1/ca-presets`.

## Example

```sh
TOKEN=$(curl -s -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"..."}' | jq -r .token)

curl -X POST localhost:8080/api/v1/orgs -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"slug":"acme","name":"ACME"}'

curl -X POST localhost:8080/api/v1/orgs/acme/projects -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"slug":"shop"}'

curl -X PUT localhost:8080/api/v1/orgs/acme/projects/shop/policy -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"allowedNames":["*.shop.example.com"],"allowWildcard":true,"maxValidityDays":100}'
```
