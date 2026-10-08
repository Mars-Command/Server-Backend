# Mars Command backend

The existing `/api/v1` package service remains unchanged. Batch 1 adds
SQLite-backed GitHub login, explicit desktop authorization, and metadata-only
community profiles under `/api/auth` and `/api/community`.

## Local setup (PowerShell)

Run from this repository, not another Mars Command checkout:

```powershell
Set-Location 'D:\Documents\Personal-Projects\Mars-Command\mars-command-backend'
& '.\.venv\Scripts\python.exe' -m pip install -r requirements-dev.txt
# Set environment variables individually; .env.example is NOT automatically loaded.
$env:MARS_RELEASE_DIR = 'D:\path\to\release'
$env:MARS_API_JWT_SECRET = '<separate-random-pack-secret>'
$env:MARS_PUBLIC_BASE_URL = 'http://localhost:8000'
$env:MARS_AUTH_JWT_SECRET = '<separate-random-community-secret-at-least-32-characters>'
$env:WEBSITE_URL = 'http://localhost:5173'
$env:MARS_AUTH_PUBLIC_URL = 'http://localhost:8000'
$env:MARS_COMMUNITY_DB = 'data\community.sqlite3'
$env:MARS_AUTH_ALLOW_LOCAL_HTTP = 'true'
$env:GITHUB_CLIENT_ID = '<registered-oauth-app-client-id>'
$env:GITHUB_CLIENT_SECRET = '<registered-oauth-app-client-secret>'
& '.\.venv\Scripts\python.exe' -m uvicorn server.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

The package service still requires a real release directory containing `mods`
and at least one JAR. Its existing manifest-preview endpoint still requires
`MARS_PUBLIC_BASE_URL` to be HTTPS; local HTTP does not relax that existing rule.
Use a GitHub OAuth App (not a browser-side GitHub access token), registering
`http://localhost:8000/api/auth/github/callback` for local development.
Use the production HTTPS callback for production. Never put the client secret
or community signing key in frontend configuration.

## Configuration and deployment requirements

See `.env.example`. Setting `MARS_AUTH_JWT_SECRET` enables community storage;
without it every new endpoint returns 503 `auth_not_configured`, without
affecting the package API. When enabled, missing/invalid origins, database path,
or a short/reused signing secret cause startup failure. OAuth start fails with
503 `github_not_configured` until both GitHub credentials exist.

* `WEBSITE_URL` and `MARS_AUTH_PUBLIC_URL` are exact origins, without `/api`,
  paths, queries, credentials or fragments. API clients append `/api/...`.
  Website `BASE_PATH` is not supported by backend redirects: login/verification
  always use origin-root `/auth/login`, and the API callback uses
  origin-root `/api/auth/github/callback`.
* Production requires HTTPS. Deploy frontend/backend on the **same site**,
  for example `www.example.com` and `api.example.com`. The host uses
  SameSite=Lax cookies; unrelated domains are intentionally unsupported.
* Local HTTP requires `MARS_AUTH_ALLOW_LOCAL_HTTP=true`, loopback origins and
  the same hostname (do not mix `localhost` and `127.0.0.1`).
* SQLite is durable single-host local storage, not a distributed database.
  Relative `MARS_COMMUNITY_DB` paths resolve against this repository, not cwd.
  Use a persistent local disk, restrict directory/WAL/backup permissions and
  encrypt disks/backups as needed. Do not use shared/network filesystems.
  Connections use foreign keys, WAL, 10-second busy timeout and serialized
  transactions. Windows filesystem ACLs must be configured by the operator.
* Use a secret manager/environment injection; never commit `.env`, databases,
  tokens, credentials, or provider responses. Rotate the signing key to revoke
  all desktop tokens; website sessions require deleting their database records.
* Disable access logs containing OAuth query strings at **all** proxies/server
  layers; callback codes/state are sensitive even though no JWTs enter URLs.
* Rate limits use the server's client IP, not arbitrary X-Forwarded-For.
  Configure trusted proxy handling narrowly; NAT/proxies may share a limit.
  Add edge abuse controls, TLS, backup/restore procedures and operational
  monitoring before production. No live deployment is validated by these tests.

## Authentication contract

`User = {id, username, avatarUrl, roles}`; IDs are stable `github:<numeric-id>`.
Roles are server-stored, default `[]`, and never accepted from client payloads.
Responses containing identities/private metadata use `Cache-Control: no-store`.

| Method/path | Body/query | Response |
| --- | --- | --- |
| GET `/api/auth/session` | website cookie | `{user: User \| null}` |
| POST `/api/auth/logout` | website cookie + trusted Origin | 204; deletes session/cookie |
| GET `/api/auth/github/start` | optional `requestId`, `switchAccount=1` | 302 to GitHub |
| GET `/api/auth/github/callback` | provider `state`, `code` or `error` | 303 to website `/auth/login` |
| POST `/api/auth/desktop` | `{}` | `{deviceCode, requestId, verificationUri, expiresIn:600, pollInterval:5}` |
| POST `/api/auth/desktop/poll` | `{deviceCode}` | `{status:'pending'\|'approved'\|'expired'\|'denied', accessToken?, user?}` |
| POST `/api/auth/desktop/approve` | `{requestId}`, website cookie + Origin | `{status:'approved'}` |

The callback retains a known `requestId` and uses `authResult=success` or
`authResult=error&errorCode=invalid_state|oauth_denied|oauth_failed`, never raw
provider errors/tokens. A replayed unknown state cannot recover its request ID.
OAuth state is cryptographically random, stored as a hash, expires in 10 minutes,
requires a separate browser-binding HttpOnly cookie, and is atomically consumed
before server-side exchange and `/user` identity verification.

Website sessions use a random opaque HttpOnly, SameSite=Lax cookie at `/api`,
Secure on HTTPS, with a fixed 7-day expiry persisted in SQLite. A new login rotates
the session. Logout invalidates only that session, not previously issued desktop
JWTs. Community JWTs are HS256, 15-minute expiry, audience
`mars-community-desktop`, issuer `mars-community-api`, scope `community`,
and include `sub/iat/exp/jti`. The separate pack JWT cannot authorize community
actions, and community JWTs cannot authorize the existing protected pack routes.

The desktop secret goes only to the initiating client. The public opaque
`requestId` alone cannot poll or obtain a JWT. The verification URL contains
only `requestId`. An approval binds a pending request to the approving session's
identity; expiry/reapproval fail, and polling issues the token once. Later polls
return `denied`, never another token. No token refresh or device-deny endpoint is
provided in this batch; abandonment expires after 10 minutes.

**Website requirement:** fetch session with `credentials: 'include'`, show the
current identity and require a deliberate confirmation button before POSTing
approval. Never approve on page load/login/callback. Account switching clears the
backend session but does not guarantee GitHub logout; prompt the user to choose
the intended GitHub account, then display the verified result before confirming.
The backend cannot prove the human saw a particular UI.

Cookie mutations require an exact `Origin: <WEBSITE_URL>`, including logout and
profile changes; missing/null/foreign origins are rejected. Approval accepts
website cookies only, not bearer JWTs. Desktop bearer tokens authorize profile
APIs without cookies/Origin. Exact-origin credentialed CORS is enabled; wildcards
are never used. Browser OAuth navigation can omit Origin; if supplied it must
match the trusted website.
Browser-marked cross-site OAuth-start navigation is also rejected; start login
from the website rather than linking directly to the API from another site.

Initiation limits: desktop and OAuth start, 10/IP/minute each; callback
30/IP/minute; approval 30/IP/minute; polling 120/IP/minute and at least 5 seconds
per device. Limits persist across app reopen/workers, with `429` and `Retry-After`.

## Profile contract (metadata only)

```text
ProfileMod = {name:string, version:string, sourceUrl:string, sha256:string}
Profile = {id:string, name:string, description:string,
  visibility:'private'|'public', owner:User, mods:ProfileMod[],
  sourceProfileId:string|null, updatedAt:string}
```

| Method/path | Behavior |
| --- | --- |
| GET `/api/community/profiles?q=` | `{profiles:Profile[]}`, public only, case-insensitive name/description search |
| GET `/api/community/profiles/mine` | `{profiles:Profile[]}`, authenticated owner's records |
| POST `/api/community/profiles` | `{name,description,mods,sourceProfileId?}` → 201 Profile, always private |
| PATCH `/api/community/profiles/{id}` | optional mutable fields above → Profile, owner only |
| DELETE `/api/community/profiles/{id}` | 204, owner only |
| POST `/api/community/profiles/{id}/submit` | owner only; **always 409 scanning_not_configured** |

PATCH is partial; explicit null for name/description/mods is invalid.
`sourceProfileId:null` clears attribution. A source ID must refer to a public
profile. Copies use the submitted independent metadata, belong to the new owner
and are private. Changes also withdraw any existing public record. Owner mismatch
returns 404 without exposing another owner's private metadata.

Limits: name/mod name 120 characters, description 4,000, version 80,
source URL 2,048, at most 200 mods/profile, at most 100 profiles/owner,
search query 120 characters, list responses at most 100, body at most 128 KiB.
Extra fields are rejected; hashes must be 64 hexadecimal characters and are
normalized lowercase. Sources must be public HTTPS URLs, without credentials,
fragments, nonstandard ports, control characters or private IP literals.
**No URL is fetched**; URL syntax/hash metadata is not evidence of authenticity,
licenses, scanning or safety. DNS-resolved destination checks will be needed if
fetching is ever introduced.

Errors follow `{detail:string|{code,message}}`; invalid input is a sanitized 422
`invalid_input` rather than returning submitted secret fields. Publishing returns:

```json
{"detail":{"code":"scanning_not_configured","message":"Publishing requires backend-validated mods; scanning is not configured"}}
```

Even empty profiles fail. There is no upload, download, scan registry, Sponsors
lookup, entitlement assignment or public publishing workflow. Do not bypass the
gate with client-provided flags/hashes. Configure scanning infrastructure, artifact
storage, provenance/license policies and Sponsors ownership/entitlement policy
before implementing those later milestones.

## Release-capsule foundations (internal only)

`server.capsules.CapsuleRegistry` uses the existing community SQLite store.
Each reservation gets a server-generated release ID and immutable uploader,
project/version, declared source and creation time. Declared source is attribution
metadata, not verified authorship, a license grant, or a URL to fetch. Backend
callers must supply the authenticated uploader ID, never a request's owner field.
No capsule HTTP endpoints are exposed in this increment.

Reservations are pending and have no artifact checksum. The internal `observe`
operation hashes a backend-observed byte stream within an explicit byte bound,
then atomically binds the release once to that checksum-addressed artifact.
It **does not upload or retain bytes**, validate a JAR, or perform a scan. A
failed/empty/oversized observation leaves no binding or artifact record.
Separate releases (including different uploaders or declarations) can share
identical bytes without sharing release identity/provenance. Deduplication does
not reset artifact state. Release metadata and artifact bindings cannot be edited;
changed content or provenance requires a new release ID.

Artifacts start `unscanned` and `unavailable`. The schema supports only negative
scan states (`unscanned`, `pending`, `rejected`, `error`) and unavailable storage;
there is no positive attestation setter. Both `require_publishable` and
`require_downloadable` fail closed, including on missing artifacts. Even
incompatible/forged positive database flags cannot bypass the final
`capsule_integration_not_configured` gate. Hashes and client scan results are
not accepted as evidence or metadata input. These gates are internal checks,
not working publish/download operations or a substitute for API authorization.

Next API integration is blocked on trusted binary ingestion and durable storage
availability verification, backend-only scan attestations bound to exact bytes,
and provenance/license/publication policy. Bucket, edge, queue and scanner
decisions remain unresolved; none are selected here. Existing profile submission
still returns `409 scanning_not_configured`; profile hashes remain untrusted
metadata and the existing `/api/v1` package routes are unchanged.

## Tests

```powershell
Set-Location 'D:\Documents\Personal-Projects\Mars-Command\mars-command-backend'
& '.\.venv\Scripts\python.exe' -m pytest tests\test_capsules.py tests\test_community.py -q -p no:cacheprovider
```

Tests use disposable fixtures **inside this repository** and mocked GitHub HTTP
responses. No credentials, real OAuth calls, uploads or remote source fetches.
See `sub_report-backend.md` for exact executed commands/results and blockers.
