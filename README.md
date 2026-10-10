# Mars Command backend

Backend release: **0.3.0**.

`server/version.py` is the authoritative backend version source. FastAPI reads
that value for the runtime and OpenAPI `info.version`; `output/openapi.json`
must carry the same value. To prepare a backend release, update
`BACKEND_VERSION` there, regenerate/verify the checked-in OpenAPI document, and
run the full validation commands below. This backend version is independent of
`MARS_PACK_VERSION` and does not change package manifest version semantics.

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
  Connections use foreign keys, required WAL mode, full synchronous durability,
  a 10-second busy timeout and serialized transactions. Reopening an existing
  community database installs missing internal capsule tables without replacing
  community data. Windows filesystem ACLs must be configured by the operator.
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

Even empty profiles fail. Capsule ingestion below is separate from profile
publication. There is no public capsule download, Sponsors lookup, entitlement
assignment or public publishing workflow. Never trust client scan flags/hashes.

## Private capsule ingestion (Batch 3)

Community authentication is required for every capsule endpoint. Website cookies
retain exact-Origin protection on mutations; native clients use the existing
community bearer, never a package token. Owner mismatches return 404.

| Method/path | Input/result |
| --- | --- |
| POST `/api/community/capsules` | `{project,version,sourceUrl}` + required `Idempotency-Key` header → 201 Capsule |
| GET `/api/community/capsules/mine` | `{capsules:Capsule[]}`, newest 100 owned releases |
| GET `/api/community/capsules/{release_id}` | Capsule, owner only |
| PUT `/api/community/capsules/{release_id}/artifact` | raw `application/java-archive` or `application/octet-stream` → Capsule |
| POST `/api/community/capsules/{release_id}/retry` | no body → Capsule |
| POST `/api/community/capsules/{release_id}/withdraw` | no body → Capsule |

Project is trimmed, 1–120 characters; version is trimmed, 1–80; source is
1–2,048 and must pass the public HTTPS rules above. Hostnames must contain a dot
and cannot be `localhost`, `.localhost` or `.local`; backslashes and characters
below ASCII 33 or ASCII 127 are forbidden. IP literals must be globally routable.
Metadata is never fetched or DNS-resolved and does not establish license/authorship.
Extra metadata fields (including owner, hash or scan verdict) are rejected.
Idempotency keys match `[A-Za-z0-9._:-]{1,128}`, scoped to owner. Replaying identical
metadata returns the same release (201); changed metadata returns `idempotency_conflict`.

Capsule fields: `releaseId` (32 lowercase hex), `ownerId`, `project`, `version`,
`sourceUrl`, `createdAt`, `artifactSha256` (64 lowercase hex or null), `state`,
`revision` (positive, monotonic), `updatedAt`, `evidence`, `queue`, and
`publicDownloadAvailable` (**always false**). Timestamps are ISO UTC strings.
Queue is null before binding, otherwise `{status,attempts,maxAttempts,nextAttemptAt,lastError}`.
Status is `pending|leased|complete|blocked|failed`; attempt counts are nonnegative.
`nextAttemptAt` is null unless pending; errors are sanitized machine codes.
Evidence is null before a result, otherwise `{version,artifactSha256,provider,
providerResultId,policyVersion,scannedAt,expiresAt,verdict,summary}`. Verdict is
`accepted|rejected|blocked|error`; result identifiers and summaries are normalized
nonempty machine codes. Responses never expose paths, lease tokens, raw references,
provider credentials or a download URL. `output/openapi.json` is authoritative.

State flow: `reserved → uploading → quarantined → scan_pending`, then `scan_blocked`,
`rejected` or `publishable`. Interrupted/invalid uploads return to `reserved`.
Identical-byte upload retries return current status; different bytes cannot rebind
a release (`release_already_bound`). `scan_blocked` retries require available
quarantine bytes, a non-leased job and remaining attempt budget; `scan_pending`
pending/leased retries are idempotent. Rejected releases cannot retry. Withdrawal
is idempotent and supports any nonexpired unpublished state (including uploading
and publishable). Expired/withdrawn releases cannot upload. Immutable release facts
and bindings survive deduplication; digest/policy jobs are shared, not ownership.

Errors use `{detail:{code,message}}`: 409 `idempotency_conflict`,
`upload_in_progress`, `release_already_bound`, `invalid_state`, `submission_limit`,
`retry_not_eligible`; 404 `release_not_found`; 413 `artifact_too_large`; 422
`invalid_input`, `artifact_empty`, `artifact_invalid`; 415 `unsupported_media_type`;
408 `upload_timeout`; 503 `storage_unavailable`, `artifact_unavailable`, plus existing
authentication/rate errors. Owner mutations/reads are limited to 30/action/minute.

### Storage and worker operation

Default private buckets are `<database parent>\capsule-private\quarantine`,
`\retained`, and `\evidence`; environment overrides must be absolute, nonoverlapping
and outside public/static/output/dist/package release directories. Links/junctions
in bucket ancestors are rejected. Startup creates protected Windows DACLs allowing
only the service account and SYSTEM (POSIX directories 0700, files 0600). Use the
same service identity for API and worker. Do not configure static servers, proxies,
CDNs or package routes to serve these buckets. Restrict disk access and execution
with OS/container policy; an upload is never loaded/executed by the backend.

Uploads are streamed, SHA-256 computed from observed bytes, bounded while reading,
validated without ZIP extraction, fsynced and atomically moved. Unsafe member paths,
symlinks, encrypted entries, duplicate names, CRC failures, more than 10,000 entries,
over 4× configured expanded size or over 100× compression ratio are rejected.
An archive needs at least a `.class` or `META-INF/MANIFEST.MF` member.
Defaults: 64 MiB, 10 active releases/owner, 7-day abandoned/failed expiry, 300s upload
timeout/worker lease, 3 attempts, 30s exponential retry (capped 3,600s), 24h evidence TTL.
All limits must be positive bounded integers. See `.env.example` for overrides.

Run separately with the same community/database/bucket configuration:

```powershell
& '.\.venv\Scripts\python.exe' -m server.worker --once
& '.\.venv\Scripts\python.exe' -m server.worker --poll-seconds 5 --worker-id worker-1
```

The first cleans up/processes at most one job; the second loops until SIGINT/SIGTERM.
SQLite atomically leases jobs, fences stale completions and records attempts,
versioned immutable evidence and state history. Expired leases recover with bounded
backoff; exhausted attempts preserve failure reasons. Cleanup expires abandoned
reservations/failed states and removes old artifacts only without another live
release/lease; raw evidence is retained for audit. Back up and restore the SQLite
database **and all three buckets together**, with API/worker stopped or a coordinated
consistent snapshot; do not copy an active database without its WAL. Keep persistent
single-host local disk (no unsupported shared/network filesystem). Restores with
missing/modified bytes fail eligibility checks rather than trusting database flags.

Only `MARS_CAPSULE_SCANNER=disabled` is permitted in production. The worker records
`blocked` / `scanning_not_configured`, never a clean result. Test scanners are
injected only by tests; configuring `clean` or another adapter fails startup.
`publishable` requires exact digest/current policy, trusted backend-generated accepted
evidence within TTL, source metadata and hash-verified retained bytes. It means
future eligibility, **not public availability**. The legacy `CapsuleRegistry`
keeps its negative-only gates; no capsule download/install/publication endpoint
or profile-publication bypass is added. Provider usage rights, provenance/license
policy and real scanner integration remain deferred.

## Tests

```powershell
Set-Location 'D:\Documents\Personal-Projects\Mars-Command\mars-command-backend'
& '.\.venv\Scripts\python.exe' -m pytest tests\test_capsules.py tests\test_community.py tests\test_ingestion.py -q -p no:cacheprovider
& '.\.venv\Scripts\python.exe' -m compileall -q server tests
git diff --check
```

Tests use disposable fixtures **inside this repository** and mocked GitHub HTTP
responses and private local JAR fixtures. No real credentials, OAuth calls, scanner
calls or remote source fetches. See `doc\reports\batch-3-backend.md` for results.
