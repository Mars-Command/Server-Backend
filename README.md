# Mars Command backend

Backend release: **0.3.0**.

`server/version.py` is the authoritative backend version source. FastAPI reads
that value for the runtime and OpenAPI `info.version`; `output/openapi.json`
must carry the same value. To prepare a backend release, update
`BACKEND_VERSION` there, regenerate/verify the checked-in OpenAPI document, and
run the full validation commands below. This backend version is independent of
`MARS_PACK_VERSION` and does not change package manifest version semantics.

The existing `/api/v1` download/authentication contracts remain available. Signed
pack publishing adds a separate server-to-server deployment API; community and
desktop credentials cannot publish packs. Batch 1 adds
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
$env:MARS_COMMUNITY_DB = 'data/community.sqlite3'
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
without it community/account endpoints return 503 `auth_not_configured`, without
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

The worker loads `.env.local`, then `.env`, from the backend root. Existing
process environment variables take precedence; `.env.example` is a template only.

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

## HTTPS signed-pack publishing

GitHub Actions can publish approved Minecraft pack files through the existing
HTTPS API. No SSH, Cloudflare SSH proxy, `scp`, `systemctl`, archive extraction,
remote commands, or backend-code upload is involved in normal pack updates.
This is separate from user capsule submission: it installs maintainer-signed
base packs and does not grant community submissions publication rights.

### One-time server bootstrap

The old running API cannot install this feature itself. Using the server's
local console or existing administration method:

1. Install this backend update and run `pip install -r requirements.txt` in
   the API's virtual environment. `cryptography` provides Ed25519 verification.
2. Set **`MARS_RELEASE_DEPLOY_TOKEN`** to a new random URL-safe value of
   32..128 characters. Set the same value as a protected **GitHub Actions
   secret** in the launcher repository. Do not reuse package JWT, community JWT,
   Minecraft integration, GitHub OAuth, or Cloudflare service credentials.
3. Set **`MARS_RELEASE_PUBLIC_KEY`** to the public pack-signing key trusted by
   the launcher. The current public pin is
   `a88e7dc70a1227cbc3decac967664e3bea75da9d72550e14f2c6a4ea8118391e`.
   The private signing key stays in maintainer/CI storage, never on the API.
4. Choose a persistent absolute **`MARS_RELEASE_PUBLISH_DIR`**, for example
   `/opt/mars-package-api/pack-publisher`, writable by the API service account.
   It must be separate from `MARS_RELEASE_DIR` and must not be served by a static
   web server. Without an override, the default is a sibling hidden directory.
5. Restart the API **once** to load the new code/environment. Keep the existing
   `MARS_RELEASE_DIR` intact as the legacy/bootstrap release.
      Its optional server-owned `mods.json` continues to provide API ID/name/version
      overrides for matching JAR filenames; clients cannot upload or replace it.

Without a deployment token, write endpoints return 503 `publishing_disabled`.
Read access to an already-active generation persists if you subsequently
disable publishing; keep its public key and publishing directory configured.
Production uses HTTPS through the current Cloudflare HTTP tunnel. Restrict
the publishing path further with Cloudflare Access **Service Auth** if desired;
the publishing script supports optional service credentials, but the backend
deployment token is still mandatory.

### Deployment contract

All these routes require `Authorization: Bearer <MARS_RELEASE_DEPLOY_TOKEN>`.
Authentication happens **before reading the request body**; browser-marked
requests/cookies, package-reader JWTs, and account credentials are not accepted.

| Method/path | Request | Result |
| --- | --- | --- |
| POST `/api/v1/releases/deployments` | `{manifestBase64, signature}` | Reserve the exact signed bytes and return declared upload/reuse progress |
| GET `/api/v1/releases/deployments/{id}` | deployment credential | Read resumable staging progress and active/published status |
| PUT `/api/v1/releases/deployments/{id}/files/{index}?offset=N` | raw `application/octet-stream` chunk | Acknowledged byte count and SHA-256-verified completion |
| POST `/api/v1/releases/deployments/{id}/commit` | `{}` | Verify every file, build serving indexes, and activate the complete release |

`id` is the SHA-256 of the exact manifest bytes. The signature is the existing
detached 128-character Ed25519 hex signature. The server verifies it **before
parsing**, then checks the schema, configured Minecraft/loader versions,
managed directories, unique/safe paths, hashes, and size limits. Only
hash-listed `files` manifests are accepted; unresolved `curseforgeMods` are not
deployable inventories. Neither request accepts an arbitrary filesystem path
or shell command. File indexes refer only to the signed declaration.
The manifest bytes are never rewritten. Signature text is stored as canonical
lowercase hex; whitespace/case in a local hex signature file is not signed data.

Uploads are limited to **8 MiB per request**, so larger JARs/resource packs can
cross the HTTP tunnel without one giant request. Default limits are **512 MiB
per file**, **4 GiB per pack**, **three staged deployments**, and **one active
hour to finish staging**. The manifest limit is 8 MiB, with at most 20,000
declared files. Limits are configurable in `.env.example`.
Exact chunk retries are idempotent, partial transfers resume from the
acknowledged offset, and final mismatched hashes are rejected/reset explicitly.

The publish step reuses existing files only when their signed size/hash match,
and copies them into a new immutable generation. Missing or changed files must
be uploaded; they cannot be skipped because a manifest says they exist.
Unlisted files are never added to the new serving inventory.

All generation bytes and serving indexes are verified before a serialized
SQLite transaction switches the active-generation pointer. Concurrent stale
deployments cannot overwrite a newer activation. Published pack versions must
increase after the first API-managed activation; republishing the exact active
manifest is idempotent, not a mutation or rollback.

The public manifest/signature endpoints, payload route, authenticated mod list,
mod downloads, and manifest preview read the same active snapshot. API workers
detect the persistent pointer and refresh their local indexes automatically:
**no restart is needed for pack publication**. In-flight requests retain paths
to previous immutable generations. Separate client requests can still straddle
an activation; clients continue to fail closed/retry if a manifest and signature
do not match. Manifest responses now require cache revalidation; proxies must
not override these cache headers with stale fixed-TTL rules.

### Storage, durability and operations

Publishing uses single-host local SQLite/WAL with full synchronous durability
and immutable generation directories. Use persistent local disk, not shared/NFS
storage. Restrict filesystem permissions; encrypt backups as appropriate.
Back up the publishing database/WAL and generation files **together**, plus
the unchanged legacy release. The API stores no deployment token in that DB.

Expired staging data is cleaned on the next reservation. Previously published
generations are retained rather than deleted under readers. Monitor disk usage;
garbage collection and explicit rollback/accounting retention are not automatic
in this milestone. Do not manually edit active or retained generation files.
Corrupt/unavailable active storage fails explicitly rather than serving a stale
or unsigned fallback.

After bootstrap, run the launcher's updated **Publish pack manifest** workflow.
For the existing pack 1.2.5, use `source_release=v1.2.5` and
`payload_asset=mars-command-mod-0.4.0.jar`. Its already-signed manifest is
preserved; the declared JAR is uploaded only if not reusable on the server.
The workflow verifies the exact live manifest bytes and matching hex signature after
publication. Installing the endpoint is not itself a deployment of pack 1.2.5.

## Minecraft player arrival

Minecraft arrival reuses the same GitHub OAuth start/callback and website
session, but has a separate authorization purpose from desktop launcher login.
Deploy the updated backend and website together before enabling it on a server.

Set `MARS_MINECRAFT_SERVER_TOKEN` to a separate random URL-safe ASCII value of
32..128 characters, and inject the matching value into the Minecraft server
process. It is not a package/community JWT, browser credential, or public player
ID. Never put it in `VITE_*`, URLs, client config, or source control.

| Method/path | Authorization / body | Result |
| --- | --- | --- |
| GET `/api/auth/requests/{request_id}` | website cookie | Server-derived `desktop`/`minecraft` purpose, status, callsign/name for arrival requests |
| POST `/api/auth/minecraft/arrival` | server bearer credential; `{minecraftUuid, playerName}` | Permanent callsign and confirmed context, or a bound pending challenge |
| POST `/api/auth/minecraft/poll` | server bearer credential; `{minecraftUuid, deviceCode}` | `pending`, approved account name, `expired`, or `denied`; never a JWT |
| POST `/api/auth/minecraft/approve` | website cookie + exact Origin; `{requestId}` | Browser approval only; does not finalize player linking |
| POST `/api/auth/minecraft/confirm` | server bearer credential; `{minecraftUuid, deviceCode, expectedAccountName}` | Finalizes the in-game-reviewed identity atomically |
| GET `/api/auth/minecraft/context/{minecraft_uuid}` | server bearer credential | Limited player context |

The UUID is canonical lowercase Minecraft UUID text, not a shortened UUID.
Calls are accepted only from trusted server integrations; enable Minecraft
`online-mode=true` to establish player ownership. API credentials trust the
operator's server, not a public caller supplying someone else's UUID.

Callsigns are permanent four-digit strings (`0000`..`9999`) allocated under the
existing serialized SQLite transaction with a uniqueness constraint. The
10,000-ID capacity fails explicitly rather than recycling identities.
Registration of the same UUID preserves its callsign, including after restarts.
Minecraft linking is one website account to one Minecraft UUID; conflicting
links are rejected, not overwritten. Back up the registry with the community DB.

Challenges are random, hashed in storage, UUID-bound, expire after 10 minutes,
and are invalidated when a new link starts. Only the server receives `deviceCode`.
The website verification URL carries only the opaque `requestId`. Website
approval names the current authenticated account; in-game finalization checks
the reviewed account name and consumes the challenge once. Forwarding a URL
alone cannot finalize the Minecraft account link.

Minecraft-purpose requests cannot use desktop approval/polling to obtain a
community token. Cookie approval cannot be replaced with a server bearer key,
and server operations reject browser-marked requests. Existing pack, desktop,
and community authorization behavior remains separate.

Context is restricted to `{minecraftUuid, callSign, confirmed, accountName,
roles}`. Roles are server-stored and bounded; no private profiles, artifacts,
provider secrets, session tokens, or avatar data are returned. This supports
future Moon context but does not run a model or grant Minecraft operator rights.
Operational account recovery/rebinding is not an automatic endpoint in this
milestone.

## Tests

```powershell
Set-Location 'D:\Documents\Personal-Projects\Mars-Command\mars-command-backend'
& '.\.venv\Scripts\python.exe' -m pytest tests\test_capsules.py tests\test_community.py tests\test_ingestion.py tests\test_minecraft.py tests\test_release_publishing.py -q -p no:cacheprovider
& '.\.venv\Scripts\python.exe' -m compileall -q server tests
git diff --check
```

Tests use disposable fixtures **inside this repository** and mocked GitHub HTTP
responses and private local JAR fixtures. No real credentials, OAuth calls, scanner
calls or remote source fetches. See `doc\reports\batch-3-backend.md` for results.
