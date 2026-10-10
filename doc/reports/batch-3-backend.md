# Batch 3 backend implementation report

## Scope and version

Implemented only in `mars-command-backend`, against the approved Batch 3 plan.
Backend/OpenAPI version is **0.3.0**. Existing package API, authentication,
private profile behavior and internal capsule registry remain compatible.
No other repository, roadmap or release tag was modified; no commit was created.

## Exact changed files

| File | Change |
| --- | --- |
| `.env.example` | Private bucket, limits, disabled-scanner and worker configuration examples |
| `.gitignore` | Ignore default `capsule-private` folders |
| `README.md` | Version, capsule contract, private storage/worker/backup operations and validation |
| `server/community.py` | Settings integration, additive migration hookup, authenticated owner APIs, streaming middleware exception, CORS and sanitized errors |
| `server/ingestion.py` | New validated private filesystem workflow, JAR validation, SHA-256 binding, SQLite queue/leases/attempts/evidence, transitions, retry/withdrawal/cleanup and eligibility checks |
| `server/worker.py` | New separate once/loop worker command, graceful shutdown and whitelisted structured diagnostics |
| `server/version.py` | Authoritative backend version 0.3.0 |
| `output/openapi.json` | Regenerated schemas/endpoints/header/raw-upload types and version 0.3.0 |
| `tests/test_community.py` | Expected backend version 0.3.0 |
| `tests/test_ingestion.py` | 43 focused ingestion/config/API/storage/worker regression cases |
| `doc/reports/batch-3-backend.md` | This report |

## Validation commands and results

All commands ran in this backend repository with the existing `.venv` Python
3.13.15 interpreter and already-installed dependencies. No packages were installed.

* `.\.venv\Scripts\python.exe -m pytest -q tests\test_ingestion.py -x --tb=short`
  — **42 passed** after initial fixture/implementation corrections.
* `.\.venv\Scripts\python.exe -m pytest tests\test_capsules.py tests\test_community.py tests\test_ingestion.py -q -p no:cacheprovider --tb=short`
  — **114 passed** before the final diagnostic-formatter regression was added.
* `.\.venv\Scripts\python.exe -m pytest tests\test_ingestion.py -q -p no:cacheprovider --tb=short`
  — **43 passed** including that final regression.
* Final complete suite:
  `.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --tb=short`
  — **115 passed**, 211.35 seconds.
* `.\.venv\Scripts\python.exe -m compileall -q server tests` — passed.
* `git diff --check` — passed.
* File-specific Pylance `textDocument/diagnostic` checks for
  `server/community.py`, `server/ingestion.py`, `server/worker.py`,
  `server/version.py`, `tests/test_ingestion.py` — **no errors or warnings**;
  only platform-unreachable/unused-argument informational hints where applicable.
* OpenAPI regeneration imported `server.main:app` using a unique repository-local
  synthetic package release and dummy environment secrets, then serialized
  `app.openapi()` to `output/openapi.json`. Exact checked-in/runtime equality,
  backend version and existing package route media types passed the full suite.

The suite emits one existing FastAPI/Starlette TestClient deprecation warning
about `httpx`; it does not affect test outcomes. Windows DACL behavior was exercised
on actual private test directories/files. POSIX mode-setting code compiles but
was not executed on this Windows host. No real GitHub, remote scanner or source
URL was contacted. Repository-local failed test fixtures and schema fixtures
were removed after validation.

Tests cover immutable migrations/reopen, database state/history guards, concurrent
reservation/lease claims, upload replays and digest deduplication, bounded streaming,
timeout/interruption/concurrent upload/withdrawal, malformed/traversal/symlink/CRC/
decompression-bomb archives, account cap, cookie Origin checks, bearer ownership,
raw upload media types, no download route, private response fields, retry/backoff/
exhaustion, stale lease completion, scanner trust/normalization, retained-byte and
evidence expiry/policy gates, cleanup shared-reference safety and disabled worker.

## Authoritative UI integration contract

Paths: `POST /api/community/capsules`, `GET /api/community/capsules/mine`,
`GET /api/community/capsules/{release_id}`, raw `PUT .../{release_id}/artifact`,
`POST .../{release_id}/retry`, `POST .../{release_id}/withdraw`.
Reservation requires `{project,version,sourceUrl}` and
`Idempotency-Key: [A-Za-z0-9._:-]{1,128}`; same-owner identical metadata replay
returns the same release and 201. Project/version limits are 120/80 characters;
source limit 2,048 with authoritative public HTTPS validation. The key and upload
reservation should be reused after an interruption, not a newly reserved release.

Capsule has `releaseId`, `ownerId`, `project`, `version`, `sourceUrl`, `createdAt`,
nullable `artifactSha256`, `state`, monotonic positive `revision`, `updatedAt`,
nullable `evidence`, nullable `queue`, and literal `publicDownloadAvailable:false`.
Evidence/queue fields and machine error codes are fully documented in README and
generated OpenAPI. No capabilities, public URL, raw evidence reference, lease token
or filesystem path is returned. Native bearer credentials remain native-side;
website cookie mutations require the exact configured Origin.

Retry requires `scan_blocked`, remaining budget, a non-leased job and available
quarantine bytes. Pending/leased `scan_pending` retry is idempotent. Rejected
is terminal for retries. The ordinary eligible queue statuses are blocked/failed.
Withdrawal is idempotent and allowed for nonexpired unpublished states.
Disabled worker yields `scan_blocked`, evidence verdict `blocked`, provider
`disabled`, result `unconfigured`, summary/error `scanning_not_configured`.
Website/client agents were informed of the contract, URL rules and retry behavior.

## Boundaries and outstanding integration

`publishable` means eligibility for a future publication operation, never public
artifact availability. No capsule download, installation, profile publication,
moderation, Sponsor entitlement, signing or production-clean scanner fallback
exists. Only the disabled production adapter is configurable; deterministic
accepted/rejected/error providers live exclusively in tests.

Deployment requires persistent local disk, the same API/worker service account,
private bucket/server routing isolation, restrictive OS execution policy,
consistent database-plus-bucket backup/restore and an independently supervised
worker. API and worker should not run against unsupported shared/network disks.
Real permitted-scanner integration, usage rights, provenance/license policies and
future publication remain deliberately deferred. Cross-repository browser/native
smoke, installer/release acceptance and roadmap updates belong to parent review;
this backend task verifies HTTP/worker integration with synthetic local fixtures.
