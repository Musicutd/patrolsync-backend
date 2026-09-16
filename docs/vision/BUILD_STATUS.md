# PatrolSync Vision Build Status

Updated: 16 September 2026  
Master specification: PatrolSync Vision Codex Master Upgrade Specification v1.0  
Current stage: V01 Vision Scaffolding in review  
Next stage: Complete V01 verification before V02

## Programme status

| Stage | Status | Exit evidence or dependency |
|---|---|---|
| V00 Repository Audit | Complete | Real supplied workspace audited; architecture, reuse, gaps, risks, database expectations and V01 plan documented. |
| V01 Vision Scaffolding | In progress | Disabled scaffold, lockfile, unit tests and restricted-role PostgreSQL rollout-flag isolation pass in CI; full endpoint and browser acceptance remain unverified. |
| V02 Plans and Entitlements | Not started | Requires a product decision resolving the legacy versus current public plan ladder. |
| V03 Database Foundation | Not started | Requires an explicit migration framework and live-schema baseline. |
| V04 Edge Enrolment | Not started | Depends on V03 machine identity tables and security design. |
| V05 Camera Onboarding | Not started | Depends on V04 and local secret-storage design. |
| V06 Local Inference Prototype | Not started | Separate Edge Agent dependency/licence review required. |
| V07 Line Crossing | Not started | Depends on detector/tracker prototype and fixtures. |
| V08 Cloud Event Ingest | Not started | Depends on V03, V04 and V07 contracts. |
| V09 Multi-Entrance Occupancy | Not started | Depends on idempotent event ingest. |
| V10 Health and Calibration | Not started | Depends on agent/camera heartbeat contracts. |
| V11 Vision Dashboards | Not started | Depends on occupancy, health and rollups. |
| V12 Alerts and Automations | Not started | Depends on reliable occupancy and health states. |
| V13 Incident and Dispatch Integration | Not started | Depends on validated, deduplicated rules. |
| V14 Reports and Client Portal | Not started | Depends on rollups, confidence and client visibility. |
| V15 Billing UX | Not started | Depends on active-camera entitlement accounting. |
| V16 Super Admin Fleet | Not started | Depends on edge/camera/version health data. |
| V17 API and Webhooks | Not started | Depends on stable aggregate contracts. |
| V18 Security and Privacy Hardening | Not started | Release gate after full threat, tenant and retention review. |
| V19 Pilot Benchmark | Not started | Real-site validation under approved camera conditions. |
| V20 Production Readiness | Not started | Persistent paid infrastructure, monitoring, runbooks and rollback required. |

## V00 completed work

- Read the complete PatrolSync Vision master specification and treated it as the requirements source for this stage.
- Audited the supplied workspace and confirmed the backend snapshot exactly matches the linked GitHub repository's `index.js`.
- Mapped the frontend, backend, database bootstrap, authentication, roles, permissions, tenancy, RLS, plans, entitlements, billing, client portal, incidents, dispatch, patrols, reports, audits, webhooks, jobs, monitoring, storage and deployment environment.
- Compared the real implementation with the Vision specification.
- Identified reusable services, required modifications, new domains/services, expected database changes, migration risks, security/privacy risks and regression risks.
- Identified the plan/pricing conflict between the specification, legacy plan limits and the current global public catalogue.
- Produced the concrete V01 implementation plan and exit gate.

## Files changed

- `docs/vision/V00_REPOSITORY_AUDIT.md` — new repository audit and implementation recommendation.
- `docs/vision/BUILD_STATUS.md` — new Vision programme tracker.

No application, frontend, database, environment or deployment files were changed.

## Database changes

None. V00 was read-only with respect to application architecture and data.

## Environment and configuration changes

None.

Expected V01 addition after implementation begins:

- `VISION_ENABLED=false` as a fail-closed global rollout switch.

No value should be added to production until V01 tests and deployment instructions are ready.

## Verification performed

- Node syntax check: `work/index.js` — passed.
- Node syntax check: `work/patrolsync-module.js` — passed.
- Node syntax check: `work/patrolsync-guard-ui.js` — passed.
- Node syntax check: `work/service-worker.js` — passed.
- Static inventory: 118 HTML pages, 392 Express routes, 109 table-creation declarations and 10 registered background jobs.
- Static Vision check: zero `/api/vision` routes found.
- Repository-control check: the local workspace has no Git metadata, but the linked backend repository has `package.json` and a historical one-time `run-migration.js`; no lockfile, repeatable migration ledger, automated tests, CI workflow or deployment manifest is present on `main`.
- GitHub check: `Musicutd/patrolsync-backend` `main` at `811d8bc879d8d3089f5433b1385f1e74c68ee348`; `index.js` blob matches local file exactly. `main` is unprotected and has no required status checks.

No live database query, deployed endpoint test or browser workflow was executed during this documentation-only stage.

## Known limitations and unresolved issues

1. The supplied local workspace is not a Git checkout. The backend repository `Musicutd/patrolsync-backend` and frontend repository `Musicutd/patrolsync-frontend` are accessible through GitHub; their `index.js` and `dashboard.html` files respectively match the local snapshot exactly. Confirm the frontend deployment points to that repository before publishing navigation changes.
2. GitHub `package.json` provides dependency ranges, but exact installed versions and third-party licences cannot be verified without a lockfile.
3. The original complete base-schema migrations for tenants, users, sites, checkpoints and patrol logs are absent. The existing `run-migration.js` is a one-time legacy organizations migration, not a repeatable migration framework; do not run it for Vision.
4. Production RLS and environment state were not independently queried; existing readiness evidence must be re-run before V03.
5. The current code has legacy and current public plan catalogues with conflicting names, capacities and prices.
6. No automated unit, integration, tenant-isolation or end-to-end test suite is present in the linked backend repository.
7. Render configuration is described in text and code assumptions but not represented by an infrastructure manifest.
8. Vision Edge Agent language/runtime, inference engine, tracker and model licences remain intentionally undecided until V06 research and benchmarking.

## Stage decision

V00 is complete. PatrolSync is architecturally suitable for an additive Vision module. The backend repository is confirmed. Proceed to V01 on a review branch, adding tests and repository controls before changing behaviour. Do not begin V02 pricing activation or V03 database migrations until the catalogue decision, automated test baseline and migration process are resolved.

## Next stage V01

V01 should implement only:

- a disabled global Vision switch;
- tenant rollout flag and entitlement code using existing services;
- explicit Vision permission constants;
- server-side Vision access middleware;
- a safe `/api/vision/status` endpoint;
- a native PatrolSync placeholder page and authorised navigation entry;
- initial Vision contracts and characterisation tests;
- safe environment documentation.

V01 must not create camera/event tables, connect CCTV streams, add inference dependencies or expose camera credentials.

## V01 work in review

- Added a fail-closed Vision switch, explicit Vision permission names, a tenant-flag and entitlement access decision, and guarded status/capabilities endpoints.
- Added `vision_access` to the existing feature catalogue without automatically granting it to any plan, plus a disabled `vision_rollout` flag.
- Added a status-gated placeholder page and navigation in both the dashboard and shared module shell. Added `vision_view` to delegated staff permission management.
- Added three pure access-decision tests and a syntax/unit CI workflow.
- Added a fourth pure test that rejects a rollout flag or entitlement belonging to another tenant, and hid the direct placeholder page until an enabled status is confirmed.
- Added a disposable PostgreSQL CI test that queries the real rollout-flag SQL as a restricted tenant role. It verifies that a tenant cannot see another tenant's enabled flag.
- Rebased the backend V01 draft PR onto `main` after the V00 documentation PR was merged; its diff is now limited to V01 changes.
- Extracted the Vision HTTP routes into an injectable router and added an isolated Express test for disabled, denied, tenant, entitlement, role, delegated permission and schema-failure responses. GitHub CI passed all six backend tests with `npm ci`.
- Ran local Chromium checks with mocked status responses: disabled and denied direct visits redirect, an enabled placeholder and dashboard navigation render, and a 390px mobile layout has no horizontal overflow. No production records were accessed.
- Added `V01_SCAFFOLD.md` documenting the exact inactive boundary.
- Added `V01_CONTRACTS.md` with non-executable edge, camera, count, heartbeat and confidence interface sketches.
- No production deployment, customer entitlement, camera credential, Vision data table, video processing or inference dependency was introduced.

V01 is **not ready for activation**. The workspace has pnpm but no npm. Offline lockfile generation lacked cached registry metadata; online resolution failed TLS certificate verification. TLS checks were not bypassed. A trusted GitHub Actions runner generated `package-lock.json`; CI now uses `npm ci` to verify it. The rollout-flag query passed a restricted-role PostgreSQL integration test and isolated HTTP/browser checks passed, but the full authenticated status and entitlement path has not been exercised against a representative base schema or production deployment. Keep `VISION_ENABLED` unset/false and both PRs in draft until those review checks pass.

