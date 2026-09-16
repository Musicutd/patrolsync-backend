# PatrolSync Vision V00 Repository Audit

Audit date: 16 September 2026  
Specification: PatrolSync Vision Codex Master Upgrade Specification v1.0  
Audited source: local `work/` snapshot, verified against `Musicutd/patrolsync-backend` `main` at `811d8bc879d8d3089f5433b1385f1e74c68ee348`  
Stage outcome: Proceed to V01 with the safeguards and prerequisites in this audit

## Executive conclusion

PatrolSync can support PatrolSync Vision without a rewrite. The existing application already has the tenant, site, identity, permissions, entitlement, incident, dispatch, reporting, audit, webhook, job, monitoring, storage, billing and platform-owner foundations that Vision needs. Vision should be added as a feature-flagged domain inside the current application and connected to those services through small, explicit interfaces.

The primary engineering risk is not a missing business foundation. It is repository maturity. The local workspace is a source snapshot rather than a Git checkout, but the linked GitHub backend repository is accessible and its `index.js` blob exactly matches `work/index.js` (`f9361e52e07adf8d1f282e1ee4871c7482dd19ce`). The backend is a 7,419-line, approximately 952 KB Express monolith with schema creation and alteration embedded in application startup. The separate local frontend snapshot has 118 static HTML pages. The backend has 392 Express routes, 109 table-creation declarations and 10 scheduled background jobs. No Vision routes or Vision tables exist yet.

The backend GitHub repository contains `package.json` and a legacy `run-migration.js`, but no lockfile, repeatable migration framework, automated test suite, CI workflow, Dockerfile, Procfile or `render.yaml` on `main`. The migration script is a one-time historical `organizations` migration, not a ledger or current Vision migration runner; do not execute it for Vision. Existing browser pages named `integrity_tests.html` and `load_testing.html` are operational diagnostics, not a replacement for repeatable automated tests. V01 may safely introduce a disabled scaffold, but V02 and especially V03 must not proceed to production until a dependency lock, test baseline and controlled migration process are established.

## Audit method and evidence boundary

The audit inspected the supplied workspace, the current `work/` production snapshot, the linked GitHub backend repository root and package/migration files, existing architecture and implementation status documents, deployment instructions, SQL isolation scripts, backend route/table/job declarations, authentication and permission middleware, plan and entitlement configuration, Stripe integration, object storage, email delivery, client portal boundaries, and deployment environment references. GitHub backend `main` is currently unprotected and has no required status checks; this is a repository governance concern before Vision code work. The 118 frontend pages are local workspace evidence, not files in the linked backend repository. A separate `Musicutd/patrolsync-frontend` repository is accessible; its `dashboard.html` blob exactly matches local `work/dashboard.html` (`7e20616405a5233f04e132a45d1df422a0ef8fe3`).

Static syntax checks passed for:

- `work/index.js`
- `work/patrolsync-module.js`
- `work/patrolsync-guard-ui.js`
- `work/service-worker.js`

This V00 audit did not connect to the live PostgreSQL database or Render account. Runtime claims such as current RLS coverage, active environment values, deployed schema and job health therefore remain production evidence to revalidate before V03. No application code, database schema or deployment configuration was changed during V00.

## Current PatrolSync architecture discovered

### Application structure

| Layer | Current implementation | Assessment for Vision |
|---|---|---|
| Subscriber frontend | Static multi-page HTML, shared CSS and browser JavaScript under `work/` | Reuse the design language and shell. Add Vision pages incrementally. |
| Guard frontend | `guard.html`, guard-specific pages, PWA manifest, service worker and IndexedDB-based offline workflows | Reuse only for Vision-generated response tasks. Do not expose camera configuration to guards. |
| Client portal | `client_portal.html` with a separate client token and site-bound APIs | Reuse for contract-authorised Vision widgets and reports. |
| Platform control | Separate platform login, token, MFA, dashboard, audit and operational tools | Reuse for Vision fleet, licence and support controls. |
| Backend | Node.js, Express and native `fetch` in one `index.js` process | Add a bounded Vision section first; extract modules only after tests protect behaviour. |
| Database | PostgreSQL through `pg`, trusted system pool plus restricted tenant pool | Reuse. Every tenant-owned Vision table must use `tenant_id`, RLS, restricted grants and `withTenant`. |
| Files | PostgreSQL fallback plus S3-compatible private object storage for incident evidence | Do not use for routine video. Potentially reuse for generated reports and redacted diagnostics only. |
| Billing | Stripe Checkout and signed webhook processing | Extend the existing subscription/entitlement flow; do not create parallel Vision billing. |
| Email | Brevo transactional email and durable delivery queue | Reuse for configurable Vision alert/report notifications. |
| Jobs | In-process timers, PostgreSQL advisory locks and `platform_job_runs` history | Reuse for low-volume control-plane sweeps initially; move heavy/critical Vision workers to a dedicated service later. |
| Deployment | Code references a Render backend and static `patrolsync.co` frontend | Keep AI inference off Render. Use paid persistent cloud services before a customer pilot. |

### Runtime dependencies observed

The backend imports Express, CORS, PostgreSQL, bcryptjs, JSON Web Tokens, Luxon, QRCode, PDFKit, crypto and dotenv. Node provides outbound HTTP through `fetch`. GitHub `package.json` declares semver ranges for Express 4.19.2, CORS 2.8.5, dotenv 16.4.5, pg 8.12.0, bcryptjs 2.4.3, jsonwebtoken 9.0.2, Luxon 3.4.4, qrcode 1.5.3 and pdfkit 0.15.0; exact installed versions and licence state cannot be verified without a lockfile.

### Deployment and environment surface

The backend reads the following environment families:

- Runtime: `NODE_ENV`, `PORT`, `HOSTNAME`, `RENDER_INSTANCE_ID`
- Browser/API: `FRONTEND_URL`, `ALLOWED_ORIGINS`, request limits
- Database: `DATABASE_URL`, `SYSTEM_DATABASE_URL`, `TENANT_DATABASE_URL`, pool settings
- Authentication: `JWT_SECRET`, `PLATFORM_JWT_SECRET`, platform bootstrap credentials
- Email: Brevo/provider and sender variables
- Storage: endpoint, bucket, region, access key and secret
- Stripe: secret key, webhook secret and automatic-tax switch
- OpenAI: API key, model and assistant feature switch
- Retention/cache: audit, webhook and platform-cache settings

There is no checked-in safe `.env.example` in the GitHub backend root. V01 should add one documenting names without secrets.

## Authentication, roles and permissions

### Existing identities

| Identity | Authentication and scope | Vision reuse |
|---|---|---|
| Company administrator | Subscriber JWT, tenant ID, optional email MFA, tracked/revocable session | Company Vision configuration, rules, entitlements and analytics. |
| Delegated staff | Subscriber JWT plus JSON permission list | Add a dedicated `vision` permission rather than mapping Vision to generic administration. |
| Guard | Guard JWT and company-scoped login; trusted-device controls can observe/enforce selected actions | Receive minimum-data Vision tasks/alerts only. |
| Client user | Separate client JWT bound to tenant and site | Read-only contract/site Vision views only. |
| Platform owner | Separate JWT secret, audience/issuer, MFA challenge, recovery codes and revocable session | Global Vision fleet, plan, entitlement and diagnostics administration. |

### Current permission model

Subscriber administrators have full company authority. Delegated staff use module permission strings such as scheduling, attendance, patrols, incidents, dispatch, safety, communications, training, assets, quality, clients, finance and analytics. `requireAdmin` maps API path prefixes to these permissions; `requireOwnerAdmin` limits sensitive operations to the company administrator. Platform operations use fully separate middleware and audit storage.

Vision must add explicit permissions, for example `vision_view`, `vision_operate`, `vision_configure` and `vision_billing`, or a single `vision` permission in V01 followed by finer separation before onboarding. Relying only on a hidden navigation item would violate the specification.

### Authentication risks relevant to Vision

- Subscriber, guard, client and platform JWTs are stored in browser `localStorage`. This is the established pattern but increases the impact of any XSS defect. Vision pages must avoid unsafe HTML construction from camera or edge metadata and should not introduce credential-bearing browser payloads.
- The backend has a development fallback JWT secret. Production posture checks detect weak configuration, but production deployment must fail closed if a secret is absent rather than merely report it.
- Camera and edge credentials need a separate machine-identity design. They must not reuse human subscriber JWTs.
- Platform support access must not become an unaudited path into raw camera streams or credentials.

## Multi-tenancy and data isolation

### Existing pattern

PatrolSync uses:

1. A trusted system pool for platform operations and bootstrap work.
2. A restricted tenant pool for `withTenant(tenantId, fn)` operations.
3. PostgreSQL session context `app.current_tenant`.
4. RLS policies comparing row `tenant_id` with that context.
5. Explicit tenant predicates in most SQL.
6. Diagnostics and launch gates that report RLS coverage and restricted-role access.

The production history supplied by the user reported 97 of 97 tenant tables protected. That is useful evidence but was not independently queried in this static audit.

### Isolation risks

- Many existing routes and jobs still use the trusted `pool` with explicit tenant predicates instead of the restricted `withTenant` path. This is compatible with platform work but is too risky for new Vision tenant APIs if copied casually.
- Startup-time schema functions mix DDL, grants and policy creation. A partial startup failure can leave a table present but incompletely protected.
- Several base tables such as `tenants`, `users`, `sites`, `checkpoints` and `patrol_logs` are assumed to pre-exist; their complete current migration history is not in the linked repository. Its `run-migration.js` only handles an older `organizations` migration and must not be treated as the current schema baseline.
- Edge event ingestion will use machine credentials and therefore needs an authoritative tenant/site/agent binding on every batch, independent of client-supplied tenant IDs.
- Client Vision APIs must derive site scope from the signed client identity and contract relationship, never query parameters.

### Required Vision tenancy rule

Every tenant-owned Vision mutation and read must execute through `withTenant`, include explicit tenant predicates, validate all referenced site/camera/agent rows within that tenant, and have automated cross-tenant/IDOR tests. Platform fleet queries may use the system pool but must require platform authentication and create platform audit events.

## Existing components to reuse

### Plans, entitlements and feature flags

PatrolSync already has the correct conceptual foundation:

- `plan_catalog`
- `feature_catalog`
- `plan_features`
- `tenant_subscriptions`
- `tenant_entitlement_overrides`
- `usage_events`
- `usage_period_summaries`
- `feature_flags`
- `feature_flag_tenants`
- entitlement resolution, usage reconciliation and platform diagnostics
- compatibility fallback to legacy `PLAN_LIMITS`

This should be extended with Vision plan and camera feature codes. Server-side camera activation must call the existing entitlement service and record idempotent usage. A separate `vision_entitlements` table from the illustrative specification is unnecessary unless it stores camera-class-specific allocation detail that cannot fit `plan_features` and overrides.

### Incidents, dispatch and operational timeline

Reusable components include incidents, incident activities, dispatch jobs, notifications, communication notifications, system events, audit logs, webhook delivery and service tickets. Vision automation should create incidents through a dedicated internal service that applies existing validation and writes source metadata such as `source = VISION`, rule ID, camera ID and event UUID. It should not call an HTTP endpoint internally or duplicate incident SQL in a worker.

### Sites, contracts and client access

Existing tenant/site relationships, guard assignments, service contracts, client users and client-site APIs are suitable. Vision client visibility should be contract/site scoped and add widget-level settings without weakening the existing site boundary.

### Reports and analytics

Existing PDF/CSV generation, client report schedules, delivery queue and service report calculations can be extended with Vision sections. Vision long-range analytics should query hourly/daily rollups rather than raw events.

### Audit, integrity and notifications

Existing subscriber audit logs, platform audit logs, system events, TrustProof evidence records, email deliveries and signed webhook framework are reusable. Vision configuration, reconciliation, support and automation decisions need explicit audit actions. TrustProof sealing of selected Vision events can remain a later opt-in integration rather than a V01 dependency.

### Jobs, health and platform operations

PostgreSQL advisory-lock jobs, persisted run history, `/health`, `/live`, `/ready`, performance dashboards, object-storage checks and platform readiness gates are strong foundations for the cloud control plane. Edge inference and continuous video processing must remain outside this process.

## Existing components requiring modification

1. **Plan catalogue:** reconcile the current code's two pricing ladders with the specification before inserting Vision. Legacy `PLAN_LIMITS` contains Starter/Medium/Pro/Diamond/Enterprise plus Growth/Command, while the public regional catalogue exposes Starter/Growth/Pro/Command/Enterprise with materially different prices and capacities.
2. **Entitlement service:** add camera licence classes, included quantities, purchased quantities, grace states and activation/deactivation usage semantics.
3. **Permission mapping:** add explicit Vision permissions and route mapping.
4. **Navigation/search:** add a Vision group only after a server-derived access/status response confirms both rollout flag and entitlement.
5. **Incidents/dispatch:** expose an internal, tested creation service for system-generated Vision actions.
6. **Client portal:** add per-contract Vision widget visibility and confidence-aware presentation.
7. **Reports:** add Vision data-quality annotations and rollup sections.
8. **Webhook catalogue:** add signed Vision event types using the existing queue and retry history.
9. **Background jobs:** add lightweight health, rollup and alert jobs with advisory locks; do not process video in these jobs.
10. **Platform console:** add fleet, entitlement, version and redacted diagnostics views.
11. **Audit sanitisation:** expand sensitive-key filtering to cover RTSP URLs, camera usernames/passwords, enrolment tokens, certificates and agent secrets.
12. **Repository structure:** introduce a safe module boundary around Vision rather than adding twenty more stages directly into the already large monolith.

## Completely new modules and services required

### Cloud domain modules

- Vision access and entitlement guard
- Edge-agent enrolment, credential rotation and revocation
- Camera/entrance/counting-line configuration
- Event batch validation and idempotent ingest
- Occupancy state, reconciliation and confidence calculation
- Health/calibration and suitability scoring
- Vision alert/rule evaluation
- Incident/dispatch integration adapter
- Vision analytics and rollups
- Client/report integration
- Platform fleet management
- External Vision API and webhook contracts

### Edge deployment

A separate deployable Edge Agent is required for Windows and Linux. It should have its own manifest, dependency lock, tests, service installer, encrypted secret store, local queue, hardware capability probe, detector/tracker interfaces, RTSP/ONVIF adapters, update signing and rollback. It must not be hosted in the PatrolSync web service.

The Edge Agent may live in the same Git repository after its structure is confirmed, but it remains a separately built and deployed process.

## Expected database changes

The following is the recommended logical data model. Names should follow the final migration conventions of the authoritative repository.

### Reuse instead of duplicate

- Use `plan_catalog`, `feature_catalog`, `plan_features`, `tenant_subscriptions`, `tenant_entitlement_overrides` and `usage_events` for commercial entitlement.
- Use central `audit_logs` and `platform_audit_logs` where they can express the action cleanly.
- Use existing incidents, dispatch, notifications, webhooks and report schedules through integration references.

### New core tables

| Table | Purpose and key controls |
|---|---|
| `vision_edge_agents` | Tenant-bound agent identity, certificate fingerprint/status, version, heartbeat and revocation. Never store a reusable plaintext secret. |
| `vision_edge_agent_sites` | Normalised many-to-many authorised site assignments. |
| `vision_entrances` | Site entrances, occupancy-required flag and ordering. |
| `vision_cameras` | Site/agent/source metadata, local opaque reference, health status and consumed entitlement class. No RTSP password. |
| `vision_counting_lines` | Versioned geometry, direction, thresholds and enabled state. |
| `vision_zones` | Phase-two-ready zone geometry, disabled until entitled. |
| `vision_calibrations` | Suitability result, scene/config version, validation and approval evidence. |
| `vision_events` | Immutable anonymous events with unique `event_uuid`, tenant/site/camera/line, UTC time, delta, confidence and engine/config versions. |
| `vision_site_occupancy_state` | Transactionally maintained current value, confidence, last event sequence/time and reconciliation state. |
| `vision_occupancy_adjustments` | Append-only correction/reset events with actor and reason. |
| `vision_occupancy_snapshots` | Time-bucket snapshots for history and confidence. |
| `vision_rollups_hourly` | Tenant/site/entrance/camera metrics and quality flags. |
| `vision_rollups_daily` | Daily totals, peaks and coverage quality. |
| `vision_camera_health` | Time-series camera health with short retention. |
| `vision_edge_health` | Agent telemetry, queue depth, version and update state. |
| `vision_alert_rules` | Tenant/site triggers, schedules, persistence, cooldown and actions. |
| `vision_alert_instances` | Deduplicated lifecycle and linked incident/dispatch IDs. |
| `vision_client_visibility` | Contract/site/widget permissions where existing client access cannot express widget-level visibility. |
| `vision_audit_events` | Only Vision-specific machine/configuration evidence not adequately represented by central audit tables. |

### Constraints and indexes

- Unique `vision_events.event_uuid` globally, plus tenant/time, site/time and camera/time indexes.
- Foreign keys must include or validate tenant ownership; a valid foreign key to another tenant's row is not acceptable.
- Unique active camera licence consumption per camera.
- Unique agent certificate identity and revocation status.
- Optimistic/config-version constraints for line and camera changes.
- UTC storage with site timezone resolved from the existing tenant/site model.
- RLS, a tenant policy and restricted-role grants on every tenant-owned Vision table before the corresponding API ships.
- Partitioning for `vision_events` and health tables should be evaluated using measured pilot volume, not introduced speculatively in V03.

## Commercial and pricing conflicts

The master specification says the existing ladder is Starter €39, Medium €79, Pro €149, Diamond €299 and Enterprise from €499, with Vision €399 inserted between Diamond and Enterprise.

The current repository contains three overlapping commercial representations:

1. Legacy `PLAN_LIMITS`: Starter €39, Medium €79, Pro €149, Diamond €299, Enterprise €499.
2. Additional compatibility entries: Growth €129 and Command €499.
3. Public regional catalogue: Starter €59, Growth €129, Pro €249, Command €499, Enterprise €899 in EUR, plus USD/AUD/CAD/JPY values and onboarding prices.

This is a direct specification/code conflict. V02 must not silently replace current public plans or existing subscriber contracts. The recommended resolution is:

- preserve all historical plan versions and active tenant mappings;
- create a new versioned catalogue release containing the approved global ladder;
- decide whether Vision is inserted into the newer Starter/Growth/Pro/Command/Enterprise ladder or whether the older Medium/Diamond ladder is being restored;
- model `VISION_COUNT_CAMERA` and `VISION_ANALYTICS_CAMERA` as configurable metered features/SKUs;
- store regional prices in authoritative plan/product configuration rather than the current source constants;
- keep Enterprise contract overrides;
- migrate no subscriber automatically during V02.

This commercial decision is not a blocker for V01 scaffolding, but it is a blocker for completing V02.

## Migration strategy and risks

### Required approach

1. Use the confirmed `Musicutd/patrolsync-backend` repository and add a dependency lockfile; use the confirmed `Musicutd/patrolsync-frontend` repository for frontend work after verifying the production deployment source.
2. Introduce an explicit ordered migration directory and migration ledger. Do not repurpose the historical `run-migration.js` without a controlled baseline review.
3. Baseline the live database without recreating existing tables.
4. Add Vision tables incrementally, initially unused and behind flags.
5. Apply constraints/indexes in safe phases; use concurrent indexes where production size requires them.
6. Apply RLS and restricted grants in the same migration that creates each tenant table.
7. Deploy read-compatible code before any data backfill.
8. Roll back by disabling flags and stopping new processing; do not drop evidence tables during the first rollout.

### Primary migration risks

- Startup DDL is not a reliable versioned migration history.
- The original complete base-schema migration history is missing from the linked backend repository; the legacy one-time migration is insufficient.
- DDL currently runs during process startup and may race across instances despite many idempotent statements.
- Adding constraints to live tables can lock or fail on existing data.
- Entitlement backfills could change access if legacy/public catalogue versions are confused.
- Event and health volume could grow much faster than current operational tables.
- An occupancy-state update needs transaction and ordering rules to prevent race-induced drift.
- Cross-tenant foreign-key mistakes may remain structurally valid unless tenant ownership is explicitly checked.

## Security risks and required controls

### High priority

- **Camera credential exposure:** never accept or return raw RTSP credentials through normal cloud/browser APIs. Prefer local secret storage and an opaque camera reference.
- **Machine identity:** edge enrolment requires short-lived one-time codes, unique credentials/certificates, rotation and revocation.
- **Event forgery/replay:** authenticate each agent, bind it to approved sites/cameras, require unique event IDs, reject clock/config anomalies and rate-limit batches.
- **Tenant bypass:** use the restricted tenant path for all subscriber Vision data and add crafted-ID cross-tenant tests.
- **Support access:** diagnostics must redact URLs, credentials, tokens and local network identifiers where not required.
- **Supply chain:** model, tracker, FFmpeg/GStreamer/OpenCV/ONNX components need version pinning, licence review, SBOM/third-party notices and signed edge releases.
- **Monolith regression:** additive Vision work inside `index.js` without automated tests carries unacceptable production risk beyond V01.

### Existing security strengths to preserve

- Strict production-origin allowlist and CORS controls
- Separate platform and subscriber JWT secrets
- MFA/recovery and revocable sessions
- Password hashing with bcrypt
- Stripe signature verification and idempotent webhook records
- S3-compatible request signing and evidence checksums
- Request/body limits and selected rate limiting
- Subscriber and platform audit histories
- RLS diagnostic and readiness gates
- Advisory locks for cross-instance job safety

## Privacy and GDPR considerations

Vision V1 should process video locally, upload anonymous event/health metadata only, and exclude facial recognition, biometrics, demographic inference and persistent cross-camera identity.

Required privacy work includes:

- document controller/processor roles and customer configuration responsibilities;
- complete a data protection impact assessment template for customer deployments;
- define lawful-purpose, signage/transparency and retention guidance without claiming legal advice;
- minimise camera metadata and avoid unnecessary local IP/URL exposure in the cloud;
- define separate retention for raw anonymous events, rollups and health telemetry;
- provide deletion/export rules that preserve necessary audit evidence;
- make occupancy corrections append-only and attributable;
- show confidence degradation rather than a misleading exact number;
- prohibit raw frame/clip upload by default and design any future evidence flow separately;
- ensure support/calibration preview is explicit, time-limited and audited if later introduced.

Even anonymous counts may remain personal-data processing at the local video-analysis stage. Local processing lowers exposure but does not by itself establish GDPR compliance.

## Render and infrastructure assessment

The current backend is compatible with Render for the web control plane during development. It is not an appropriate home for production inference, continuous video, a durable edge queue or guaranteed alert scheduling.

The in-process job system is protected by advisory locks, but it still depends on an always-running web process. Before a production Vision pilot:

- use persistent paid PostgreSQL with backups and tested restore;
- use an always-on backend/worker tier for occupancy, alert and report processing;
- move critical jobs to a dedicated worker service or equivalent durable scheduler;
- monitor event lag, queue depth, heartbeat delay and rollup freshness;
- retain the existing health/readiness and platform job evidence;
- keep the Edge Agent functional for at least the target offline buffer while cloud services are unavailable.

## Specification adaptations to PatrolSync conventions

| Specification concept | PatrolSync adaptation |
|---|---|
| Separate Vision cloud service | Start as a bounded backend domain because PatrolSync is currently one Express service; preserve an extraction boundary. |
| `vision_entitlements` | Extend existing catalogue, plan-feature, override and usage tables; add a small allocation table only if mixed camera-class assignments require it. |
| Generic `tenant_id` | Continue PatrolSync's integer tenant IDs and `withTenant`/RLS pattern. |
| Vision audit table | Use central audit/system/platform logs first; reserve a Vision table for high-volume machine/configuration evidence. |
| Worker/rollup service | Reuse advisory-lock job conventions in development, then deploy a dedicated paid worker before pilot reliance. |
| Object storage | Use only for reports/redacted diagnostics in V1, never routine CCTV footage. |
| Suggested monorepo folders | Do not reorganise the whole application. Add a minimal `vision/` backend boundary and separate edge-agent project when the authoritative repository is available. |
| API examples | Preserve existing `/api/...` style; implement `/api/vision/...` with current auth middleware plus new entitlement/agent guards. |

## Vision integration points

1. **Tenants and sites:** ownership root for agents, cameras, entrances, rules, occupancy and analytics.
2. **Entitlements and Stripe:** plan/add-on configuration and active-camera consumption.
3. **Staff permissions:** explicit Vision view/configure/operate boundaries.
4. **Incidents and activities:** system-generated Vision incidents with explainable source evidence.
5. **Dispatch jobs:** optional action after rule evaluation and company configuration.
6. **Notifications and email queue:** capacity, after-hours and health alerts.
7. **Audit and system events:** configuration, reconciliation, acknowledgement, support and automated-action evidence.
8. **Webhooks/API keys:** signed outbound events and later aggregated external API.
9. **Client portal and service contracts:** site-scoped widgets, visibility controls and combined reports.
10. **Report schedules/PDF/CSV:** Vision sections and data-quality annotations.
11. **Operations Risk and reconstruction:** later context signals, not an early hard dependency.
12. **Platform console:** fleet health, versions, licence use and redacted diagnostics.

## Regression risks to existing PatrolSync

| Risk | Severity | Control |
|---|---|---|
| Adding more startup DDL fails application boot | High | Move Vision schema to explicit migrations; keep V01 schema-free. |
| Plan insertion changes existing limits/prices | High | Version catalogue; no automatic tenant remap. |
| Vision job overload delays core API | High | Batch, cap work, measure, then isolate workers. |
| New joins expose another tenant/site | Critical | `withTenant`, RLS, ownership validation and negative tests. |
| Automated Vision rules flood incidents/dispatch | High | Off by default, persistence/cooldown/deduplication and pilot validation. |
| Camera secrets appear in logs/audit payloads | Critical | Local-only secrets, redaction and automated secret-leak tests. |
| Event volume degrades reports/database | High | Batch ingest, indexes, rollups, retention and load tests. |
| Occupancy drift is presented as fact | High | Coverage modes, confidence state, correction ledger and health dependency. |
| Static frontend hides but API permits access | High | Server-side flag, permission and entitlement middleware. |
| Vision changes break existing routes | High | Characterisation tests before refactoring and Vision-disabled regression suite. |
| Edge update loses queued events | High | Persistent local queue, signed staged update and rollback tests. |

## Exact recommended implementation order

The specification's V01 to V20 order is sound, with these repository prerequisites inserted:

0. **Repository controls prerequisite:** use the confirmed backend and frontend repositories; add a backend lockfile, secret-safe environment example, test command, CI, branch protection and migration ledger. Verify the frontend deployment source before publishing navigation changes.
1. **V01 Vision scaffolding:** disabled global and tenant flags, Vision feature code, permission constants, server status guard, native navigation placeholder, internal contracts and docs. No camera data tables.
2. **V02 plans and entitlements:** resolve the plan-ladder conflict; version the catalogue; add camera SKUs/classes and active-camera usage semantics.
3. **V03 database foundation:** explicit migrations for the Vision core tables, RLS, grants, constraints, indexes and rollback/disable strategy.
4. **V04 edge enrolment:** one-time pairing, unique machine identity, revocation, heartbeat and audited platform status.
5. **V05 camera onboarding:** local secret flow, opaque cloud references, RTSP/ONVIF capability metadata and suitability checks.
6. **V06 local inference prototype:** detector/tracker abstractions, licence review and approved test media. Keep outside cloud web runtime.
7. **V07 line crossing:** versioned geometry, direction, debounce and repeatable fixtures.
8. **V08 cloud event ingest:** authenticated batch API, strict schema, event UUID uniqueness, accepted/duplicate/rejected response and replay tests.
9. **V09 multi-entrance occupancy:** transactional state, modes, confidence and correction ledger.
10. **V10 health and calibration:** camera/agent telemetry, confidence degradation and redacted diagnostics.
11. **V11 dashboards:** subscriber views using rollups and explicit unreliable/unavailable states.
12. **V12 alerts and automations:** rule engine off by default, deduplication, cooldown and audit.
13. **V13 incident and dispatch integration:** internal service adapters with source metadata and regression tests.
14. **V14 reports and client portal:** contract/site scope, widget visibility, combined reports and quality notes.
15. **V15 billing UX:** activation/deactivation, mixed camera classes, downgrade selection and Stripe hooks.
16. **V16 platform fleet:** global status, entitlement reconciliation, release versions and redacted support actions.
17. **V17 API and webhooks:** aggregate API, scopes, quotas, signing and retries.
18. **V18 security/privacy hardening:** threat model, DPIA material, retention, secret audit, SBOM and penetration/IDOR tests.
19. **V19 pilot benchmark:** approved-site tally, accuracy/latency/offline/restart tests and published operating conditions.
20. **V20 production readiness:** persistent paid infrastructure, backups/restore, dedicated workers, monitoring, runbooks, signed releases and rollback.

## Concrete V01 implementation plan

### Scope

V01 establishes a disabled, native-looking Vision boundary without adding CCTV processing, camera tables or broad refactoring.

### Proposed changes

1. Add a global environment switch such as `VISION_ENABLED=false`, failing closed when absent.
2. Seed an existing database feature flag such as `vision_rollout` and a feature-catalogue entitlement such as `vision_access` without changing existing plans.
3. Add backend helpers:
   - `visionGlobalEnabled()`
   - `resolveVisionAccess(tenantId)`
   - `requireVisionAccess`
   - `requireVisionPermission(level)`
4. Add `GET /api/vision/status`, returning only rollout, entitlement, permission and safe capability metadata.
5. Add a disabled `vision_overview.html` placeholder using the existing PatrolSync module shell, theme and search/navigation conventions.
6. Add Vision navigation/search entries only after the status endpoint authorises access; direct page/API access must still fail server-side.
7. Extend staff permissions with a Vision permission while keeping company billing/configuration owner-admin-only.
8. Define internal JSON schemas/types for edge identity, camera reference, anonymous count event, heartbeat and confidence states. Do not implement ingest yet.
9. Add a `vision/` documentation/domain boundary compatible with the present repository rather than moving existing modules.
10. Add characterisation tests for Vision-disabled behaviour and the existing login, site, incident, dispatch, client-scope and entitlement paths before V02.

### V01 exit gate

- Vision is invisible and inaccessible when the global switch is off.
- An enabled global switch without tenant flag/entitlement still returns 403 or a safe disabled status.
- A tenant cannot query another tenant's Vision status.
- Staff without Vision permission cannot access Vision APIs.
- Client and guard identities cannot access configuration APIs.
- Existing route syntax and automated regression tests pass.
- No new camera credentials, video, event tables or inference dependencies exist.
- `BUILD_STATUS.md` is updated with exact files, tests, configuration and blockers.

## V00 decision

**Decision: proceed to V01 scaffolding, conditionally.** There is no architectural conflict requiring a PatrolSync rewrite. The existing product foundations are suitable and should be reused. The backend and frontend repositories are confirmed; before V02/V03 production work, a lockfile, automated tests and migration mechanism must be present. The plan-catalogue conflict must be resolved before Vision pricing or entitlements are activated. Frontend publishing requires verification that production deploys from the confirmed frontend repository.

