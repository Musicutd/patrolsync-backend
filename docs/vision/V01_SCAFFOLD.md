# V01 Vision scaffold boundary

This stage is deliberately inactive. `VISION_ENABLED` must be the exact string `true`; absent and all other values fail closed. There is no camera connection, event ingest, video handling, occupancy calculation or Vision billing in V01.

Access requires all of the following:

1. `VISION_ENABLED=true` on the backend.
2. The existing `feature_flags` row `vision_rollout` globally enabled.
3. An enabled `feature_flag_tenants` row for the same authenticated tenant.
4. An enabled `vision_access` entitlement on that tenant's active or trialing subscription.
5. Subscriber administrator role or delegated staff with `vision_view` permission.

The status decision also checks that the returned flag and entitlement rows belong to the authenticated tenant. Missing or mismatched tenant IDs fail closed.

A disposable PostgreSQL CI test exercises the rollout-flag query with the restricted database role and a tenant RLS policy. It demonstrates that a different tenant context cannot read an enabled flag. An isolated Express HTTP test also exercises the status and capabilities routes with injected authentication, tenant, entitlement and schema dependencies, including disabled, denied, role-restricted and schema-failure cases. Neither test yet exercises the full production authentication and entitlement path against a representative base schema.

The `vision_access` feature is inserted **after** plan-feature seeding, so no existing plan receives it automatically, including Enterprise. The two Vision catalogue records are inserted idempotently into existing tables; no Vision data tables or irreversible migration are introduced. Do not turn on any flag or entitlement during V01 review.

`GET /api/vision/status` returns only enabled/disabled status and scaffold capability booleans. `GET /api/vision/capabilities` is forbidden unless every gate passes. Guards, clients and platform tokens cannot use subscriber Vision routes. The frontend adds the navigation entry only after a successful enabled status response; hiding navigation is not the API security boundary.

Before activating Vision in any environment, add a repeatable migration ledger, integration tests against a tenant-isolated test database, and a reviewed plan/entitlement decision. A dependency lockfile is checked in and verified by CI. Do not use the historical `run-migration.js` for Vision.

Local Chromium browser checks used mocked status responses and no production data. They confirmed direct-page redirects when disabled or denied, the enabled placeholder and dashboard navigation, and a readable 390px mobile layout without horizontal overflow. These checks do not prove production login, deployment, or live entitlement behaviour.

