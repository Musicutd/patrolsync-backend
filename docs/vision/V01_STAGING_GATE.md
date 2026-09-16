# V01 staging gate — not executed

This checklist is for a **separate, disposable** PatrolSync Vision test deployment. It is not permission to change the production Render service, database, DNS, customer subscriptions, or rollout flags. Keep both V01 pull requests in draft and keep production `VISION_ENABLED` unset or `false`.

## Current blocker: production API URLs in the frontend

The frontend source contains the production backend URL in 120 HTML/JavaScript files, including `login.html`, `dashboard.html`, `patrolsync-module.js`, and `vision_overview.html`. Render's `patrolsync-frontend` static site deploys `main` automatically and has PR previews disabled. A plain static-site copy would therefore send staging activity to production. The frontend V01 draft PR now contains an **optional staging-only build** that requires an explicit HTTPS Render staging API origin, refuses the known production frontend service ID, and rewrites all reviewed static assets into a separate output directory without changing source. CI produced a 127-file artifact with 119 API references redirected. This is a build-time safety check, **not a deployed staging frontend**. Before any deployment, supply a real isolated backend URL, verify the served artifact has no production API references, and block production API requests in browser network tests. Do not alter the live `patrolsync.co` site while doing this work.

## Provisioning boundary

1. Use a new staging backend service from the V01 draft branch and a separate staging frontend origin. Never change the existing `patrolsync-backend` production service or `patrolsync.co` deployment.
2. Use a newly created, empty PostgreSQL database and a separately created restricted tenant database role. Verify the database name, host, and role differ from production before starting the backend. Do not copy production data or credentials.
3. Generate new staging-only subscriber and platform JWT secrets. Set the staging frontend origin explicitly. Do not copy production API keys, SMTP/Brevo credentials, Stripe live keys, webhook secrets, camera credentials, or object-storage credentials. If a dependency cannot safely run without a live integration, stop rather than substituting a production credential.
4. Start with `VISION_ENABLED=false`. Create only synthetic tenants and accounts. Do not activate any plan feature or rollout flag for a real tenant.
5. Restrict public access to the staging services and label the UI clearly as staging. Retain a short cleanup date and owner. Confirm logs do not contain passwords, JWTs, database URLs, or email verification codes.

## Acceptance sequence

1. Verify backend startup and health with the isolated database. Treat any schema-setup error or background-job failure as a failed gate, not as a warning to ignore.
2. With Vision off, log in through the staging frontend as a synthetic subscriber administrator. `GET /api/vision/status` must return `enabled: false`; the Vision navigation must be hidden; `GET /api/vision/capabilities` must be forbidden. A direct visit to the Vision page must redirect or deny access.
3. Test a synthetic guard, client, delegated staff member without `vision_view`, and a staff member with `vision_view`. Guards/clients and unpermitted staff must be denied. The permitted staff member still cannot access Vision while the global switch is off.
4. In staging only, add the `vision_access` entitlement and tenant rollout for one synthetic tenant and set `VISION_ENABLED=true` on the staging backend. Confirm only its administrator and `vision_view` staff can see the placeholder. A second synthetic tenant must remain denied. Confirm camera, event and occupancy capabilities remain `false`.
5. Revoke a synthetic session and disable a synthetic account; both must lose access immediately. Test the MFA path separately if configured without a live email provider.
6. Remove the test entitlement and rollout, reset staging `VISION_ENABLED=false`, and rerun the denied-access checks. Capture timestamps, test account roles, HTTP results and CI commit SHA. Do not record passwords or tokens in evidence.

## Exit decision

V01 is reviewable only after the above checks pass on the same commit as both draft PRs, the base schema is reproducible in staging, and a human security review confirms tenant/RLS and deployment isolation. Do not merge or activate solely because CI is green. If no separate Render service and database are available, this gate remains **not run**.

