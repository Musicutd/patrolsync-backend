# Controlled PatrolSync migrations

These migrations are separate from the historical one-time `run-migration.js`.

The runner is fail-closed:

- only `ci` and `staging` are accepted; production is unsupported;
- CI targets must use loopback PostgreSQL;
- staging database names must contain `staging`;
- the restricted tenant role must be supplied explicitly;
- an environment-specific confirmation phrase is mandatory;
- every applied file is recorded with a SHA-256 checksum;
- changed checksums stop execution;
- an advisory lock prevents concurrent runners;
- each migration is transactional.

Do not run the staging path until its migration SQL, preflight evidence, rollback procedure, and disposable-database acceptance have all been reviewed.

Before applying relationship migrations to staging, run the aggregate-only preflight with
`PREFLIGHT_ENVIRONMENT=staging`, confirmation text
`RUN PATROLSYNC STAGING READ ONLY PREFLIGHT`, and the staging-only database URL in
`PREFLIGHT_DATABASE_URL`. It starts a read-only transaction, derives all 59 relationships
from migration `0003`, reports counts only, and fails on orphaned or cross-tenant references.
It intentionally refuses database names that do not contain `staging`.

The manual GitHub Actions workflow `Vision staging read-only preflight` provides the
preferred remote execution path. Store the external staging connection only as
`VISION_STAGING_DATABASE_URL` in the protected `vision-staging-readonly` GitHub
environment, require reviewer approval on that environment, and type
`RUN READ ONLY PREFLIGHT` when dispatching. The workflow has read-only repository
permissions and cannot invoke the migration or rollback runners.

The separate `Vision staging controlled migration` workflow is preparation only and
must not be dispatched until the read-only staging preflight passes and recovery is
approved. It is restricted to the V01 review branch, requires the exact selected commit
SHA plus a long confirmation phrase, and uses the protected
`vision-staging-migration` environment. That environment must contain the encrypted
`VISION_STAGING_DATABASE_URL` secret, a `VISION_STAGING_TENANT_ROLE` variable, and a
required human reviewer. The job runs preflight, migration, and read-only verification
in that order. It does not deploy the API, enable Vision, or change the 503 holding command.
