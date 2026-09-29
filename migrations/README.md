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
