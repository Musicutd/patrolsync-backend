'use strict';

// One-time schema baseline for the dedicated Vision staging database only.
// This script never starts the API and must never be run against production.
const fs = require('node:fs');
const path = require('node:path');

const STAGING_SERVICE_ID = 'srv-dal8ne3l550s73ck8l40';
const STAGING_BRANCH = 'feature/vision-v01-scaffold';
const STAGING_DATABASE = 'patrolsync_vision_staging_db';
const STAGING_HOST = 'dpg-dal8lpbm8hqs73f9nsk0-a';
const TENANT_ROLE = 'patrolsync_vision_staging_tenant';
const REQUIRED_TABLES = [
  'alert_log', 'checkpoints', 'guard_assignments', 'patrol_logs',
  'patrol_schedules', 'service_contracts', 'sites', 'tenants', 'users'
];

function validateStagingConnection(env) {
  if (env.RENDER_SERVICE_ID !== STAGING_SERVICE_ID ||
      env.RENDER_GIT_BRANCH !== STAGING_BRANCH ||
      env.VISION_ENABLED !== 'false') {
    throw new Error('Staging service, branch, or disabled Vision flag is missing');
  }
  let url;
  try { url = new URL(env.SYSTEM_DATABASE_URL || ''); }
  catch (_) { throw new Error('A staging-only SYSTEM_DATABASE_URL is required'); }
  const expectedOwner = String(env.STAGING_DATABASE_OWNER || '').trim();
  if (!/^patrolsyncvisionstagingdb_[a-z0-9]+_user$/.test(expectedOwner)) {
    throw new Error('The rotated staging database owner identity is required');
  }
  const identityChecks = {
    protocol: ['postgres:', 'postgresql:'].includes(url.protocol),
    database: url.pathname === `/${STAGING_DATABASE}`,
    owner: decodeURIComponent(url.username) === expectedOwner,
    host: url.hostname === STAGING_HOST || url.hostname.startsWith(`${STAGING_HOST}.`),
    password: Boolean(url.password)
  };
  const failedIdentityChecks = Object.entries(identityChecks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name);
  if (failedIdentityChecks.length > 0) {
    throw new Error(`Database connection does not identify the dedicated Vision staging instance (failed checks: ${failedIdentityChecks.join(', ')})`);
  }
  const rolePassword = env.STAGING_TENANT_ROLE_PASSWORD || '';
  if (rolePassword.length < 32 || rolePassword.length > 256 || /[\r\n]/.test(rolePassword)) {
    throw new Error('A separate 32–256 character staging tenant-role password is required');
  }
  return { connectionString: url.href, rolePassword, expectedOwner };
}

function validateTarget(env) {
  if (env.PATROLSYNC_STAGING_BOOTSTRAP !== 'BOOTSTRAP_EMPTY_VISION_DB') {
    throw new Error('Staging bootstrap confirmation is missing');
  }
  return validateStagingConnection(env);
}

function quoteLiteral(value) { return `'${String(value).replaceAll("'", "''")}'`; }

async function bootstrap(env = process.env) {
  const { connectionString, rolePassword, expectedOwner } = validateTarget(env);
  const { Client } = require('pg');
  const client = new Client({ connectionString, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    await client.query('BEGIN');
    const identity = (await client.query(`SELECT current_database() AS db,
      session_user AS login_role,
      current_user AS active_role,
      pg_get_userbyid(datdba) AS database_owner
      FROM pg_database WHERE datname = current_database()`)).rows[0];
    const failedConnectedIdentityChecks = [];
    if (identity.db !== STAGING_DATABASE) failedConnectedIdentityChecks.push('database');
    if (identity.login_role !== expectedOwner) failedConnectedIdentityChecks.push('login-owner');
    if (identity.active_role !== identity.database_owner) failedConnectedIdentityChecks.push('active-database-owner');
    if (failedConnectedIdentityChecks.length > 0) {
      throw new Error(`Connected database identity differs from the approved staging target (failed checks: ${failedConnectedIdentityChecks.join(', ')})`);
    }
    const existing = await client.query("SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename");
    const roleExists = await client.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [TENANT_ROLE]);
    if (existing.rowCount !== 0 || roleExists.rowCount !== 0) {
      if (roleExists.rowCount === 0 ||
          JSON.stringify(existing.rows.map(row => row.tablename)) !== JSON.stringify(REQUIRED_TABLES) ||
          !existing.rows.every(row => row.rowsecurity)) {
        throw new Error('Refusing to bootstrap a nonempty or partially initialized public schema');
      }
      const priorRole = (await client.query('SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = $1', [TENANT_ROLE])).rows[0];
      if (!priorRole?.rolcanlogin || priorRole.rolsuper || priorRole.rolbypassrls || priorRole.rolcreaterole || priorRole.rolcreatedb) {
        throw new Error('Existing staging tenant role is not restricted');
      }
      await client.query('COMMIT');
      return { database: STAGING_DATABASE, tables: existing.rowCount, role: TENANT_ROLE, alreadyInitialized: true };
    }

    await client.query(`CREATE ROLE ${TENANT_ROLE} LOGIN PASSWORD ${quoteLiteral(rolePassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`);
    const fixture = fs.readFileSync(path.join(__dirname, '..', 'test', 'fixtures', 'vision-staging-base.sql'), 'utf8');
    if (!fixture.includes('vision_base_reader')) throw new Error('Reviewed staging baseline role marker is missing');
    await client.query(fixture.replaceAll('vision_base_reader', TENANT_ROLE));
    await client.query(`GRANT CONNECT ON DATABASE ${STAGING_DATABASE} TO ${TENANT_ROLE}`);
    await client.query(`GRANT USAGE ON SCHEMA public TO ${TENANT_ROLE}`);
    await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${TENANT_ROLE}`);
    await client.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${TENANT_ROLE}`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${TENANT_ROLE}`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO ${TENANT_ROLE}`);

    const tables = await client.query("SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename");
    if (JSON.stringify(tables.rows.map(row => row.tablename)) !== JSON.stringify(REQUIRED_TABLES) ||
        !tables.rows.every(row => row.rowsecurity)) {
      throw new Error('Baseline table or RLS verification failed');
    }
    const role = (await client.query('SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = $1', [TENANT_ROLE])).rows[0];
    if (!role || role.rolsuper || role.rolbypassrls || role.rolcreaterole || role.rolcreatedb) {
      throw new Error('Restricted staging role verification failed');
    }
    await client.query('COMMIT');
    return { database: STAGING_DATABASE, tables: tables.rowCount, role: TENANT_ROLE, alreadyInitialized: false };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { await client.end(); }
}

if (require.main === module) {
  bootstrap().then(result => {
    console.log(`Vision staging baseline ${result.alreadyInitialized ? 'verified' : 'created'}: ${result.tables} RLS tables; restricted role ${result.role}. API remains inactive.`);
  }).catch(error => {
    // Database errors may embed query text; print only their SQLSTATE, never a URL or password.
    console.error(`Vision staging bootstrap refused: ${error.code || error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { validateTarget, validateStagingConnection, bootstrap };

