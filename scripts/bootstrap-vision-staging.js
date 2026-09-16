'use strict';

// One-time schema baseline for the dedicated Vision staging database only.
// This script never starts the API and must never be run against production.
const fs = require('node:fs');
const path = require('node:path');

const STAGING_SERVICE_ID = 'srv-dal8ne3l550s73ck8l40';
const STAGING_BRANCH = 'feature/vision-v01-scaffold';
const STAGING_DATABASE = 'patrolsync_vision_staging_db';
const STAGING_OWNER = 'patrolsync_vision_staging_db_user';
const STAGING_HOST = 'dpg-dal8lpbm8hqs73f9nsk0-a';
const TENANT_ROLE = 'patrolsync_vision_staging_tenant';
const REQUIRED_TABLES = [
  'alert_log', 'checkpoints', 'guard_assignments', 'patrol_logs',
  'patrol_schedules', 'service_contracts', 'sites', 'tenants', 'users'
];

function validateTarget(env) {
  if (env.PATROLSYNC_STAGING_BOOTSTRAP !== 'BOOTSTRAP_EMPTY_VISION_DB' ||
      env.RENDER_SERVICE_ID !== STAGING_SERVICE_ID ||
      env.RENDER_GIT_BRANCH !== STAGING_BRANCH ||
      env.VISION_ENABLED !== 'false') {
    throw new Error('Staging bootstrap confirmation, service, branch, or disabled Vision flag is missing');
  }
  let url;
  try { url = new URL(env.SYSTEM_DATABASE_URL || ''); }
  catch (_) { throw new Error('A staging-only SYSTEM_DATABASE_URL is required'); }
  if (!['postgres:', 'postgresql:'].includes(url.protocol) ||
      url.pathname !== `/${STAGING_DATABASE}` ||
      decodeURIComponent(url.username) !== STAGING_OWNER ||
      !(url.hostname === STAGING_HOST || url.hostname.startsWith(`${STAGING_HOST}.`)) ||
      !url.password) {
    throw new Error('Database connection does not identify the dedicated Vision staging instance');
  }
  const rolePassword = env.STAGING_TENANT_ROLE_PASSWORD || '';
  if (rolePassword.length < 32 || rolePassword.length > 256 || /[\r\n]/.test(rolePassword)) {
    throw new Error('A separate 32–256 character staging tenant-role password is required');
  }
  return { connectionString: url.href, rolePassword };
}

function quoteLiteral(value) { return `'${String(value).replaceAll("'", "''")}'`; }

async function bootstrap(env = process.env) {
  const { connectionString, rolePassword } = validateTarget(env);
  const { Client } = require('pg');
  const client = new Client({ connectionString, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    await client.query('BEGIN');
    const identity = (await client.query('SELECT current_database() AS db, current_user AS role')).rows[0];
    if (identity.db !== STAGING_DATABASE || identity.role !== STAGING_OWNER) {
      throw new Error('Connected database identity differs from the approved staging target');
    }
    const existing = await client.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'");
    if (existing.rowCount !== 0) throw new Error('Refusing to bootstrap a nonempty public schema');
    const roleExists = await client.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [TENANT_ROLE]);
    if (roleExists.rowCount !== 0) throw new Error('Refusing to reuse an existing staging tenant role');

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
    return { database: STAGING_DATABASE, tables: tables.rowCount, role: TENANT_ROLE };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { await client.end(); }
}

if (require.main === module) {
  bootstrap().then(result => {
    console.log(`Vision staging baseline ready: ${result.tables} RLS tables; restricted role ${result.role}. API remains inactive.`);
  }).catch(error => {
    // Database errors may embed query text; print only their SQLSTATE, never a URL or password.
    console.error(`Vision staging bootstrap refused: ${error.code || error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { validateTarget, bootstrap };

