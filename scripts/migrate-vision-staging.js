'use strict';

// One-time bridge from the Render hold service to the reviewed migration runner.
const path = require('node:path');
const { spawn } = require('node:child_process');
const { validateStagingConnection } = require('./bootstrap-vision-staging');
const { BASELINE_TABLES, buildExpansion } = require('./expand-vision-staging-schema');

const CONFIRMATION = 'APPLY_REVIEWED_VISION_MIGRATIONS';
const TENANT_ROLE = 'patrolsync_vision_staging_tenant';

function validateTarget(env) {
  if (env.PATROLSYNC_STAGING_MIGRATE !== CONFIRMATION) {
    throw new Error('Staging migration confirmation is missing');
  }
  return validateStagingConnection(env);
}

function runChild(env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(__dirname, 'run-controlled-migrations.js')], {
      env: {
        ...process.env,
        MIGRATION_ENVIRONMENT: 'staging',
        MIGRATION_CONFIRMATION: 'APPLY PATROLSYNC STAGING MIGRATIONS',
        MIGRATION_DATABASE_URL: env.SYSTEM_DATABASE_URL,
        MIGRATION_TENANT_ROLE: TENANT_ROLE
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.resume();
    child.once('error', reject);
    child.once('close', code => {
      if (code !== 0) return reject(new Error(`controlled migration process exited ${code}`));
      resolve(stdout.trim().split(/\r?\n/).filter(Boolean));
    });
  });
}

async function migrate(env = process.env) {
  const { connectionString, expectedOwner } = validateTarget(env);
  const { inventory } = buildExpansion();
  const expectedTables = [...new Set([...BASELINE_TABLES, ...inventory])].sort();
  const { Client } = require('pg');
  const client = new Client({ connectionString, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const identity = (await client.query(`SELECT current_database() AS db,session_user AS login_role,
      current_user AS active_role,pg_get_userbyid(datdba) AS database_owner
      FROM pg_database WHERE datname=current_database()`)).rows[0];
    if (identity.db !== 'patrolsync_vision_staging_db' || identity.login_role !== expectedOwner ||
        identity.active_role !== identity.database_owner) {
      throw new Error('Connected database identity differs from the approved staging target');
    }
    const actual = (await client.query("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename<>'patrolsync_schema_migrations' ORDER BY tablename"))
      .rows.map(row => row.tablename);
    if (JSON.stringify(actual) !== JSON.stringify(expectedTables)) {
      throw new Error('Staging table inventory differs from the reviewed expansion');
    }
    const role = (await client.query(`SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb
      FROM pg_roles WHERE rolname=$1`, [TENANT_ROLE])).rows[0];
    if (!role?.rolcanlogin || role.rolsuper || role.rolbypassrls || role.rolcreaterole || role.rolcreatedb) {
      throw new Error('Restricted staging tenant role verification failed');
    }
    await client.query('ROLLBACK');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { await client.end(); }
  const output = await runChild(env);
  if (!output.some(line => line === 'applied: 0003_tenant_parent_child_constraints' ||
      line === 'already applied: 0003_tenant_parent_child_constraints')) {
    throw new Error('Controlled migration completion marker is missing');
  }
  return { migrations: 3 };
}

if (require.main === module) {
  migrate().then(result => console.log(`Vision staging controlled migrations complete: ${result.migrations}; API remains inactive.`))
    .catch(error => { console.error(`Vision staging controlled migration refused: ${error.code || error.message}`); process.exitCode = 1; });
}

module.exports = { CONFIRMATION, TENANT_ROLE, validateTarget, migrate };
