'use strict';

// Read-only audit of the isolated staging baseline. Never starts the API.
const assert = require('node:assert/strict');
const { validateStagingConnection } = require('./bootstrap-vision-staging');

const ROLE = 'patrolsync_vision_staging_tenant';
const TABLES = [
  'alert_log', 'checkpoints', 'guard_assignments', 'patrol_logs',
  'patrol_schedules', 'service_contracts', 'sites', 'tenants', 'users'
];

async function verify(env = process.env) {
  if (env.PATROLSYNC_STAGING_VERIFY !== 'VERIFY_BASELINE') {
    throw new Error('Staging read-only verification confirmation is missing');
  }
  const { connectionString, rolePassword } = validateStagingConnection(env);
  const { Client } = require('pg');
  const owner = new Client({ connectionString, ssl: { rejectUnauthorized: false } });
  const restrictedUrl = new URL(connectionString);
  restrictedUrl.username = ROLE;
  restrictedUrl.password = rolePassword;
  const tenant = new Client({ connectionString: restrictedUrl.href, ssl: { rejectUnauthorized: false } });
  await owner.connect();
  try {
    const tables = (await owner.query("SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")).rows;
    assert.deepEqual(tables.map(row => row.tablename), TABLES, 'Baseline table set differs');
    assert.ok(tables.every(row => row.rowsecurity), 'A baseline table lacks RLS');
    const policies = (await owner.query("SELECT tablename, roles FROM pg_policies WHERE schemaname = 'public' AND policyname = 'tenant_row' ORDER BY tablename")).rows;
    assert.deepEqual(policies.map(row => row.tablename), TABLES, 'Tenant policy coverage differs');
    assert.ok(policies.every(row => row.roles.includes(ROLE)), 'Tenant policy is not assigned to the restricted role');
    const role = (await owner.query('SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = $1', [ROLE])).rows[0];
    assert.ok(role?.rolcanlogin && !role.rolsuper && !role.rolbypassrls && !role.rolcreaterole && !role.rolcreatedb,
      'Restricted role properties differ');
    assert.equal((await owner.query('SELECT count(*)::int AS n FROM tenants')).rows[0].n, 0, 'Staging tenants are not empty');
    assert.equal((await owner.query('SELECT count(*)::int AS n FROM users')).rows[0].n, 0, 'Staging users are not empty');

    await tenant.connect();
    try {
      const identity = (await tenant.query(`SELECT current_user AS role,
        has_schema_privilege(current_user, 'public', 'USAGE') AS can_use_schema,
        has_schema_privilege(current_user, 'public', 'CREATE') AS can_create_in_schema`)).rows[0];
      assert.equal(identity.role, ROLE, 'Restricted connection has the wrong role');
      assert.equal(identity.can_use_schema, true, 'Restricted role cannot use public schema');
      assert.equal(identity.can_create_in_schema, false, 'Restricted role can create schema objects');
      for (const table of TABLES) {
        const rights = (await tenant.query(`SELECT
          has_table_privilege(current_user, $1, 'SELECT') AS can_read,
          has_table_privilege(current_user, $1, 'INSERT') AS can_insert,
          has_table_privilege(current_user, $1, 'UPDATE') AS can_update,
          has_table_privilege(current_user, $1, 'DELETE') AS can_delete`, [`public.${table}`])).rows[0];
        assert.ok(rights.can_read && rights.can_insert && rights.can_update && rights.can_delete,
          `Restricted grants differ for ${table}`);
      }
      assert.equal((await tenant.query('SELECT count(*)::int AS n FROM public.tenants')).rows[0].n, 0,
        'Tenant role can see rows without tenant context');
    } finally { await tenant.end(); }
    return { tables: TABLES.length, policies: policies.length, restrictedLogin: true, dataEmpty: true };
  } finally { await owner.end(); }
}

if (require.main === module) {
  verify().then(result => {
    console.log(`Vision staging read-only audit passed: ${result.tables} RLS tables, ${result.policies} policies, restricted login, empty data. API remains inactive.`);
  }).catch(error => {
    console.error(`Vision staging read-only audit refused: ${error.code || error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { verify };

