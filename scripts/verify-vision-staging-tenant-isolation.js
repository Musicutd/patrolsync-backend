'use strict';

const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { validateStagingConnection } = require('./bootstrap-vision-staging');

const CONFIRMATION = 'VERIFY_RESTRICTED_TENANT_ISOLATION';
const ROLE = 'patrolsync_vision_staging_tenant';

function reviewedPrivileges() {
  const source = fs.readFileSync(path.join(__dirname, '..', 'migrations', 'vision',
    '0002_tenant_workflow_policies_and_grants.sql'), 'utf8');
  const block = source.match(/tenant_tables text\[\] := ARRAY\[([\s\S]*?)\];/);
  const tables = [...(block?.[1] || '').matchAll(/'([a-z_][a-z0-9_]*)'/g)].map(match => match[1]);
  if (tables.length !== 56) throw new Error('Reviewed tenant table inventory is incomplete');
  const privileges = new Map(tables.map(table => [table, new Set()]));
  for (const match of source.matchAll(/GRANT\s+([A-Z,]+)\s+ON\s+([\s\S]*?)\s+TO\s+\{\{TENANT_ROLE\}\};/g)) {
    for (const table of match[2].split(',').map(value => value.trim()).filter(Boolean)) {
      if (!privileges.has(table)) throw new Error(`Unexpected reviewed grant table ${table}`);
      privileges.set(table, new Set(match[1].split(',')));
    }
  }
  return privileges;
}

function validateTarget(env) {
  if (env.PATROLSYNC_STAGING_TENANT_AUDIT !== CONFIRMATION) {
    throw new Error('Restricted tenant-isolation audit confirmation is missing');
  }
  return validateStagingConnection(env);
}

async function verify(env = process.env) {
  const { connectionString, rolePassword } = validateTarget(env);
  const privileges = reviewedPrivileges();
  const restrictedUrl = new URL(connectionString);
  restrictedUrl.username = ROLE;
  restrictedUrl.password = rolePassword;
  const { Client } = require('pg');
  const client = new Client({ connectionString: restrictedUrl.href, ssl: { rejectUnauthorized: false },
    application_name: 'patrolsync-staging-tenant-isolation-audit' });
  await client.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const identity = (await client.query(`SELECT current_user AS role,
      has_schema_privilege(current_user,'public','USAGE') AS can_use_schema,
      has_schema_privilege(current_user,'public','CREATE') AS can_create_schema,
      r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb
      FROM pg_roles r WHERE r.rolname=current_user`)).rows[0];
    assert.equal(identity.role, ROLE);
    assert.equal(identity.can_use_schema, true);
    assert.equal(identity.can_create_schema, false);
    assert.equal(identity.rolsuper || identity.rolbypassrls || identity.rolcreaterole || identity.rolcreatedb, false);
    let readable = 0;
    for (const [table, expected] of privileges) {
      for (const operation of ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) {
        const actual = (await client.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',
          [`public.${table}`, operation])).rows[0].allowed;
        assert.equal(actual, expected.has(operation), `${table} ${operation} privilege differs`);
      }
      if (expected.has('SELECT')) {
        readable++;
        const noContext = await client.query(`SELECT COUNT(*)::int AS count FROM public.${table}`);
        assert.equal(noContext.rows[0].count, 0, `${table} exposes rows without tenant context`);
      }
    }
    await client.query("SELECT set_config('app.current_tenant','2147483647',true)");
    for (const [table, expected] of privileges) {
      if (!expected.has('SELECT')) continue;
      const arbitrary = await client.query(`SELECT COUNT(*)::int AS count FROM public.${table}`);
      assert.equal(arbitrary.rows[0].count, 0, `${table} exposes rows to an arbitrary tenant context`);
    }
    await client.query('ROLLBACK');
    return { tables: privileges.size, readable, restrictedRole: true, rowsVisible: 0 };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { await client.end(); }
}

if (require.main === module) {
  verify().then(result => console.log(`Vision staging tenant-isolation audit passed: ${result.tables} privilege maps, ${result.readable} readable tables, zero rows visible; API remains inactive.`))
    .catch(error => { console.error(`Vision staging tenant-isolation audit refused: ${error.code || error.message}`); process.exitCode = 1; });
}

module.exports = { CONFIRMATION, ROLE, reviewedPrivileges, validateTarget, verify };
