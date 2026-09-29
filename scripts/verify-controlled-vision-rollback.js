'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('pg');

const environment = String(process.env.VERIFY_ROLLBACK_ENVIRONMENT || '').trim().toLowerCase();
const confirmation = String(process.env.VERIFY_ROLLBACK_CONFIRMATION || '');
const connectionString = String(process.env.VERIFY_ROLLBACK_DATABASE_URL || '');
const tenantRole = String(process.env.VERIFY_ROLLBACK_TENANT_ROLE || '').trim();

if (!['ci', 'staging'].includes(environment)) throw new Error('VERIFY_ROLLBACK_ENVIRONMENT must be ci or staging');
if (confirmation !== `VERIFY PATROLSYNC ${environment.toUpperCase()} VISION ROLLBACK`) {
  throw new Error('Explicit environment-specific VERIFY_ROLLBACK_CONFIRMATION is required');
}
if (!connectionString) throw new Error('VERIFY_ROLLBACK_DATABASE_URL is required');
if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole)) throw new Error('VERIFY_ROLLBACK_TENANT_ROLE is invalid');
const target = new URL(connectionString);
if (environment === 'ci' && !['127.0.0.1', 'localhost'].includes(target.hostname)) {
  throw new Error('CI rollback verification may only target loopback PostgreSQL');
}
if (environment === 'staging' && !/staging/i.test(target.pathname)) {
  throw new Error('Staging database name must contain staging');
}

const migrationsDir = path.join(__dirname, '..', 'migrations', 'vision');
const policySource = fs.readFileSync(path.join(migrationsDir, '0002_tenant_workflow_policies_and_grants.sql'), 'utf8');
const relationshipSource = fs.readFileSync(path.join(migrationsDir, '0003_tenant_parent_child_constraints.sql'), 'utf8');
const names = source => [...source.matchAll(/'([a-z_][a-z0-9_]*)'/g)].map(match => match[1]);
const policyTables = names(policySource.match(/tenant_tables text\[\] := ARRAY\[([\s\S]*?)\];/)?.[1] || '');
const parentTables = names(relationshipSource.match(/unnest\(ARRAY\[([\s\S]*?)\]\)/)?.[1] || '');
const foreignKeys = [...relationshipSource.matchAll(/\('([a-z_][a-z0-9_]*)','(patrolsync_[^']+_fk)'/g)]
  .map(match => ({ table: match[1], constraint: match[2] }));
if (policyTables.length !== 56 || parentTables.length !== 18 || foreignKeys.length !== 59) {
  throw new Error('Rollback verification inventory is incomplete');
}

async function main() {
  const client = new Client({ connectionString, application_name: 'patrolsync-rollback-verifier' });
  await client.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const ledger = await client.query('SELECT version FROM patrolsync_schema_migrations ORDER BY version');
    if (ledger.rowCount !== 1 || ledger.rows[0].version !== '0001_migration_foundation') {
      throw new Error('Migration ledger was not restored to the foundation state');
    }
    const state = await client.query(`SELECT c.relname,c.relrowsecurity,
        EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname='public' AND p.tablename=c.relname
          AND p.policyname='patrolsync_tenant_isolation') AS migrated_policy
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname=ANY($1::text[])`, [policyTables]);
    if (state.rowCount !== 56 || state.rows.some(row => !row.relrowsecurity || row.migrated_policy)) {
      throw new Error('Rollback must remove migrated policies while leaving RLS enabled');
    }
    for (const table of policyTables) {
      for (const operation of ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) {
        const allowed = (await client.query('SELECT has_table_privilege($1,$2,$3) AS allowed',
          [tenantRole, `public.${table}`, operation])).rows[0].allowed;
        if (allowed) throw new Error(`Rollback left ${operation} privilege on ${table}`);
      }
    }
    for (const { table, constraint } of foreignKeys) {
      const found = await client.query('SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass($1) AND conname=$2',
        [`public.${table}`, constraint]);
      if (found.rowCount) throw new Error(`Rollback left tenant foreign key ${constraint}`);
    }
    for (const table of parentTables) {
      const found = await client.query('SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass($1) AND conname=$2',
        [`public.${table}`, `patrolsync_${table}_tenant_id_unique`]);
      if (found.rowCount) throw new Error(`Rollback left tenant parent key for ${table}`);
    }
    await client.query('ROLLBACK');
    console.log(JSON.stringify({ environment, ledger: 'foundation-only', rlsEnabled: 56,
      migratedPolicies: 0, restrictedRolePrivileges: 0, tenantForeignKeys: 0, tenantParentKeys: 0 }, null, 2));
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}

main().catch(error => {
  console.error(`Controlled Vision rollback verification failed: ${error.message}`);
  process.exitCode = 1;
});
