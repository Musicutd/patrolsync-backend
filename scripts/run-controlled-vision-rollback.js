'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('pg');

const environment = String(process.env.ROLLBACK_ENVIRONMENT || '').trim().toLowerCase();
const confirmation = String(process.env.ROLLBACK_CONFIRMATION || '');
const connectionString = String(process.env.ROLLBACK_DATABASE_URL || '');
const tenantRole = String(process.env.ROLLBACK_TENANT_ROLE || '').trim();

if (!['ci', 'staging'].includes(environment)) throw new Error('ROLLBACK_ENVIRONMENT must be ci or staging');
if (confirmation !== `ROLL BACK PATROLSYNC ${environment.toUpperCase()} VISION MIGRATIONS`) {
  throw new Error('Explicit environment-specific ROLLBACK_CONFIRMATION is required');
}
if (!connectionString) throw new Error('ROLLBACK_DATABASE_URL is required');
if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole)) {
  throw new Error('ROLLBACK_TENANT_ROLE must be a simple PostgreSQL role name');
}

const target = new URL(connectionString);
if (environment === 'ci' && !['127.0.0.1', 'localhost'].includes(target.hostname)) {
  throw new Error('CI rollback may only target loopback PostgreSQL');
}
if (environment === 'staging' && !/staging/i.test(target.pathname)) {
  throw new Error('Staging database name must contain staging');
}

const quoteIdentifier = value => `"${value.replaceAll('"', '""')}"`;
const migrationsDir = path.join(__dirname, '..', 'migrations', 'vision');
const policySource = fs.readFileSync(path.join(migrationsDir, '0002_tenant_workflow_policies_and_grants.sql'), 'utf8');
const relationshipSource = fs.readFileSync(path.join(migrationsDir, '0003_tenant_parent_child_constraints.sql'), 'utf8');
const policyTablesBlock = policySource.match(/tenant_tables text\[\] := ARRAY\[([\s\S]*?)\];/);
const parentTablesBlock = relationshipSource.match(/unnest\(ARRAY\[([\s\S]*?)\]\)/);
if (!policyTablesBlock || !parentTablesBlock) throw new Error('Unable to derive rollback inventory from controlled migrations');
const quotedNames = source => [...source.matchAll(/'([a-z_][a-z0-9_]*)'/g)].map(match => match[1]);
const policyTables = quotedNames(policyTablesBlock[1]);
const parentTables = quotedNames(parentTablesBlock[1]);
const foreignKeys = [...relationshipSource.matchAll(/\('([a-z_][a-z0-9_]*)','(patrolsync_[^']+_fk)'/g)]
  .map(match => ({ table: match[1], constraint: match[2] }));
if (policyTables.length !== 56 || parentTables.length !== 18 || foreignKeys.length !== 59) {
  throw new Error(`Rollback inventory mismatch: ${policyTables.length} policies, ${parentTables.length} parents, ${foreignKeys.length} foreign keys`);
}

async function main() {
  const client = new Client({ connectionString, application_name: 'patrolsync-controlled-rollback' });
  await client.connect();
  try {
    await client.query(`SELECT pg_advisory_lock(hashtext('patrolsync-controlled-migrations'))`);
    const ledger = await client.query(`SELECT version FROM patrolsync_schema_migrations
      WHERE version IN ('0002_tenant_workflow_policies_and_grants','0003_tenant_parent_child_constraints')`);
    if (ledger.rowCount !== 2) throw new Error('Both controlled migrations 0002 and 0003 must be applied before rollback');
    await client.query('BEGIN');
    try {
      for (const { table, constraint } of foreignKeys.reverse()) {
        await client.query(`ALTER TABLE public.${quoteIdentifier(table)} DROP CONSTRAINT IF EXISTS ${quoteIdentifier(constraint)}`);
      }
      for (const table of parentTables.reverse()) {
        await client.query(`ALTER TABLE public.${quoteIdentifier(table)} DROP CONSTRAINT IF EXISTS ${quoteIdentifier(`patrolsync_${table}_tenant_id_unique`)}`);
      }
      for (const table of policyTables) {
        const sequence = (await client.query(`SELECT pg_get_serial_sequence($1,'id') AS name
          WHERE EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass($1)
            AND attname='id' AND attnum>0 AND NOT attisdropped)`, [`public.${table}`])).rows[0]?.name;
        await client.query(`REVOKE ALL PRIVILEGES ON TABLE public.${quoteIdentifier(table)} FROM ${quoteIdentifier(tenantRole)}`);
        await client.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON public.${quoteIdentifier(table)}`);
        if (sequence) await client.query(`REVOKE ALL PRIVILEGES ON SEQUENCE ${sequence} FROM ${quoteIdentifier(tenantRole)}`);
      }
      await client.query(`DELETE FROM patrolsync_schema_migrations
        WHERE version IN ('0003_tenant_parent_child_constraints','0002_tenant_workflow_policies_and_grants')`);
      await client.query('COMMIT');
      console.log('Rolled back Vision migrations 0003 and 0002; RLS remains enabled and restricted-role access is fail-closed.');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  } finally {
    await client.query(`SELECT pg_advisory_unlock(hashtext('patrolsync-controlled-migrations'))`).catch(() => {});
    await client.end();
  }
}

main().catch(error => {
  console.error(`Controlled rollback failed: ${error.message}`);
  process.exitCode = 1;
});
