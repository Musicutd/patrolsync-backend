'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('pg');

const environment = String(process.env.PREFLIGHT_ENVIRONMENT || '').trim().toLowerCase();
const confirmation = String(process.env.PREFLIGHT_CONFIRMATION || '');
const connectionString = String(process.env.PREFLIGHT_DATABASE_URL || '');

if (!['ci', 'staging'].includes(environment)) throw new Error('PREFLIGHT_ENVIRONMENT must be ci or staging');
if (confirmation !== `RUN PATROLSYNC ${environment.toUpperCase()} READ ONLY PREFLIGHT`) {
  throw new Error('Explicit environment-specific PREFLIGHT_CONFIRMATION is required');
}
if (!connectionString) throw new Error('PREFLIGHT_DATABASE_URL is required');

const target = new URL(connectionString);
if (environment === 'ci' && !['127.0.0.1', 'localhost'].includes(target.hostname)) {
  throw new Error('CI preflight may only target loopback PostgreSQL');
}
if (environment === 'staging' && !/staging/i.test(target.pathname)) {
  throw new Error('Staging database name must contain staging');
}

const migration = fs.readFileSync(path.join(__dirname, '..', 'migrations', 'vision',
  '0003_tenant_parent_child_constraints.sql'), 'utf8');
const pattern = /\('([a-z_][a-z0-9_]*)','patrolsync_[^']+_fk','([a-z_][a-z0-9_]*)','([a-z_][a-z0-9_]*)'\)/g;
const relationships = [...migration.matchAll(pattern)].map(match => ({
  childTable: match[1], childColumn: match[2], parentTable: match[3]
}));
if (relationships.length !== 59) throw new Error(`Expected 59 migration relationships, found ${relationships.length}`);

const quoteIdentifier = value => `"${value.replaceAll('"', '""')}"`;

async function main() {
  const client = new Client({ connectionString, application_name: 'patrolsync-read-only-preflight' });
  await client.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const results = [];
    for (const relationship of relationships) {
      const child = quoteIdentifier(relationship.childTable);
      const column = quoteIdentifier(relationship.childColumn);
      const parent = quoteIdentifier(relationship.parentTable);
      const result = await client.query(`
        SELECT COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE c.${column} IS NOT NULL AND p.id IS NULL)::int AS orphaned,
          COUNT(*) FILTER (WHERE p.id IS NOT NULL AND c.tenant_id IS DISTINCT FROM p.tenant_id)::int AS cross_tenant
        FROM public.${child} c LEFT JOIN public.${parent} p ON p.id=c.${column}
      `);
      results.push({ ...relationship, ...result.rows[0] });
    }
    await client.query('ROLLBACK');
    const failures = results.filter(row => row.orphaned !== 0 || row.cross_tenant !== 0);
    console.log(JSON.stringify({
      environment,
      relationshipsChecked: results.length,
      totalChildRows: results.reduce((sum, row) => sum + row.total, 0),
      failures
    }, null, 2));
    if (failures.length) throw new Error(`${failures.length} tenant relationship preflight check(s) failed`);
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}

main().catch(error => {
  console.error(`Read-only tenant relationship preflight failed: ${error.message}`);
  process.exitCode = 1;
});
