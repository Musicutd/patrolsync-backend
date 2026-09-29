'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('pg');

const environment = String(process.env.VERIFY_ENVIRONMENT || '').trim().toLowerCase();
const confirmation = String(process.env.VERIFY_CONFIRMATION || '');
const connectionString = String(process.env.VERIFY_DATABASE_URL || '');
const tenantRole = String(process.env.VERIFY_TENANT_ROLE || '').trim();

if (!['ci', 'staging'].includes(environment)) throw new Error('VERIFY_ENVIRONMENT must be ci or staging');
if (confirmation !== `VERIFY PATROLSYNC ${environment.toUpperCase()} VISION MIGRATIONS`) {
  throw new Error('Explicit environment-specific VERIFY_CONFIRMATION is required');
}
if (!connectionString) throw new Error('VERIFY_DATABASE_URL is required');
if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole)) throw new Error('VERIFY_TENANT_ROLE is invalid');
const target = new URL(connectionString);
if (environment === 'ci' && !['127.0.0.1', 'localhost'].includes(target.hostname)) {
  throw new Error('CI verification may only target loopback PostgreSQL');
}
if (environment === 'staging' && !/staging/i.test(target.pathname)) {
  throw new Error('Staging database name must contain staging');
}

const migrationsDir = path.join(__dirname, '..', 'migrations', 'vision');
const migrationFiles = fs.readdirSync(migrationsDir).filter(name => /^000[123]_[a-z0-9_]+\.sql$/.test(name)).sort();
if (migrationFiles.length !== 3) throw new Error(`Expected three controlled migrations, found ${migrationFiles.length}`);
const policySource = fs.readFileSync(path.join(migrationsDir, migrationFiles[1]), 'utf8');
const relationshipSource = fs.readFileSync(path.join(migrationsDir, migrationFiles[2]), 'utf8');
const policyBlock = policySource.match(/tenant_tables text\[\] := ARRAY\[([\s\S]*?)\];/);
const parentBlock = relationshipSource.match(/unnest\(ARRAY\[([\s\S]*?)\]\)/);
const quotedNames = source => [...source.matchAll(/'([a-z_][a-z0-9_]*)'/g)].map(match => match[1]);
const policyTables = quotedNames(policyBlock?.[1] || '');
const parentTables = quotedNames(parentBlock?.[1] || '');
const foreignKeys = [...relationshipSource.matchAll(/\('([a-z_][a-z0-9_]*)','(patrolsync_[^']+_fk)'/g)]
  .map(match => ({ table: match[1], constraint: match[2] }));
if (policyTables.length !== 56 || parentTables.length !== 18 || foreignKeys.length !== 59) {
  throw new Error('Controlled migration inventory is incomplete');
}

const expectedPrivileges = new Map(policyTables.map(table => [table, new Set()]));
for (const match of policySource.matchAll(/GRANT\s+([A-Z,]+)\s+ON\s+([\s\S]*?)\s+TO\s+\{\{TENANT_ROLE\}\};/g)) {
  const operations = match[1].split(',');
  for (const table of match[2].split(',').map(value => value.trim()).filter(Boolean)) {
    if (!expectedPrivileges.has(table)) throw new Error(`Unexpected granted table ${table}`);
    expectedPrivileges.set(table, new Set(operations));
  }
}

async function main() {
  const client = new Client({ connectionString, application_name: 'patrolsync-migration-verifier' });
  await client.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const ledger = await client.query(`SELECT version,checksum_sha256 FROM patrolsync_schema_migrations ORDER BY version`);
    const expectedLedger = migrationFiles.map(file => {
      const source = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      return { version: file.slice(0, -4), checksum_sha256: crypto.createHash('sha256').update(source).digest('hex') };
    });
    const applied = new Map(ledger.rows.map(row => [row.version, row.checksum_sha256]));
    for (const expected of expectedLedger) {
      if (applied.get(expected.version) !== expected.checksum_sha256) throw new Error(`Missing or changed migration ${expected.version}`);
    }
    const policies = await client.query(`SELECT c.relname AS table_name,c.relrowsecurity,
        p.roles::text AS roles,p.qual,p.with_check
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      LEFT JOIN pg_policies p ON p.schemaname=n.nspname AND p.tablename=c.relname
        AND p.policyname='patrolsync_tenant_isolation'
      WHERE n.nspname='public' AND c.relname=ANY($1::text[])`, [policyTables]);
    if (policies.rowCount !== 56 || policies.rows.some(row => !row.relrowsecurity || !row.roles?.includes(tenantRole)
      || !row.qual?.includes('app.current_tenant') || !row.with_check?.includes('app.current_tenant'))) {
      throw new Error('RLS or migrated tenant policy verification failed');
    }
    for (const [table, expected] of expectedPrivileges) {
      for (const operation of ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) {
        const actual = (await client.query('SELECT has_table_privilege($1,$2,$3) AS allowed',
          [tenantRole, `public.${table}`, operation])).rows[0].allowed;
        if (actual !== expected.has(operation)) throw new Error(`${table} ${operation} privilege differs from migration`);
      }
    }
    for (const { table, constraint } of foreignKeys) {
      const present = await client.query(`SELECT 1 FROM pg_constraint
        WHERE conrelid=to_regclass($1) AND conname=$2 AND contype='f'`, [`public.${table}`, constraint]);
      if (!present.rowCount) throw new Error(`Missing tenant foreign key ${constraint}`);
    }
    for (const table of parentTables) {
      const present = await client.query(`SELECT 1 FROM pg_constraint
        WHERE conrelid=to_regclass($1) AND conname=$2 AND contype='u'`,
      [`public.${table}`, `patrolsync_${table}_tenant_id_unique`]);
      if (!present.rowCount) throw new Error(`Missing tenant parent key for ${table}`);
    }
    await client.query('ROLLBACK');
    console.log(JSON.stringify({ environment, migrations: 3, policies: 56,
      privilegeMaps: 56, tenantForeignKeys: 59, tenantParentKeys: 18 }, null, 2));
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}

main().catch(error => {
  console.error(`Controlled Vision verification failed: ${error.message}`);
  process.exitCode = 1;
});
