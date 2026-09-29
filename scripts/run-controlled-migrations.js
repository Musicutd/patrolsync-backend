'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('pg');

const allowedEnvironments = new Set(['ci', 'staging']);
const environment = String(process.env.MIGRATION_ENVIRONMENT || '').trim().toLowerCase();
const confirmation = String(process.env.MIGRATION_CONFIRMATION || '');
const connectionString = String(process.env.MIGRATION_DATABASE_URL || '');
const tenantRole = String(process.env.MIGRATION_TENANT_ROLE || '').trim();

if (!allowedEnvironments.has(environment)) {
  throw new Error('MIGRATION_ENVIRONMENT must be ci or staging; production is intentionally unsupported');
}
if (confirmation !== `APPLY PATROLSYNC ${environment.toUpperCase()} MIGRATIONS`) {
  throw new Error('Explicit environment-specific MIGRATION_CONFIRMATION is required');
}
if (!connectionString) throw new Error('MIGRATION_DATABASE_URL is required');
if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole)) {
  throw new Error('MIGRATION_TENANT_ROLE must be a simple PostgreSQL role name');
}

const target = new URL(connectionString);
if (environment === 'ci' && !['127.0.0.1', 'localhost'].includes(target.hostname)) {
  throw new Error('CI migrations may only target loopback PostgreSQL');
}
if (environment === 'staging' && !/staging/i.test(target.pathname)) {
  throw new Error('Staging database name must contain staging');
}

const quoteIdentifier = value => `"${value.replaceAll('"', '""')}"`;
const migrationsDir = path.resolve(__dirname, '..', 'migrations', 'vision');
const files = fs.readdirSync(migrationsDir)
  .filter(name => /^\d{4}_[a-z0-9_]+\.sql$/.test(name))
  .sort();
if (!files.length) throw new Error('No controlled Vision migrations were found');

async function main() {
  const client = new Client({ connectionString });
  await client.connect();
  try {
    await client.query(`SELECT pg_advisory_lock(hashtext('patrolsync-controlled-migrations'))`);
    await client.query(`CREATE TABLE IF NOT EXISTS public.patrolsync_schema_migrations(
      version TEXT PRIMARY KEY,
      checksum_sha256 TEXT NOT NULL,
      environment TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    for (const file of files) {
      const version = file.slice(0, -4);
      const source = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      const checksum = crypto.createHash('sha256').update(source).digest('hex');
      const existing = await client.query(
        'SELECT checksum_sha256 FROM public.patrolsync_schema_migrations WHERE version=$1', [version]);
      if (existing.rowCount) {
        if (existing.rows[0].checksum_sha256 !== checksum) {
          throw new Error(`Applied migration ${version} has changed checksum`);
        }
        console.log(`already applied: ${version}`);
        continue;
      }
      const sql = source.replaceAll('{{TENANT_ROLE}}', quoteIdentifier(tenantRole));
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query(`INSERT INTO public.patrolsync_schema_migrations(
          version,checksum_sha256,environment) VALUES($1,$2,$3)`, [version, checksum, environment]);
        await client.query('COMMIT');
        console.log(`applied: ${version}`);
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    await client.query(`SELECT pg_advisory_unlock(hashtext('patrolsync-controlled-migrations'))`).catch(() => {});
    await client.end();
  }
}

main().catch(error => {
  console.error(`Controlled migration failed: ${error.message}`);
  process.exitCode = 1;
});
