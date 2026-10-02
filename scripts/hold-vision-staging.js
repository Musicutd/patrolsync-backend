'use strict';

// Safe Render start command while the isolated staging database is being prepared.
// It never starts index.js or exposes application endpoints.
const http = require('node:http');
const { bootstrap } = require('./bootstrap-vision-staging');

async function main() {
  if (process.env.PATROLSYNC_STAGING_BOOTSTRAP === 'BOOTSTRAP_EMPTY_VISION_DB') {
    const result = await bootstrap();
    console.log(`Vision staging baseline ${result.alreadyInitialized ? 'verified' : 'created'}; API remains inactive.`);
  }
  if (process.env.PATROLSYNC_STAGING_VERIFY === 'VERIFY_BASELINE') {
    const result = await require('./verify-vision-staging-baseline').verify();
    console.log(`Vision staging read-only audit passed: ${result.tables} RLS tables, ${result.policies} policies, restricted login, empty data. API remains inactive.`);
  }
  if (process.env.PATROLSYNC_STAGING_EXPAND === 'EXPAND_REVIEWED_EXISTING_SCHEMA') {
    const result = await require('./expand-vision-staging-schema').expand();
    console.log(`Vision staging schema expanded by ${result.added} tables (${result.tables} total); access remains revoked and API inactive.`);
  }
  if (!process.env.PATROLSYNC_STAGING_EXPAND &&
      process.env.PATROLSYNC_STAGING_MIGRATE === 'APPLY_REVIEWED_VISION_MIGRATIONS') {
    const result = await require('./migrate-vision-staging').migrate();
    console.log(`Vision staging controlled migrations complete: ${result.migrations}; API remains inactive.`);
  }
  if (!process.env.PATROLSYNC_STAGING_EXPAND && !process.env.PATROLSYNC_STAGING_MIGRATE &&
      process.env.PATROLSYNC_STAGING_MIGRATION_VERIFY === 'VERIFY_REVIEWED_VISION_MIGRATIONS') {
    const result = await require('./verify-vision-staging-migrations').verify();
    console.log(`Vision staging migration audit passed: ${result.migrations} migrations, ${result.policies} policies, ${result.tenantForeignKeys} tenant foreign keys; API remains inactive.`);
  }
  if (!process.env.PATROLSYNC_STAGING_EXPAND && !process.env.PATROLSYNC_STAGING_MIGRATE &&
      !process.env.PATROLSYNC_STAGING_MIGRATION_VERIFY &&
      process.env.PATROLSYNC_STAGING_TENANT_AUDIT === 'VERIFY_RESTRICTED_TENANT_ISOLATION') {
    const result = await require('./verify-vision-staging-tenant-isolation').verify();
    console.log(`Vision staging tenant-isolation audit passed: ${result.tables} privilege maps, ${result.readable} readable tables, zero rows visible; API remains inactive.`);
  }
  http.createServer((request, response) => {
    response.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    response.end('PatrolSync Vision staging is not initialized');
  }).listen(Number(process.env.PORT) || 10000, '0.0.0.0');
}

main().catch(error => {
  // SQL errors can contain query text, so never print a database URL or full SQL error.
  console.error(`Vision staging hold refused: ${error.code || error.message}`);
  process.exitCode = 1;
});

