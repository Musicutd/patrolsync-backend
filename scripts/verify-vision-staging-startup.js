'use strict';

// Boots the real API against an empty, disposable CI database. Never point this at Render.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');
const { Client } = require('pg');
const jwt = require('jsonwebtoken');

const TEST_DB = 'vision_startup_ci';
const TEST_ROLE = 'vision_startup_reader';
const TEST_PASSWORD = 'vision_startup_ci_only';
// Review-only snapshot of the previously unprotected tables on a clean startup.
// Any addition, removal, or rename must stop CI for a fresh security review.
const EXPECTED_UNCOVERED_TABLES = Object.freeze([
  'asset_custody',
  'attendance_breaks',
  'attendance_sessions',
  'audit_logs',
  'auth_sessions',
  'client_report_runs',
  'client_report_schedules',
  'client_users',
  'communication_notification_receipts',
  'communication_notifications',
  'contract_renewal_history',
  'contract_renewals',
  'corrective_actions',
  'dispatch_jobs',
  'email_deliveries',
  'guard_availability',
  'guard_certifications',
  'guard_location_history',
  'guard_locations',
  'handover_logs',
  'incident_activities',
  'incident_photos',
  'incidents',
  'inspection_runs',
  'inspection_templates',
  'integration_api_keys',
  'invoice_lines',
  'invoice_payments',
  'invoices',
  'leave_requests',
  'lone_worker_alerts',
  'lone_worker_checkins',
  'lone_worker_settings',
  'managed_assets',
  'notifications',
  'password_reset_tokens',
  'patrol_alerts',
  'patrol_route_checkpoints',
  'patrol_routes',
  'patrol_run_scans',
  'patrol_runs',
  'service_ticket_comments',
  'service_tickets',
  'shift_swap_requests',
  'shift_templates',
  'shifts',
  'sos_alerts',
  'system_events',
  'team_conversation_reads',
  'team_conversations',
  'team_messages',
  'timesheets',
  'training_assignments',
  'training_materials',
  'webhook_deliveries',
  'webhook_endpoints',
]);
// Prototype only: operations observed in reviewed withTenant() paths.
// This is not a complete permission map for the application.
const CORE_WORKFLOW_GRANTS = Object.freeze({
  attendance_sessions: 'SELECT,INSERT,UPDATE',
  attendance_breaks: 'SELECT,INSERT,UPDATE',
  patrol_routes: 'SELECT,INSERT,UPDATE,DELETE',
  patrol_route_checkpoints: 'SELECT,INSERT,UPDATE,DELETE',
  patrol_runs: 'SELECT,INSERT,UPDATE',
  patrol_run_scans: 'SELECT,INSERT',
  incidents: 'SELECT,INSERT,UPDATE',
  incident_activities: 'SELECT,INSERT',
  incident_photos: 'SELECT,INSERT,DELETE'
});
const WORKFORCE_GRANTS = Object.freeze({
  shifts: 'SELECT,INSERT,UPDATE,DELETE',
  shift_templates: 'SELECT,INSERT,UPDATE,DELETE',
  shift_swap_requests: 'SELECT,INSERT,UPDATE',
  guard_availability: 'SELECT,INSERT,UPDATE',
  leave_requests: 'SELECT,INSERT,UPDATE,DELETE',
  timesheets: 'SELECT,INSERT,UPDATE'
});
const DISPATCH_SAFETY_GRANTS = Object.freeze({
  dispatch_jobs: 'SELECT,INSERT,UPDATE',
  sos_alerts: 'SELECT,INSERT,UPDATE',
  patrol_alerts: 'SELECT,UPDATE',
  notifications: 'SELECT,UPDATE,DELETE',
  communication_notifications: 'SELECT,INSERT,UPDATE,DELETE'
});
const COMMUNICATION_LONE_WORKER_GRANTS = Object.freeze({
  communication_notification_receipts: 'SELECT,INSERT,UPDATE',
  team_conversations: 'SELECT,INSERT,UPDATE',
  team_messages: 'SELECT,INSERT',
  team_conversation_reads: 'SELECT,INSERT,UPDATE',
  lone_worker_settings: 'SELECT,INSERT,UPDATE',
  lone_worker_checkins: 'SELECT,INSERT',
  lone_worker_alerts: 'SELECT,UPDATE'
});
const LOCATION_GRANTS = Object.freeze({
  guard_locations: 'SELECT,INSERT,UPDATE',
  guard_location_history: 'SELECT,INSERT'
});
const CLIENT_ACCESS_GRANTS = Object.freeze({
  client_users: 'SELECT,INSERT,UPDATE,DELETE'
});
const SERVICE_TICKET_GRANTS = Object.freeze({
  service_tickets: 'SELECT,UPDATE',
  service_ticket_comments: 'SELECT'
});
const HANDOVER_GRANTS = Object.freeze({
  handover_logs: 'SELECT,INSERT,UPDATE'
});
const TRAINING_GRANTS = Object.freeze({
  training_materials: 'SELECT,INSERT',
  training_assignments: 'SELECT,INSERT,UPDATE'
});
const ASSET_GRANTS = Object.freeze({
  managed_assets: 'SELECT,INSERT,UPDATE',
  asset_custody: 'SELECT,INSERT,UPDATE'
});
const QUALITY_GRANTS = Object.freeze({
  inspection_templates: 'SELECT,INSERT',
  inspection_runs: 'SELECT,INSERT,UPDATE',
  corrective_actions: 'SELECT,INSERT,UPDATE'
});
const CLIENT_REPORT_GRANTS = Object.freeze({
  client_report_schedules: 'SELECT,INSERT,UPDATE',
  client_report_runs: 'SELECT,INSERT,UPDATE'
});
const RENEWAL_GRANTS = Object.freeze({
  contract_renewals: 'SELECT,INSERT,UPDATE',
  contract_renewal_history: 'SELECT,INSERT'
});
const BILLING_GRANTS = Object.freeze({
  invoices: 'SELECT,INSERT,UPDATE',
  invoice_lines: 'SELECT,INSERT',
  invoice_payments: 'SELECT,INSERT'
});
const INTEGRATION_OWNER_ONLY_TABLES = Object.freeze([
  'integration_api_keys',
  'webhook_endpoints',
  'webhook_deliveries'
]);
const SECURITY_OPERATIONS_GRANTS = Object.freeze({
  audit_logs: 'SELECT',
  system_events: 'SELECT,INSERT'
});
const SECURITY_OWNER_ONLY_TABLES = Object.freeze([
  'auth_sessions',
  'password_reset_tokens'
]);
const CERTIFICATION_DELIVERY_GRANTS = Object.freeze({
  guard_certifications: 'SELECT,INSERT,UPDATE',
  email_deliveries: 'SELECT,UPDATE'
});

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function runControlledMigrations(databaseUrl) {
  const script = path.join(__dirname, 'run-controlled-migrations.js');
  await new Promise((resolve, reject) => {
    const migration = spawn(process.execPath, [script], {
      cwd: path.join(__dirname, '..'),
      env: {
        ...process.env,
        MIGRATION_ENVIRONMENT: 'ci',
        MIGRATION_CONFIRMATION: 'APPLY PATROLSYNC CI MIGRATIONS',
        MIGRATION_DATABASE_URL: databaseUrl,
        MIGRATION_TENANT_ROLE: TEST_ROLE
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let migrationOutput = '';
    for (const stream of [migration.stdout, migration.stderr]) stream.on('data', chunk => {
      migrationOutput = (migrationOutput + chunk.toString()).slice(-20000);
    });
    migration.once('error', reject);
    migration.once('exit', code => code === 0 ? resolve() : reject(new Error(
      `Controlled migration runner exited ${code}. Output:\n${migrationOutput}`)));
  });
}

async function runRelationshipPreflight(databaseUrl) {
  const script = path.join(__dirname, 'run-tenant-relationship-preflight.js');
  await new Promise((resolve, reject) => {
    const preflight = spawn(process.execPath, [script], {
      cwd: path.join(__dirname, '..'),
      env: {
        ...process.env,
        PREFLIGHT_ENVIRONMENT: 'ci',
        PREFLIGHT_CONFIRMATION: 'RUN PATROLSYNC CI READ ONLY PREFLIGHT',
        PREFLIGHT_DATABASE_URL: databaseUrl
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let preflightOutput = '';
    for (const stream of [preflight.stdout, preflight.stderr]) stream.on('data', chunk => {
      preflightOutput = (preflightOutput + chunk.toString()).slice(-20000);
    });
    preflight.once('error', reject);
    preflight.once('exit', code => code === 0 ? resolve() : reject(new Error(
      `Read-only relationship preflight exited ${code}. Output:\n${preflightOutput}`)));
  });
}

async function runControlledRollback(databaseUrl) {
  const script = path.join(__dirname, 'run-controlled-vision-rollback.js');
  await new Promise((resolve, reject) => {
    const rollback = spawn(process.execPath, [script], {
      cwd: path.join(__dirname, '..'),
      env: {
        ...process.env,
        ROLLBACK_ENVIRONMENT: 'ci',
        ROLLBACK_CONFIRMATION: 'ROLL BACK PATROLSYNC CI VISION MIGRATIONS',
        ROLLBACK_DATABASE_URL: databaseUrl,
        ROLLBACK_TENANT_ROLE: TEST_ROLE
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let rollbackOutput = '';
    for (const stream of [rollback.stdout, rollback.stderr]) stream.on('data', chunk => {
      rollbackOutput = (rollbackOutput + chunk.toString()).slice(-20000);
    });
    rollback.once('error', reject);
    rollback.once('exit', code => code === 0 ? resolve() : reject(new Error(
      `Controlled rollback exited ${code}. Output:\n${rollbackOutput}`)));
  });
}

async function verifyControlledMigrations(databaseUrl) {
  const script = path.join(__dirname, 'verify-controlled-vision-migrations.js');
  await new Promise((resolve, reject) => {
    const verification = spawn(process.execPath, [script], {
      cwd: path.join(__dirname, '..'),
      env: {
        ...process.env,
        VERIFY_ENVIRONMENT: 'ci',
        VERIFY_CONFIRMATION: 'VERIFY PATROLSYNC CI VISION MIGRATIONS',
        VERIFY_DATABASE_URL: databaseUrl,
        VERIFY_TENANT_ROLE: TEST_ROLE
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let verificationOutput = '';
    for (const stream of [verification.stdout, verification.stderr]) stream.on('data', chunk => {
      verificationOutput = (verificationOutput + chunk.toString()).slice(-20000);
    });
    verification.once('error', reject);
    verification.once('exit', code => code === 0 ? resolve() : reject(new Error(
      `Controlled migration verification exited ${code}. Output:\n${verificationOutput}`)));
  });
}

async function verifyControlledRollback(databaseUrl) {
  const script = path.join(__dirname, 'verify-controlled-vision-rollback.js');
  await new Promise((resolve, reject) => {
    const verification = spawn(process.execPath, [script], {
      cwd: path.join(__dirname, '..'),
      env: {
        ...process.env,
        VERIFY_ROLLBACK_ENVIRONMENT: 'ci',
        VERIFY_ROLLBACK_CONFIRMATION: 'VERIFY PATROLSYNC CI VISION ROLLBACK',
        VERIFY_ROLLBACK_DATABASE_URL: databaseUrl,
        VERIFY_ROLLBACK_TENANT_ROLE: TEST_ROLE
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let verificationOutput = '';
    for (const stream of [verification.stdout, verification.stderr]) stream.on('data', chunk => {
      verificationOutput = (verificationOutput + chunk.toString()).slice(-20000);
    });
    verification.once('error', reject);
    verification.once('exit', code => code === 0 ? resolve() : reject(new Error(
      `Controlled rollback verification exited ${code}. Output:\n${verificationOutput}`)));
  });
}

async function main() {
  const source = new URL(process.env.VISION_TEST_DATABASE_URL || '');
  assert.ok(['127.0.0.1', 'localhost'].includes(source.hostname), 'CI database must be on loopback');
  assert.equal(source.pathname, '/vision_ci', 'Refusing any database other than the CI fixture');
  const admin = new Client({ connectionString: source.href });
  const target = new URL(source.href);
  target.pathname = `/${TEST_DB}`;
  let child;
  let output = '';
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${TEST_DB}`);
    const db = new Client({ connectionString: target.href });
    await db.connect();
    try {
      await db.query(`CREATE ROLE ${TEST_ROLE} LOGIN PASSWORD '${TEST_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`);
      const fixture = fs.readFileSync(path.join(__dirname, '..', 'test', 'fixtures', 'vision-staging-base.sql'), 'utf8');
      await db.query(fixture.replaceAll('vision_base_reader', TEST_ROLE));
      await db.query(`GRANT USAGE ON SCHEMA public TO ${TEST_ROLE}`);
      await db.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON tenants,sites,users,checkpoints,patrol_schedules,patrol_logs,alert_log,guard_assignments,service_contracts TO ${TEST_ROLE}`);
    } finally { await db.end(); }

    const port = await freePort();
    const restricted = new URL(target.href);
    restricted.username = TEST_ROLE;
    restricted.password = TEST_PASSWORD;
    child = spawn(process.execPath, [
      '--require', path.join(__dirname, '..', 'test', 'helpers', 'local-postgres-no-ssl.js'),
      path.join(__dirname, '..', 'index.js')
    ], {
      cwd: path.join(__dirname, '..'),
      env: {
        ...process.env, NODE_ENV: 'test', VISION_ENABLED: 'false',
        DATABASE_URL: target.href, SYSTEM_DATABASE_URL: target.href,
        TENANT_DATABASE_URL: restricted.href, VISION_TEST_DATABASE_URL: target.href,
        VISION_TEST_TENANT_DATABASE_URL: restricted.href,
        PORT: String(port), AI_ASSISTANT_ENABLED: 'false',
        STRIPE_SECRET_KEY: '', OPENAI_API_KEY: '', BREVO_API_KEY: ''
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
      output = (output + chunk.toString()).slice(-20000);
    });

    let healthy = false;
    let tables = 0;
    let missingTables = [];
    const sourceCode = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    const expectedTables = new Set([...sourceCode.matchAll(/CREATE TABLE IF NOT EXISTS\s+([a-z_][a-z0-9_]*)/gi)]
      .map(match => match[1].toLowerCase()));
    for (const name of ['tenants', 'sites', 'users', 'checkpoints', 'patrol_schedules', 'patrol_logs', 'alert_log']) {
      expectedTables.add(name);
    }
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline && child.exitCode === null) {
      try {
        const response = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(1000) });
        healthy = response.status === 200;
        const count = new Client({ connectionString: target.href });
        await count.connect();
        try {
          const found = new Set((await count.query(`SELECT tablename FROM pg_tables WHERE schemaname='public'`))
            .rows.map(row => row.tablename));
          tables = found.size;
          missingTables = [...expectedTables].filter(name => !found.has(name)).sort();
        } finally { await count.end(); }
        if (healthy && missingTables.length === 0) break;
      } catch (_) { /* Server is still starting. */ }
      await delay(500);
    }
    assert.ok(healthy, `API health did not become ready. Output:\n${output}`);
    assert.deepEqual(missingTables, [], `Missing startup tables: ${missingTables.join(', ')}. ${tables} tables initialized. Output:\n${output}`);
    assert.doesNotMatch(output, /setup failed:|unhandled_rejection/i, `Startup error:\n${output}`);
    const audit = new Client({ connectionString: target.href });
    await audit.connect();
    try {
      // HTTP regression: legacy subscriber endpoints must reject a tenant_id
      // different from the one in the signed token before selecting RLS context.
      const account = await audit.query(`WITH own AS (
        INSERT INTO tenants(name,slug) VALUES('HTTP One','vision-http-one') RETURNING id
      ), other AS (
        INSERT INTO tenants(name,slug) VALUES('HTTP Two','vision-http-two') RETURNING id
      ), actor AS (
        INSERT INTO users(tenant_id,email,role) SELECT id,'vision-http-admin@example.test','admin' FROM own RETURNING id,tenant_id
      ) SELECT actor.id AS user_id, actor.tenant_id AS own_tenant_id, other.id AS other_tenant_id FROM actor CROSS JOIN other`);
      const { user_id: userId, own_tenant_id: ownTenantId, other_tenant_id: otherTenantId } = account.rows[0];
      const token = jwt.sign({ user_id: userId, tenant_id: ownTenantId, role: 'admin', email: 'vision-http-admin@example.test' },
        process.env.JWT_SECRET || 'patrolsync-dev-secret', { expiresIn: '5m' });
      const ownSites = await fetch(`http://127.0.0.1:${port}/api/sites?tenant_id=${ownTenantId}`, {
        headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000)
      });
      assert.equal(ownSites.status, 200, 'A matching signed-in tenant must retain normal site access');
      assert.deepEqual(await ownSites.json(), []);
      const guard = await audit.query(`INSERT INTO users(tenant_id,email,role)
        VALUES($1,'vision-http-guard@example.test','guard') RETURNING id`, [ownTenantId]);
      const site = await audit.query(`INSERT INTO sites(tenant_id,name)
        VALUES($1,'Unassigned CI Site') RETURNING id`, [ownTenantId]);
      const clientToken = jwt.sign({ user_id: 9001, tenant_id: ownTenantId, role: 'client', site_id: site.rows[0].id },
        process.env.JWT_SECRET || 'patrolsync-dev-secret', { expiresIn: '5m' });
      const guardToken = jwt.sign({ user_id: guard.rows[0].id, tenant_id: ownTenantId, role: 'guard' },
        process.env.JWT_SECRET || 'patrolsync-dev-secret', { expiresIn: '5m' });
      for (const [label, actorToken, expectedError] of [
        ['administrator', token, 'Guard access required'],
        ['client', clientToken, 'Guard access required'],
        ['guard without site assignment', guardToken, 'Guard is not assigned to this site']
      ]) {
        const response = await fetch(`http://127.0.0.1:${port}/api/guard-locations`, {
          method: 'POST', headers: { Authorization: `Bearer ${actorToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ tenant_id: ownTenantId, site_id: site.rows[0].id, latitude: 35.9, longitude: 14.5 }),
          signal: AbortSignal.timeout(5000)
        });
        assert.equal(response.status, 403, `${label} must not submit a guard location`);
        assert.equal((await response.json()).error, expectedError);
      }
      for (const [method, route, body] of [
        ['GET', `/api/usage?tenant_id=${otherTenantId}`],
        ['GET', `/api/notifications?tenant_id=${otherTenantId}`],
        ['GET', `/api/sites?tenant_id=${ownTenantId}&tenant_id=${otherTenantId}`],
        ['POST', '/api/sos', { tenant_id: otherTenantId, message: 'CI only' }]
      ]) {
        const response = await fetch(`http://127.0.0.1:${port}${route}`, {
          method, headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
          ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(5000)
        });
        assert.equal(response.status, 403, `${method} ${route} must reject a foreign tenant`);
        assert.equal((await response.json()).error, 'Tenant access denied');
      }
      console.log('Subscriber HTTP tenant binding: matching tenant allowed; forged query/body tenant IDs rejected.');
      const coverage = await audit.query(`
        SELECT c.relname AS table_name, c.relrowsecurity AS rls_enabled
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
          AND EXISTS (
            SELECT 1 FROM pg_attribute a
            WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
              AND a.attnum > 0 AND NOT a.attisdropped
          )
        ORDER BY c.relname
      `);
      const uncovered = coverage.rows.filter(row => !row.rls_enabled).map(row => row.table_name);
      console.log(`Tenant-keyed RLS coverage: ${coverage.rows.length - uncovered.length}/${coverage.rows.length}.`);
      if (uncovered.length) console.log(`Tenant-keyed tables without RLS: ${uncovered.join(', ')}.`);
      assert.deepEqual(uncovered, EXPECTED_UNCOVERED_TABLES,
        'Clean-startup RLS inventory changed; review table ownership before extending the prototype');
      const preexistingProtected = coverage.rows.filter(row => row.rls_enabled).map(row => row.table_name);
      const preexistingPolicies = await audit.query(`
        SELECT tablename, policyname, cmd, roles::text AS roles, qual, with_check
        FROM pg_policies WHERE schemaname='public' ORDER BY tablename,policyname
      `);
      const applicable = preexistingPolicies.rows.filter(row => preexistingProtected.includes(row.tablename)
        && (row.roles.includes('public') || row.roles.includes(TEST_ROLE)));
      const coveredByPolicy = new Set(applicable.map(row => row.tablename));
      assert.deepEqual([...coveredByPolicy].sort(), preexistingProtected.sort(),
        'Every pre-existing tenant-table RLS policy needs an applicable restricted-role rule');
      for (const policy of applicable) {
        const readPredicate = policy.qual || '';
        const writePredicate = policy.with_check || readPredicate;
        if (['ALL', 'SELECT', 'UPDATE', 'DELETE'].includes(policy.cmd.toUpperCase())) {
          assert.ok(readPredicate.includes('tenant_id') && readPredicate.includes('app.current_tenant'),
            `${policy.tablename}.${policy.policyname} lacks a tenant-bound read predicate`);
        }
        if (['ALL', 'INSERT', 'UPDATE'].includes(policy.cmd.toUpperCase())) {
          assert.ok(writePredicate.includes('tenant_id') && writePredicate.includes('app.current_tenant'),
            `${policy.tablename}.${policy.policyname} lacks a tenant-bound write predicate`);
        }
      }
      console.log(`Existing RLS policy metadata: ${coveredByPolicy.size} tenant tables, ${applicable.length} applicable policies with tenant-bound predicates.`);
      await runRelationshipPreflight(target.href);
      await runControlledMigrations(target.href);
      await runControlledMigrations(target.href);
      await verifyControlledMigrations(target.href);
      const migrationLedger = await audit.query(`SELECT version FROM patrolsync_schema_migrations ORDER BY version`);
      assert.deepEqual(migrationLedger.rows.map(row => row.version), [
        '0001_migration_foundation',
        '0002_tenant_workflow_policies_and_grants',
        '0003_tenant_parent_child_constraints'
      ], 'Controlled migrations must be applied exactly once and remain repeatable');
      const privileges = await audit.query(`
        SELECT c.relname AS table_name,
          has_table_privilege($1, format('public.%I',c.relname), 'SELECT') AS can_select,
          has_table_privilege($1, format('public.%I',c.relname), 'INSERT') AS can_insert,
          has_table_privilege($1, format('public.%I',c.relname), 'UPDATE') AS can_update,
          has_table_privilege($1, format('public.%I',c.relname), 'DELETE') AS can_delete
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p')
          AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
            AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped)
        ORDER BY c.relname
      `, [TEST_ROLE]);
      for (const table of ['platform_load_tests', 'email_mfa_challenges', 'mfa_recovery_codes']) {
        const access = privileges.rows.find(row => row.table_name === table);
        assert.ok(access, `${table} must be present in the tenant-table inventory`);
        assert.deepEqual([access.can_select, access.can_insert, access.can_update, access.can_delete],
          [false, false, false, false], `${table} must remain owner-only for the restricted role`);
      }
      const readable = privileges.rows.filter(row => row.can_select);
      const writable = privileges.rows.filter(row => row.can_insert && row.can_update && row.can_delete);
      console.log(`Restricted-role tenant-table grants: ${readable.length}/${privileges.rowCount} readable; ${writable.length}/${privileges.rowCount} full CRUD.`);
      console.log(`Tenant-keyed tables without restricted-role SELECT: ${privileges.rows.filter(row => !row.can_select).map(row => row.table_name).join(', ')}.`);
      // Parent/child constraint prototypes remain disposable until migration 0003.
      await audit.query('BEGIN');
      try {
        const after = await audit.query(`
          SELECT COUNT(*)::int AS total,
                 COUNT(*) FILTER (WHERE c.relrowsecurity)::int AS protected
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relkind IN ('r','p')
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
              AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped)
        `);
        assert.equal(after.rows[0].protected, after.rows[0].total);
        const addedPolicies = await audit.query(`
          SELECT tablename, roles::text AS roles, qual, with_check
          FROM pg_policies
          WHERE schemaname='public' AND policyname='patrolsync_tenant_isolation'
            AND tablename=ANY($1::text[])
          ORDER BY tablename
        `, [EXPECTED_UNCOVERED_TABLES]);
        assert.deepEqual(addedPolicies.rows.map(row => row.tablename), EXPECTED_UNCOVERED_TABLES);
        assert.ok(addedPolicies.rows.every(row => row.roles.includes(TEST_ROLE)
          && row.qual?.includes('app.current_tenant')
          && row.with_check?.includes('app.current_tenant')),
        'Every added policy must be scoped to the restricted role and tenant context');
        // Migration 0003 now owns these constraints. Keep the former prototype
        // disabled temporarily so the behavioral assertions below prove the
        // migrated constraints rather than transaction-local test setup.
        if (false) {
        for (const [parent, child, childColumn] of [
          ['communication_notifications', 'communication_notification_receipts', 'notification_id'],
          ['team_conversations', 'team_messages', 'conversation_id'],
          ['team_conversations', 'team_conversation_reads', 'conversation_id'],
          ['lone_worker_settings', 'lone_worker_checkins', 'setting_id'],
          ['lone_worker_settings', 'lone_worker_alerts', 'setting_id'],
          ['crisis_activations', 'crisis_roles', 'crisis_id'],
          ['crisis_activations', 'crisis_actions', 'crisis_id'],
          ['crisis_activations', 'crisis_updates', 'crisis_id'],
          ['guard_trusted_devices', 'identity_verification_events', 'device_id']
        ]) {
          const uniqueName = `vision_ci_${parent}_tenant_id_unique`;
          if (!(await audit.query(`SELECT 1 FROM pg_constraint WHERE conname=$1`, [uniqueName])).rowCount) {
            await audit.query(`ALTER TABLE public.${parent} ADD CONSTRAINT ${uniqueName} UNIQUE(tenant_id,id)`);
          }
          await audit.query(`ALTER TABLE public.${child} ADD CONSTRAINT vision_ci_${child}_tenant_parent_fk
            FOREIGN KEY(tenant_id,${childColumn}) REFERENCES public.${parent}(tenant_id,id)`);
        }
        await audit.query(`ALTER TABLE public.sites ADD CONSTRAINT vision_ci_sites_tenant_id_unique UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.client_users ADD CONSTRAINT vision_ci_client_users_tenant_site_fk
          FOREIGN KEY(tenant_id,site_id) REFERENCES public.sites(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.users ADD CONSTRAINT vision_ci_users_tenant_id_unique UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.handover_logs ADD CONSTRAINT vision_ci_handovers_tenant_site_fk
          FOREIGN KEY(tenant_id,site_id) REFERENCES public.sites(tenant_id,id)`);
        for (const column of ['from_user_id', 'to_user_id', 'acknowledged_by', 'resolved_by']) {
          await audit.query(`ALTER TABLE public.handover_logs ADD CONSTRAINT vision_ci_handovers_tenant_${column}_fk
            FOREIGN KEY(tenant_id,${column}) REFERENCES public.users(tenant_id,id)`);
        }
        await audit.query(`ALTER TABLE public.training_materials ADD CONSTRAINT vision_ci_training_materials_tenant_id_unique
          UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.training_materials ADD CONSTRAINT vision_ci_training_materials_tenant_site_fk
          FOREIGN KEY(tenant_id,site_id) REFERENCES public.sites(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.training_materials ADD CONSTRAINT vision_ci_training_materials_tenant_creator_fk
          FOREIGN KEY(tenant_id,created_by_user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.training_assignments ADD CONSTRAINT vision_ci_training_assignments_tenant_material_fk
          FOREIGN KEY(tenant_id,material_id) REFERENCES public.training_materials(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.training_assignments ADD CONSTRAINT vision_ci_training_assignments_tenant_user_fk
          FOREIGN KEY(tenant_id,user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.managed_assets ADD CONSTRAINT vision_ci_managed_assets_tenant_id_unique
          UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.managed_assets ADD CONSTRAINT vision_ci_managed_assets_tenant_site_fk
          FOREIGN KEY(tenant_id,site_id) REFERENCES public.sites(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.asset_custody ADD CONSTRAINT vision_ci_asset_custody_tenant_asset_fk
          FOREIGN KEY(tenant_id,asset_id) REFERENCES public.managed_assets(tenant_id,id)`);
        for (const column of ['user_id', 'issued_by_user_id']) {
          await audit.query(`ALTER TABLE public.asset_custody ADD CONSTRAINT vision_ci_asset_custody_tenant_${column}_fk
            FOREIGN KEY(tenant_id,${column}) REFERENCES public.users(tenant_id,id)`);
        }
        await audit.query(`ALTER TABLE public.inspection_templates ADD CONSTRAINT vision_ci_inspection_templates_tenant_id_unique UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.inspection_templates ADD CONSTRAINT vision_ci_inspection_templates_tenant_site_fk FOREIGN KEY(tenant_id,site_id) REFERENCES public.sites(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.inspection_templates ADD CONSTRAINT vision_ci_inspection_templates_tenant_creator_fk FOREIGN KEY(tenant_id,created_by_user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.inspection_runs ADD CONSTRAINT vision_ci_inspection_runs_tenant_id_unique UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.inspection_runs ADD CONSTRAINT vision_ci_inspection_runs_tenant_template_fk FOREIGN KEY(tenant_id,template_id) REFERENCES public.inspection_templates(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.inspection_runs ADD CONSTRAINT vision_ci_inspection_runs_tenant_site_fk FOREIGN KEY(tenant_id,site_id) REFERENCES public.sites(tenant_id,id)`);
        for (const column of ['assigned_user_id', 'created_by_user_id']) {
          await audit.query(`ALTER TABLE public.inspection_runs ADD CONSTRAINT vision_ci_inspection_runs_tenant_${column}_fk FOREIGN KEY(tenant_id,${column}) REFERENCES public.users(tenant_id,id)`);
        }
        await audit.query(`ALTER TABLE public.corrective_actions ADD CONSTRAINT vision_ci_corrective_actions_tenant_run_fk FOREIGN KEY(tenant_id,inspection_run_id) REFERENCES public.inspection_runs(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.corrective_actions ADD CONSTRAINT vision_ci_corrective_actions_tenant_assignee_fk FOREIGN KEY(tenant_id,assigned_user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.service_contracts ADD CONSTRAINT vision_ci_contracts_tenant_id_unique
          UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.client_report_schedules ADD CONSTRAINT vision_ci_report_schedules_tenant_id_unique UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.client_report_schedules ADD CONSTRAINT vision_ci_report_schedules_tenant_contract_fk FOREIGN KEY(tenant_id,contract_id) REFERENCES public.service_contracts(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.client_report_schedules ADD CONSTRAINT vision_ci_report_schedules_tenant_creator_fk FOREIGN KEY(tenant_id,created_by) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.client_report_runs ADD CONSTRAINT vision_ci_report_runs_tenant_schedule_fk FOREIGN KEY(tenant_id,schedule_id) REFERENCES public.client_report_schedules(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.client_report_runs ADD CONSTRAINT vision_ci_report_runs_tenant_contract_fk FOREIGN KEY(tenant_id,contract_id) REFERENCES public.service_contracts(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.client_report_runs ADD CONSTRAINT vision_ci_report_runs_tenant_deliverer_fk FOREIGN KEY(tenant_id,delivered_by) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.contract_renewals ADD CONSTRAINT vision_ci_contract_renewals_tenant_id_unique UNIQUE(tenant_id,id)`);
        for (const column of ['contract_id', 'completed_contract_id']) {
          await audit.query(`ALTER TABLE public.contract_renewals ADD CONSTRAINT vision_ci_contract_renewals_tenant_${column}_fk FOREIGN KEY(tenant_id,${column}) REFERENCES public.service_contracts(tenant_id,id)`);
        }
        await audit.query(`ALTER TABLE public.contract_renewals ADD CONSTRAINT vision_ci_contract_renewals_tenant_owner_fk FOREIGN KEY(tenant_id,owner_user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.contract_renewal_history ADD CONSTRAINT vision_ci_contract_history_tenant_renewal_fk FOREIGN KEY(tenant_id,renewal_id) REFERENCES public.contract_renewals(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.contract_renewal_history ADD CONSTRAINT vision_ci_contract_history_tenant_user_fk FOREIGN KEY(tenant_id,user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.invoices ADD CONSTRAINT vision_ci_invoices_tenant_contract_fk FOREIGN KEY(tenant_id,contract_id) REFERENCES public.service_contracts(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.invoices ADD CONSTRAINT vision_ci_invoices_tenant_creator_fk FOREIGN KEY(tenant_id,created_by) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.invoice_payments ADD CONSTRAINT vision_ci_invoice_payments_tenant_invoice_fk FOREIGN KEY(tenant_id,invoice_id) REFERENCES public.invoices(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.invoice_payments ADD CONSTRAINT vision_ci_invoice_payments_tenant_recorder_fk FOREIGN KEY(tenant_id,recorded_by) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.webhook_endpoints ADD CONSTRAINT vision_ci_webhook_endpoints_tenant_id_unique UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.webhook_deliveries ADD CONSTRAINT vision_ci_webhook_deliveries_tenant_webhook_fk FOREIGN KEY(tenant_id,webhook_id) REFERENCES public.webhook_endpoints(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.integration_api_keys ADD CONSTRAINT vision_ci_integration_keys_tenant_creator_fk FOREIGN KEY(tenant_id,created_by_user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.auth_sessions ADD CONSTRAINT vision_ci_auth_sessions_tenant_user_fk FOREIGN KEY(tenant_id,user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.password_reset_tokens ADD CONSTRAINT vision_ci_password_resets_tenant_user_fk FOREIGN KEY(tenant_id,user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.audit_logs ADD CONSTRAINT vision_ci_audit_logs_tenant_user_fk FOREIGN KEY(tenant_id,user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.guard_certifications ADD CONSTRAINT vision_ci_guard_certifications_tenant_id_unique UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.guard_certifications ADD CONSTRAINT vision_ci_guard_certifications_tenant_user_fk FOREIGN KEY(tenant_id,user_id) REFERENCES public.users(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.guard_certifications ADD CONSTRAINT vision_ci_guard_certifications_tenant_archiver_fk FOREIGN KEY(tenant_id,archived_by_user_id) REFERENCES public.users(tenant_id,id)`);
        for (const column of ['replacement_for_id', 'replaced_by_id']) {
          await audit.query(`ALTER TABLE public.guard_certifications ADD CONSTRAINT vision_ci_guard_certifications_tenant_${column}_fk FOREIGN KEY(tenant_id,${column}) REFERENCES public.guard_certifications(tenant_id,id)`);
        }
        for (const table of ['operations_risk_snapshots', 'site_risk_twins', 'site_risk_scenarios']) {
          await audit.query(`ALTER TABLE public.${table} ADD CONSTRAINT vision_ci_${table}_tenant_site_fk
            FOREIGN KEY(tenant_id,site_id) REFERENCES public.sites(tenant_id,id)`);
        }
        await audit.query(`ALTER TABLE public.client_retention_snapshots ADD CONSTRAINT vision_ci_retention_tenant_contract_fk
          FOREIGN KEY(tenant_id,contract_id) REFERENCES public.service_contracts(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.service_tickets ADD CONSTRAINT vision_ci_service_tickets_tenant_id_unique
          UNIQUE(tenant_id,id)`);
        await audit.query(`ALTER TABLE public.service_ticket_comments ADD CONSTRAINT vision_ci_ticket_comments_tenant_ticket_fk
          FOREIGN KEY(tenant_id,ticket_id) REFERENCES public.service_tickets(tenant_id,id)`);
        }
        const reviewedGrants = { ...CORE_WORKFLOW_GRANTS, ...WORKFORCE_GRANTS,
          ...DISPATCH_SAFETY_GRANTS, ...COMMUNICATION_LONE_WORKER_GRANTS,
          ...LOCATION_GRANTS, ...CLIENT_ACCESS_GRANTS, ...SERVICE_TICKET_GRANTS,
          ...HANDOVER_GRANTS, ...TRAINING_GRANTS, ...ASSET_GRANTS,
          ...QUALITY_GRANTS, ...CLIENT_REPORT_GRANTS, ...RENEWAL_GRANTS,
          ...BILLING_GRANTS, ...SECURITY_OPERATIONS_GRANTS,
          ...CERTIFICATION_DELIVERY_GRANTS };
        for (const [table, operations] of Object.entries(reviewedGrants)) {
          assert.ok(EXPECTED_UNCOVERED_TABLES.includes(table), `${table} needs separate review before adding a grant`);
          for (const operation of ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) {
            const granted = (await audit.query(`SELECT has_table_privilege($1,$2,$3) AS allowed`,
              [TEST_ROLE, `public.${table}`, operation])).rows[0].allowed;
            assert.equal(granted, operations.split(',').includes(operation),
              `${table} ${operation} differs from reviewed core-workflow scope`);
          }
        }
        for (const table of [...INTEGRATION_OWNER_ONLY_TABLES, ...SECURITY_OWNER_ONLY_TABLES]) {
          assert.ok(EXPECTED_UNCOVERED_TABLES.includes(table), `${table} must remain in the reviewed inventory`);
          for (const operation of ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) {
            const granted = (await audit.query(`SELECT has_table_privilege($1,$2,$3) AS allowed`,
              [TEST_ROLE, `public.${table}`, operation])).rows[0].allowed;
            assert.equal(granted, false, `${table} must remain owner-only for ${operation}`);
          }
        }
        console.log(`Controlled workflow grants passed: ${Object.keys(reviewedGrants).length} tables; no blanket grant.`);
        assert.ok(uncovered.includes('system_events'), 'Representative previously unprotected table was not found');
        const first = await audit.query(`INSERT INTO tenants(name,slug) VALUES('CI One','vision-ci-one') RETURNING id`);
        const second = await audit.query(`INSERT INTO tenants(name,slug) VALUES('CI Two','vision-ci-two') RETURNING id`);
        const oneId = first.rows[0].id, twoId = second.rows[0].id;
        const oneSite = await audit.query(`INSERT INTO sites(tenant_id,name) VALUES($1,'CI One Site') RETURNING id`, [oneId]);
        const twoSite = await audit.query(`INSERT INTO sites(tenant_id,name) VALUES($1,'CI Two Site') RETURNING id`, [twoId]);
        const baselineUsers = await audit.query(`INSERT INTO users(tenant_id,email,role)
          VALUES($1,'ci-baseline-one@example.test','guard'),($2,'ci-baseline-two@example.test','guard')
          RETURNING id,tenant_id`, [oneId, twoId]);
        await audit.query(`INSERT INTO platform_load_tests(
          tenant_id,scenario,concurrency,duration_seconds,status,instance_id)
          VALUES($1,'CI owner-only',1,1,'completed','ci-one'),
                ($2,'CI owner-only',1,1,'completed','ci-two')`, [oneId, twoId]);
        await audit.query(`INSERT INTO email_mfa_challenges(
          tenant_id,user_id,purpose,token_hash,code_hash,expires_at)
          VALUES($1,$2,'login','ci-token-one','ci-code-one',NOW()+INTERVAL '5 minutes'),
                ($3,$4,'login','ci-token-two','ci-code-two',NOW()+INTERVAL '5 minutes')`,
          [oneId, baselineUsers.rows[0].id, twoId, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO mfa_recovery_codes(tenant_id,user_id,code_hash)
          VALUES($1,$2,'ci-recovery-one'),($3,$4,'ci-recovery-two')`,
          [oneId, baselineUsers.rows[0].id, twoId, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO identity_assurance_settings(tenant_id,enabled,consent_version)
          VALUES($1,TRUE,'ci-v1'),($2,TRUE,'ci-v1')`, [oneId, twoId]);
        const trustedDevices = await audit.query(`INSERT INTO guard_trusted_devices(
          tenant_id,user_id,device_hash,device_name,consent_version,consented_at)
          VALUES($1,$2,'ci-device-one','CI device one','ci-v1',NOW()),
                ($3,$4,'ci-device-two','CI device two','ci-v1',NOW()) RETURNING id,tenant_id`,
          [oneId, baselineUsers.rows[0].id, twoId, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO identity_verification_events(
          tenant_id,user_id,device_id,action_type,resource_type,outcome,enforcement_mode,reason)
          VALUES($1,$2,$3,'patrol_scan','patrol_log','verified','observe','CI only'),
                ($4,$5,$6,'patrol_scan','patrol_log','verified','observe','CI only')`,
          [oneId, baselineUsers.rows[0].id, trustedDevices.rows[0].id,
            twoId, baselineUsers.rows[1].id, trustedDevices.rows[1].id]);
        await audit.query(`INSERT INTO operations_risk_snapshots(
          tenant_id,site_id,score,level,factors,recommendations)
          VALUES($1,$2,10,'low','[]'::jsonb,'[]'::jsonb),
                ($3,$4,10,'low','[]'::jsonb,'[]'::jsonb)`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO evidence_integrity_records(
          tenant_id,evidence_type,evidence_id,source_hash,chain_hash,snapshot)
          VALUES($1,'patrol_log','ci-one',repeat('1',64),repeat('2',64),'{}'::jsonb),
                ($2,'patrol_log','ci-two',repeat('3',64),repeat('4',64),'{}'::jsonb)`,
          [oneId, twoId]);
        await audit.query(`INSERT INTO tender_proposals(
          tenant_id,title,prospect_name,reference_code,executive_summary,scope)
          VALUES($1,'CI one proposal','CI one prospect','CI-PROP-ONE','CI only','CI only'),
                ($2,'CI two proposal','CI two prospect','CI-PROP-TWO','CI only','CI only')`,
          [oneId, twoId]);
        await audit.query(`INSERT INTO site_risk_twins(tenant_id,site_id,profile_name)
          VALUES($1,$2,'CI one twin'),($3,$4,'CI two twin')`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO site_risk_scenarios(
          tenant_id,site_id,name,baseline_score,projected_score,projected_band)
          VALUES($1,$2,'CI one scenario',10,20,'low'),
                ($3,$4,'CI two scenario',10,20,'low')`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        const checkpoints = await audit.query(`INSERT INTO checkpoints(tenant_id,site_id,name,qr_code)
          VALUES($1,$2,'CI checkpoint','VISION-CI-ONE'),($3,$4,'CI checkpoint','VISION-CI-TWO')
          RETURNING id,tenant_id`, [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO patrol_schedules(tenant_id,site_id,schedule_type,config)
          VALUES($1,$2,'fixed','{}'::jsonb),($3,$4,'fixed','{}'::jsonb)`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO patrol_logs(tenant_id,checkpoint_id,user_id)
          VALUES($1,$2,$3),($4,$5,$6)`,
          [oneId, checkpoints.rows[0].id, baselineUsers.rows[0].id,
            twoId, checkpoints.rows[1].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO alert_log(tenant_id,checkpoint_id)
          VALUES($1,$2),($3,$4)`, [oneId, checkpoints.rows[0].id, twoId, checkpoints.rows[1].id]);
        await audit.query(`INSERT INTO guard_assignments(tenant_id,site_id,user_id)
          VALUES($1,$2,$3),($4,$5,$6)`,
          [oneId, oneSite.rows[0].id, baselineUsers.rows[0].id,
            twoId, twoSite.rows[0].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO handover_logs(tenant_id,site_id,from_user_id,summary)
          VALUES($1,$2,$3,'CI one handover'),($4,$5,$6,'CI two handover')`,
          [oneId, oneSite.rows[0].id, baselineUsers.rows[0].id,
            twoId, twoSite.rows[0].id, baselineUsers.rows[1].id]);
        const contracts = await audit.query(`INSERT INTO service_contracts(tenant_id,site_id,reference_code,client_name,start_date)
          VALUES($1,$2,'CI-CONTRACT-ONE','CI only','2026-09-17'),
                ($3,$4,'CI-CONTRACT-TWO','CI only','2026-09-17') RETURNING id,tenant_id`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        const reportSchedules = await audit.query(`INSERT INTO client_report_schedules(
          tenant_id,contract_id,recipient_email,frequency,next_run_date,created_by)
          VALUES($1,$2,'ci-one@example.test','monthly','2026-10-01',$3),
                ($4,$5,'ci-two@example.test','monthly','2026-10-01',$6)
          RETURNING id,tenant_id`,
          [oneId, contracts.rows[0].id, baselineUsers.rows[0].id,
            twoId, contracts.rows[1].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO client_report_runs(
          tenant_id,schedule_id,contract_id,period_start,period_end,recipient_email)
          VALUES($1,$2,$3,'2026-09-01','2026-09-30','ci-one@example.test'),
                ($4,$5,$6,'2026-09-01','2026-09-30','ci-two@example.test')`,
          [oneId, reportSchedules.rows[0].id, contracts.rows[0].id,
            twoId, reportSchedules.rows[1].id, contracts.rows[1].id]);
        const renewals = await audit.query(`INSERT INTO contract_renewals(
          tenant_id,contract_id,owner_user_id,proposed_start_date)
          VALUES($1,$2,$3,'2026-10-01'),($4,$5,$6,'2026-10-01')
          RETURNING id,tenant_id`,
          [oneId, contracts.rows[0].id, baselineUsers.rows[0].id,
            twoId, contracts.rows[1].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO contract_renewal_history(tenant_id,renewal_id,action,user_id)
          VALUES($1,$2,'created',$3),($4,$5,'created',$6)`,
          [oneId, renewals.rows[0].id, baselineUsers.rows[0].id,
            twoId, renewals.rows[1].id, baselineUsers.rows[1].id]);
        const invoices = await audit.query(`INSERT INTO invoices(
          tenant_id,contract_id,invoice_number,period_start,period_end,due_date,total,created_by)
          VALUES($1,$2,'CI-INVOICE-ONE','2026-09-01','2026-09-30','2026-10-30',100,$3),
                ($4,$5,'CI-INVOICE-TWO','2026-09-01','2026-09-30','2026-10-30',100,$6)
          RETURNING id,tenant_id`,
          [oneId, contracts.rows[0].id, baselineUsers.rows[0].id,
            twoId, contracts.rows[1].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO invoice_lines(tenant_id,invoice_id,description,quantity,unit_rate,line_total)
          VALUES($1,$2,'CI one line',1,100,100),($3,$4,'CI two line',1,100,100)`,
          [oneId, invoices.rows[0].id, twoId, invoices.rows[1].id]);
        await audit.query(`INSERT INTO invoice_payments(tenant_id,invoice_id,amount,payment_date,recorded_by)
          VALUES($1,$2,25,'2026-09-29',$3),($4,$5,25,'2026-09-29',$6)`,
          [oneId, invoices.rows[0].id, baselineUsers.rows[0].id,
            twoId, invoices.rows[1].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO integration_api_keys(tenant_id,name,key_prefix,key_hash,created_by_user_id)
          VALUES($1,'CI one key','ci_one','ci-one-hash',$2),($3,'CI two key','ci_two','ci-two-hash',$4)`,
          [oneId, baselineUsers.rows[0].id, twoId, baselineUsers.rows[1].id]);
        const webhooks = await audit.query(`INSERT INTO webhook_endpoints(tenant_id,name,url,secret)
          VALUES($1,'CI one webhook','https://one.example.test/hook','ci-one-secret'),
                ($2,'CI two webhook','https://two.example.test/hook','ci-two-secret')
          RETURNING id,tenant_id`, [oneId, twoId]);
        await audit.query(`INSERT INTO webhook_deliveries(tenant_id,webhook_id,event_type,payload)
          VALUES($1,$2,'ci.test','{}'::jsonb),($3,$4,'ci.test','{}'::jsonb)`,
          [oneId, webhooks.rows[0].id, twoId, webhooks.rows[1].id]);
        await audit.query('SAVEPOINT vision_ci_webhook_fk');
        await assert.rejects(audit.query(`INSERT INTO webhook_deliveries(tenant_id,webhook_id,event_type,payload)
          VALUES($1,$2,'ci.cross','{}'::jsonb)`, [oneId, webhooks.rows[1].id]),
        error => error.code === '23503', 'Webhook delivery must reject another tenant endpoint');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_webhook_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_webhook_fk');
        await audit.query(`INSERT INTO auth_sessions(id,tenant_id,user_id,role,expires_at)
          VALUES('00000000-0000-4000-8000-000000000001',$1,$2,'guard',NOW()+INTERVAL '1 hour'),
                ('00000000-0000-4000-8000-000000000002',$3,$4,'guard',NOW()+INTERVAL '1 hour')`,
          [oneId, baselineUsers.rows[0].id, twoId, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO password_reset_tokens(tenant_id,user_id,token_hash,expires_at)
          VALUES($1,$2,'ci-reset-one',NOW()+INTERVAL '30 minutes'),
                ($3,$4,'ci-reset-two',NOW()+INTERVAL '30 minutes')`,
          [oneId, baselineUsers.rows[0].id, twoId, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO audit_logs(tenant_id,user_id,user_email,user_role,action,resource)
          VALUES($1,$2,'ci-one@example.test','guard','VIEW','ci-security'),
                ($3,$4,'ci-two@example.test','guard','VIEW','ci-security')`,
          [oneId, baselineUsers.rows[0].id, twoId, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO system_events(tenant_id,event_type,severity,message)
          VALUES($1,'ci_security','info','CI one security event'),
                ($2,'ci_security','info','CI two security event')`, [oneId, twoId]);
        const certifications = await audit.query(`INSERT INTO guard_certifications(
          tenant_id,user_id,cert_name,cert_number,issue_date,expiry_date)
          VALUES($1,$2,'CI Licence','CI-ONE','2026-01-01','2027-01-01'),
                ($3,$4,'CI Licence','CI-TWO','2026-01-01','2027-01-01')
          RETURNING id,tenant_id`,
          [oneId, baselineUsers.rows[0].id, twoId, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO email_deliveries(
          tenant_id,event_type,entity_type,idempotency_key,recipient_email,subject,status)
          VALUES($1,'ci.test','test','ci-email-one','ci-one@example.test','CI one','failed'),
                ($2,'ci.test','test','ci-email-two','ci-two@example.test','CI two','failed')`,
          [oneId, twoId]);
        await audit.query(`INSERT INTO service_credit_rules(tenant_id,contract_id)
          VALUES($1,$2),($3,$4)`, [oneId, contracts.rows[0].id, twoId, contracts.rows[1].id]);
        const creditRecommendations = await audit.query(`INSERT INTO service_credit_recommendations(
          tenant_id,contract_id,site_id,period_start,period_end)
          VALUES($1,$2,$3,'2026-09-01','2026-09-30'),
                ($4,$5,$6,'2026-09-01','2026-09-30') RETURNING id,tenant_id`,
          [oneId, contracts.rows[0].id, oneSite.rows[0].id,
            twoId, contracts.rows[1].id, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO service_credit_decisions(
          tenant_id,recommendation_id,previous_status,new_status,reason)
          VALUES($1,$2,'draft','approved','CI only'),
                ($3,$4,'draft','approved','CI only')`,
          [oneId, creditRecommendations.rows[0].id,
            twoId, creditRecommendations.rows[1].id]);
        await audit.query(`INSERT INTO visitor_records(tenant_id,site_id,full_name,purpose)
          VALUES($1,$2,'CI one visitor','CI only'),($3,$4,'CI two visitor','CI only')`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO proofscore_snapshots(tenant_id,site_id,period_start,period_end,score,grade)
          VALUES($1,$2,'2026-09-01','2026-09-30',90,'A'),
                ($3,$4,'2026-09-01','2026-09-30',90,'A')`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO assurance_improvement_actions(tenant_id,site_id,component_key,title)
          VALUES($1,$2,'ci','CI one action'),($3,$4,'ci','CI two action')`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO assurance_risk_forecasts(tenant_id,site_id,risk_score,
          breach_probability,risk_band)
          VALUES($1,$2,10,10,'low'),($3,$4,10,10,'low')`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO client_retention_snapshots(tenant_id,site_id,contract_id,
          horizon_days,risk_score,risk_band)
          VALUES($1,$2,$3,30,10,'low'),($4,$5,$6,30,10,'low')`,
          [oneId, oneSite.rows[0].id, contracts.rows[0].id,
            twoId, twoSite.rows[0].id, contracts.rows[1].id]);
        await audit.query(`INSERT INTO ai_assistant_audit(tenant_id,user_id,question_hash,status)
          VALUES($1,$2,'ci-one-hash','blocked'),($3,$4,'ci-two-hash','blocked')`,
          [oneId, baselineUsers.rows[0].id, twoId, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO ai_assistant_policies(tenant_id,enabled)
          VALUES($1,FALSE),($2,FALSE)`, [oneId, twoId]);
        await audit.query(`INSERT INTO site_guard_requirements(tenant_id,site_id,cert_name)
          VALUES($1,$2,'CI certificate'),($3,$4,'CI certificate')`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO coverage_autopilot_actions(tenant_id,shift_id,replacement_user_id,
          recommendation_score,approved_by)
          VALUES($1,101,$2,50,$2),($3,202,$4,50,$4)`,
          [oneId, baselineUsers.rows[0].id, twoId, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO pilot_operations_reviews(tenant_id,review_date,operational_status,
          platform_health,admin_workflow,guard_workflow,client_workflow,offline_sync,
          emergency_workflow,decision,summary)
          VALUES($1,'2026-09-17','green','pass','pass','pass','pass','pass','pass','continue','CI only'),
                ($2,'2026-09-17','green','pass','pass','pass','pass','pass','pass','continue','CI only')`,
          [oneId, twoId]);
        const incidents = await audit.query(`INSERT INTO incidents(tenant_id,site_id,user_id,description)
          VALUES($1,$2,$3,'CI one incident'),($4,$5,$6,'CI two incident') RETURNING id,tenant_id`,
          [oneId, oneSite.rows[0].id, baselineUsers.rows[0].id,
            twoId, twoSite.rows[0].id, baselineUsers.rows[1].id]);
        const crises = await audit.query(`INSERT INTO crisis_activations(tenant_id,incident_id,site_id,title,
          commander_user_id,activated_by_user_id,activation_reason)
          VALUES($1,$2,$3,'CI one crisis',$4,$4,'CI only'),
                ($5,$6,$7,'CI two crisis',$8,$8,'CI only') RETURNING id,tenant_id`,
          [oneId, incidents.rows[0].id, oneSite.rows[0].id, baselineUsers.rows[0].id,
            twoId, incidents.rows[1].id, twoSite.rows[0].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO crisis_roles(tenant_id,crisis_id,role_name,user_id,assigned_by_user_id)
          VALUES($1,$2,'commander',$3,$3),($4,$5,'commander',$6,$6)`,
          [oneId, crises.rows[0].id, baselineUsers.rows[0].id,
            twoId, crises.rows[1].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO crisis_actions(tenant_id,crisis_id,title,created_by_user_id)
          VALUES($1,$2,'CI one action',$3),($4,$5,'CI two action',$6)`,
          [oneId, crises.rows[0].id, baselineUsers.rows[0].id,
            twoId, crises.rows[1].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO crisis_updates(tenant_id,crisis_id,message,created_by_user_id)
          VALUES($1,$2,'CI one update',$3),($4,$5,'CI two update',$6)`,
          [oneId, crises.rows[0].id, baselineUsers.rows[0].id,
            twoId, crises.rows[1].id, baselineUsers.rows[1].id]);
        const materials = await audit.query(`INSERT INTO training_materials(tenant_id,title,material_type,content)
          VALUES($1,'CI one training','training','CI only'),($2,'CI two training','training','CI only')
          RETURNING id,tenant_id`, [oneId, twoId]);
        await audit.query(`INSERT INTO training_assignments(tenant_id,material_id,user_id)
          VALUES($1,$2,$3),($4,$5,$6)`,
          [oneId, materials.rows[0].id, baselineUsers.rows[0].id,
            twoId, materials.rows[1].id, baselineUsers.rows[1].id]);
        const assets = await audit.query(`INSERT INTO managed_assets(
          tenant_id,asset_type,name,asset_code,site_id)
          VALUES($1,'equipment','CI one asset','CI-ASSET-ONE',$2),
                ($3,'equipment','CI two asset','CI-ASSET-TWO',$4)
          RETURNING id,tenant_id`, [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO asset_custody(tenant_id,asset_id,user_id,issued_by_user_id,status)
          VALUES($1,$2,$3,$3,'issued'),($4,$5,$6,$6,'returned')`,
          [oneId, assets.rows[0].id, baselineUsers.rows[0].id,
            twoId, assets.rows[1].id, baselineUsers.rows[1].id]);
        const inspectionTemplates = await audit.query(`INSERT INTO inspection_templates(
          tenant_id,title,site_id,questions,created_by_user_id)
          VALUES($1,'CI one inspection',$2,'[{"text":"Check one"}]'::jsonb,$3),
                ($4,'CI two inspection',$5,'[{"text":"Check two"}]'::jsonb,$6)
          RETURNING id,tenant_id`,
          [oneId, oneSite.rows[0].id, baselineUsers.rows[0].id,
            twoId, twoSite.rows[0].id, baselineUsers.rows[1].id]);
        const inspectionRuns = await audit.query(`INSERT INTO inspection_runs(
          tenant_id,template_id,site_id,assigned_user_id,scheduled_for,created_by_user_id)
          VALUES($1,$2,$3,$4,NOW(),$4),($5,$6,$7,$8,NOW(),$8)
          RETURNING id,tenant_id`,
          [oneId, inspectionTemplates.rows[0].id, oneSite.rows[0].id, baselineUsers.rows[0].id,
            twoId, inspectionTemplates.rows[1].id, twoSite.rows[0].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO corrective_actions(tenant_id,inspection_run_id,title,assigned_user_id)
          VALUES($1,$2,'CI one correction',$3),($4,$5,'CI two correction',$6)`,
          [oneId, inspectionRuns.rows[0].id, baselineUsers.rows[0].id,
            twoId, inspectionRuns.rows[1].id, baselineUsers.rows[1].id]);
        await audit.query(`INSERT INTO site_training_requirements(tenant_id,site_id,material_id)
          VALUES($1,$2,$3),($4,$5,$6)`,
          [oneId, oneSite.rows[0].id, materials.rows[0].id,
            twoId, twoSite.rows[0].id, materials.rows[1].id]);
        const planId = (await audit.query(`INSERT INTO plan_catalog(code,name,version)
          VALUES('vision_ci_plan','Disposable CI plan','1') RETURNING id`)).rows[0].id;
        const featureId = (await audit.query(`INSERT INTO feature_catalog(code,name,category)
          VALUES('vision_ci_feature','Disposable CI feature','ci') RETURNING id`)).rows[0].id;
        const flagId = (await audit.query(`INSERT INTO feature_flags(code,description)
          VALUES('vision_ci_isolation','Disposable isolation fixture') RETURNING id`)).rows[0].id;
        await audit.query(`INSERT INTO tenant_subscriptions(tenant_id,plan_id)
          VALUES($1,$3),($2,$3)`, [oneId, twoId, planId]);
        await audit.query(`INSERT INTO tenant_entitlement_overrides(tenant_id,feature_id,enabled,reason)
          VALUES($1,$3,TRUE,'CI only'),($2,$3,FALSE,'CI only')`, [oneId, twoId, featureId]);
        await audit.query(`INSERT INTO usage_events(tenant_id,feature_id,quantity,idempotency_key)
          VALUES($1,$3,1,'vision-ci-one'),($2,$3,1,'vision-ci-two')`, [oneId, twoId, featureId]);
        await audit.query(`INSERT INTO usage_period_summaries(tenant_id,feature_id,period_start,period_end)
          VALUES($1,$3,'2026-09-01','2026-09-30'),($2,$3,'2026-09-01','2026-09-30')`,
          [oneId, twoId, featureId]);
        await audit.query(`INSERT INTO feature_flag_tenants(tenant_id,flag_id,enabled)
          VALUES($1,$3,TRUE),($2,$3,FALSE)`, [oneId, twoId, flagId]);
        await audit.query(`INSERT INTO billing_checkout_sessions(id,tenant_id,plan_code,billing_interval,currency,recurring_amount,status)
          VALUES('00000000-0000-4000-8000-000000000001',$1,'starter','month','EUR',1,'completed'),
                ('00000000-0000-4000-8000-000000000002',$2,'starter','month','EUR',1,'completed')`,
          [oneId, twoId]);
        await audit.query(`INSERT INTO billing_webhook_events(stripe_event_id,tenant_id,event_type)
          VALUES('vision-ci-one',$1,'ci.test'),('vision-ci-two',$2,'ci.test')`, [oneId, twoId]);
        await audit.query(`INSERT INTO patrol_routes(tenant_id,site_id,name) VALUES($1,$2,'CI Route'),($3,$4,'CI Route')`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO shifts(tenant_id,site_id,user_id,shift_date,start_time,end_time)
          VALUES($1,$2,100,'2026-09-16','08:00','16:00'),($3,$4,200,'2026-09-16','08:00','16:00')`,
        [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO system_events(tenant_id,event_type,message) VALUES($1,'vision_ci','one'),($2,'vision_ci','two')`, [oneId, twoId]);
        await audit.query(`INSERT INTO dispatch_jobs(tenant_id,reference_code,title,assigned_guard_id)
          VALUES($1,'VISION-CI-ONE','CI dispatch',100),($2,'VISION-CI-TWO','CI dispatch',200)`, [oneId, twoId]);
        await audit.query(`INSERT INTO sos_alerts(tenant_id,site_id,user_id)
          VALUES($1,$2,100),($3,$4,200)`, [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO guard_locations(tenant_id,user_id,site_id,latitude,longitude)
          VALUES($1,100,$2,35.9,14.5),($3,200,$4,35.8,14.4)`, [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO guard_location_history(tenant_id,user_id,site_id,latitude,longitude)
          VALUES($1,100,$2,35.9,14.5),($3,200,$4,35.8,14.4)`, [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO client_users(tenant_id,site_id,email,password_hash)
          VALUES($1,$2,'ci-one@example.test','ci-only'),($3,$4,'ci-two@example.test','ci-only')`,
          [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        const tickets = await audit.query(`INSERT INTO service_tickets(tenant_id,site_id,reference_code,subject,description)
          VALUES($1,$2,'CI-ONE-TICKET','CI One ticket','CI only'),($3,$4,'CI-TWO-TICKET','CI Two ticket','CI only')
          RETURNING id,tenant_id`, [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        await audit.query(`INSERT INTO service_ticket_comments(tenant_id,ticket_id,author_type,comment)
          VALUES($1,$2,'admin','CI one comment'),($3,$4,'admin','CI two comment')`,
          [oneId, tickets.rows[0].id, twoId, tickets.rows[1].id]);
        const conversations = await audit.query(`INSERT INTO team_conversations(tenant_id,title,kind)
          VALUES($1,'CI One Announcements','company'),($2,'CI Two Announcements','company') RETURNING id,tenant_id`, [oneId, twoId]);
        const messages = await audit.query(`INSERT INTO communication_notifications(tenant_id,title,message)
          VALUES($1,'CI One Notice','one'),($2,'CI Two Notice','two') RETURNING id,tenant_id`, [oneId, twoId]);
        const settings = await audit.query(`INSERT INTO lone_worker_settings(tenant_id,user_id,site_id)
          VALUES($1,100,$2),($3,200,$4) RETURNING id,tenant_id`, [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        const otherConversationId = conversations.rows.find(row => Number(row.tenant_id) === twoId).id;
        const otherNotificationId = messages.rows.find(row => Number(row.tenant_id) === twoId).id;
        const otherSettingId = settings.rows.find(row => Number(row.tenant_id) === twoId).id;
        await audit.query(`SET LOCAL ROLE ${TEST_ROLE}`);
        const visible = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM system_events WHERE event_type='vision_ci'`)).rows[0].count);
        const visibleRoutes = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM patrol_routes WHERE name='CI Route'`)).rows[0].count);
        const visibleShifts = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM shifts WHERE shift_date='2026-09-16'`)).rows[0].count);
        const visibleDispatch = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM dispatch_jobs WHERE title='CI dispatch'`)).rows[0].count);
        const visibleSos = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM sos_alerts`)).rows[0].count);
        const visibleLocations = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM guard_locations`)).rows[0].count);
        const visibleLocationHistory = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM guard_location_history`)).rows[0].count);
        const visibleClientUsers = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM client_users`)).rows[0].count);
        const visibleTickets = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM service_tickets`)).rows[0].count);
        const visibleTicketComments = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM service_ticket_comments`)).rows[0].count);
        const visibleHandovers = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM handover_logs`)).rows[0].count);
        const visibleTrainingMaterials = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM training_materials`)).rows[0].count);
        const visibleTrainingAssignments = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM training_assignments`)).rows[0].count);
        const visibleAssets = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM managed_assets`)).rows[0].count);
        const visibleAssetCustody = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM asset_custody`)).rows[0].count);
        const visibleInspectionTemplates = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM inspection_templates`)).rows[0].count);
        const visibleInspectionRuns = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM inspection_runs`)).rows[0].count);
        const visibleCorrectiveActions = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM corrective_actions`)).rows[0].count);
        const visibleReportSchedules = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM client_report_schedules`)).rows[0].count);
        const visibleReportRuns = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM client_report_runs`)).rows[0].count);
        const visibleRenewals = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM contract_renewals`)).rows[0].count);
        const visibleRenewalHistory = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM contract_renewal_history`)).rows[0].count);
        const visibleInvoices = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM invoices`)).rows[0].count);
        const visibleInvoiceLines = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM invoice_lines`)).rows[0].count);
        const visibleInvoicePayments = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM invoice_payments`)).rows[0].count);
        const visibleAuditLogs = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM audit_logs WHERE resource='ci-security'`)).rows[0].count);
        const visibleSecurityEvents = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM system_events WHERE event_type='ci_security'`)).rows[0].count);
        const visibleCertifications = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM guard_certifications WHERE cert_name='CI Licence'`)).rows[0].count);
        const visibleEmailDeliveries = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM email_deliveries WHERE event_type='ci.test'`)).rows[0].count);
        const baselineTables = ['sites', 'users', 'checkpoints', 'patrol_schedules',
          'patrol_logs', 'alert_log', 'guard_assignments', 'service_contracts'];
        const entitlementTables = ['tenant_subscriptions', 'tenant_entitlement_overrides',
          'usage_events', 'usage_period_summaries', 'feature_flag_tenants',
          'billing_checkout_sessions', 'billing_webhook_events', 'site_training_requirements'];
        const crisisTables = ['crisis_activations', 'crisis_roles', 'crisis_actions', 'crisis_updates'];
        const governanceTables = ['ai_assistant_audit', 'ai_assistant_policies',
          'site_guard_requirements', 'coverage_autopilot_actions', 'pilot_operations_reviews'];
        const assuranceTables = ['visitor_records', 'proofscore_snapshots',
          'assurance_improvement_actions', 'assurance_risk_forecasts', 'client_retention_snapshots'];
        const serviceCreditTables = ['service_credit_rules', 'service_credit_recommendations',
          'service_credit_decisions'];
        const identityTables = ['identity_assurance_settings', 'guard_trusted_devices',
          'identity_verification_events'];
        const intelligenceTables = ['operations_risk_snapshots', 'evidence_integrity_records',
          'tender_proposals', 'site_risk_twins', 'site_risk_scenarios'];
        const ownerSecurityTables = ['email_mfa_challenges', 'mfa_recovery_codes',
          'platform_load_tests'];
        const existingPolicyTables = [...baselineTables, ...entitlementTables,
          ...crisisTables, ...governanceTables, ...assuranceTables, ...serviceCreditTables,
          ...identityTables, ...intelligenceTables];
        const remainingBehaviorTables = preexistingProtected
          .filter(table => !existingPolicyTables.includes(table)).sort();
        assert.deepEqual(remainingBehaviorTables, ownerSecurityTables,
          'Pre-existing behavioral coverage inventory changed; review the remaining table set');
        const assertOwnerSecurityDenied = async context => {
          for (const table of ownerSecurityTables) {
            await audit.query('SAVEPOINT vision_ci_owner_security');
            await assert.rejects(audit.query(`SELECT tenant_id FROM public.${table} LIMIT 1`),
              error => error.code === '42501', `${table} must deny the restricted role ${context}`);
            await audit.query('ROLLBACK TO SAVEPOINT vision_ci_owner_security');
            await audit.query('RELEASE SAVEPOINT vision_ci_owner_security');
          }
        };
        const assertReviewedOwnerOnly = async context => {
          for (const table of [...INTEGRATION_OWNER_ONLY_TABLES, ...SECURITY_OWNER_ONLY_TABLES]) {
            await audit.query('SAVEPOINT vision_ci_integration_owner_only');
            await assert.rejects(audit.query(`SELECT tenant_id FROM public.${table} LIMIT 1`),
              error => error.code === '42501', `${table} must deny the restricted role ${context}`);
            await audit.query('ROLLBACK TO SAVEPOINT vision_ci_integration_owner_only');
            await audit.query('RELEASE SAVEPOINT vision_ci_integration_owner_only');
          }
        };
        await assertOwnerSecurityDenied('without tenant context');
        await assertReviewedOwnerOnly('without tenant context');
        const baselineCount = async table => Number((await audit.query(`SELECT COUNT(*)::int AS count
          FROM public.${table} WHERE tenant_id IN ($1,$2)`, [oneId, twoId])).rows[0].count);
        for (const table of existingPolicyTables) {
          assert.equal(await baselineCount(table), 0, `${table} must hide both tenants without context`);
        }
        assert.equal(await visible(), 0, 'Restricted role must see no rows without tenant context');
        assert.equal(await visibleRoutes(), 0, 'Restricted role must see no routes without tenant context');
        assert.equal(await visibleShifts(), 0, 'Restricted role must see no shifts without tenant context');
        assert.equal(await visibleDispatch(), 0, 'Restricted role must see no dispatches without tenant context');
        assert.equal(await visibleSos(), 0, 'Restricted role must see no SOS alerts without tenant context');
        assert.equal(await visibleLocations(), 0, 'Restricted role must see no live locations without tenant context');
        assert.equal(await visibleLocationHistory(), 0, 'Restricted role must see no location history without tenant context');
        assert.equal(await visibleClientUsers(), 0, 'Restricted role must see no client accounts without tenant context');
        assert.equal(await visibleTickets(), 0, 'Restricted role must see no tickets without tenant context');
        assert.equal(await visibleTicketComments(), 0, 'Restricted role must see no ticket comments without tenant context');
        assert.equal(await visibleHandovers(), 0, 'Restricted role must see no handovers without tenant context');
        assert.equal(await visibleTrainingMaterials(), 0, 'Restricted role must see no training materials without tenant context');
        assert.equal(await visibleTrainingAssignments(), 0, 'Restricted role must see no training assignments without tenant context');
        assert.equal(await visibleAssets(), 0, 'Restricted role must see no assets without tenant context');
        assert.equal(await visibleAssetCustody(), 0, 'Restricted role must see no asset custody without tenant context');
        assert.equal(await visibleInspectionTemplates(), 0, 'Restricted role must see no inspection templates without tenant context');
        assert.equal(await visibleInspectionRuns(), 0, 'Restricted role must see no inspection runs without tenant context');
        assert.equal(await visibleCorrectiveActions(), 0, 'Restricted role must see no corrective actions without tenant context');
        assert.equal(await visibleReportSchedules(), 0, 'Restricted role must see no report schedules without tenant context');
        assert.equal(await visibleReportRuns(), 0, 'Restricted role must see no report runs without tenant context');
        assert.equal(await visibleRenewals(), 0, 'Restricted role must see no contract renewals without tenant context');
        assert.equal(await visibleRenewalHistory(), 0, 'Restricted role must see no renewal history without tenant context');
        assert.equal(await visibleInvoices(), 0, 'Restricted role must see no invoices without tenant context');
        assert.equal(await visibleInvoiceLines(), 0, 'Restricted role must see no invoice lines without tenant context');
        assert.equal(await visibleInvoicePayments(), 0, 'Restricted role must see no invoice payments without tenant context');
        assert.equal(await visibleAuditLogs(), 0, 'Restricted role must see no audit logs without tenant context');
        assert.equal(await visibleSecurityEvents(), 0, 'Restricted role must see no security events without tenant context');
        assert.equal(await visibleCertifications(), 0, 'Restricted role must see no certifications without tenant context');
        assert.equal(await visibleEmailDeliveries(), 0, 'Restricted role must see no email deliveries without tenant context');
        await audit.query(`SELECT set_config('app.current_tenant',$1,true)`, [String(oneId)]);
        await assertOwnerSecurityDenied('even with tenant context');
        await assertReviewedOwnerOnly('even with tenant context');
        for (const table of existingPolicyTables) {
          assert.equal(await baselineCount(table), 1, `${table} must show only tenant one's row`);
          if (!['ai_assistant_audit', 'coverage_autopilot_actions', 'pilot_operations_reviews',
            'operations_risk_snapshots', 'evidence_integrity_records'].includes(table)) {
            assert.equal((await audit.query(`UPDATE public.${table} SET tenant_id=tenant_id
              WHERE tenant_id=$1`, [twoId])).rowCount, 0,
            `${table} must not update tenant two from tenant one's context`);
          }
        }
        await audit.query('SAVEPOINT vision_ci_governance_insert');
        await assert.rejects(audit.query(`INSERT INTO ai_assistant_audit(tenant_id,user_id,question_hash,status)
          VALUES($1,$2,'ci-cross-hash','blocked')`, [twoId, baselineUsers.rows[0].id]),
        error => error.code === '42501', 'AI audit must reject another tenant on insert');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_governance_insert');
        await audit.query('RELEASE SAVEPOINT vision_ci_governance_insert');
        await audit.query('SAVEPOINT vision_ci_existing_policy_write');
        await assert.rejects(audit.query(`UPDATE service_contracts SET tenant_id=$1
          WHERE tenant_id=$2`, [twoId, oneId]),
        error => error.code === '42501', 'Existing service-contract policy must reject cross-tenant reassignment');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_existing_policy_write');
        await audit.query('RELEASE SAVEPOINT vision_ci_existing_policy_write');
        assert.equal(await visible(), 1, 'Tenant one must see only its own row');
        assert.equal(await visibleRoutes(), 1, 'Tenant one must see only its own route');
        assert.equal(await visibleShifts(), 1, 'Tenant one must see only its own shift');
        assert.equal(await visibleDispatch(), 1, 'Tenant one must see only its own dispatch');
        assert.equal(await visibleSos(), 1, 'Tenant one must see only its own SOS alert');
        assert.equal(await visibleLocations(), 1, 'Tenant one must see only its own live location');
        assert.equal(await visibleLocationHistory(), 1, 'Tenant one must see only its own location history');
        assert.equal(await visibleClientUsers(), 1, 'Tenant one must see only its own client account');
        assert.equal(await visibleTickets(), 1, 'Tenant one must see only its own ticket');
        assert.equal(await visibleTicketComments(), 1, 'Tenant one must see only its own ticket comment');
        assert.equal(await visibleHandovers(), 1, 'Tenant one must see only its own handover');
        assert.equal(await visibleTrainingMaterials(), 1, 'Tenant one must see only its own training material');
        assert.equal(await visibleTrainingAssignments(), 1, 'Tenant one must see only its own training assignment');
        assert.equal(await visibleAssets(), 1, 'Tenant one must see only its own asset');
        assert.equal(await visibleAssetCustody(), 1, 'Tenant one must see only its own asset custody');
        assert.equal(await visibleInspectionTemplates(), 1, 'Tenant one must see only its own inspection template');
        assert.equal(await visibleInspectionRuns(), 1, 'Tenant one must see only its own inspection run');
        assert.equal(await visibleCorrectiveActions(), 1, 'Tenant one must see only its own corrective action');
        assert.equal(await visibleReportSchedules(), 1, 'Tenant one must see only its own report schedule');
        assert.equal(await visibleReportRuns(), 1, 'Tenant one must see only its own report run');
        assert.equal(await visibleRenewals(), 1, 'Tenant one must see only its own renewal');
        assert.equal(await visibleRenewalHistory(), 1, 'Tenant one must see only its own renewal history');
        assert.equal(await visibleInvoices(), 1, 'Tenant one must see only its own invoice');
        assert.equal(await visibleInvoiceLines(), 1, 'Tenant one must see only its own invoice line');
        assert.equal(await visibleInvoicePayments(), 1, 'Tenant one must see only its own invoice payment');
        assert.equal(await visibleAuditLogs(), 1, 'Tenant one must see only its own audit log');
        assert.equal(await visibleSecurityEvents(), 1, 'Tenant one must see only its own security event');
        assert.equal(await visibleCertifications(), 1, 'Tenant one must see only its own certification');
        assert.equal(await visibleEmailDeliveries(), 1, 'Tenant one must see only its own email delivery');
        assert.equal((await audit.query(`UPDATE guard_certifications SET cert_number='blocked' WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`UPDATE email_deliveries SET status='queued' WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`UPDATE email_deliveries SET status='queued' WHERE tenant_id=$1 AND event_type='ci.test'`, [oneId])).rowCount, 1);
        await audit.query('SAVEPOINT vision_ci_certification_user_fk');
        await assert.rejects(audit.query(`INSERT INTO guard_certifications(
          tenant_id,user_id,cert_name,cert_number,issue_date,expiry_date)
          VALUES($1,$2,'CI Cross','CI-CROSS','2026-01-01','2027-01-01')`,
        [oneId, baselineUsers.rows[1].id]),
        error => error.code === '23503', 'Certification must reject another tenant user');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_certification_user_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_certification_user_fk');
        assert.equal((await audit.query(`INSERT INTO system_events(tenant_id,event_type,severity,message)
          VALUES($1,'ci_security','info','CI one appended event')`, [oneId])).rowCount, 1);
        await audit.query('SAVEPOINT vision_ci_system_event_cross_tenant');
        await assert.rejects(audit.query(`INSERT INTO system_events(tenant_id,event_type,severity,message)
          VALUES($1,'ci_security','warning','blocked')`, [twoId]),
        error => error.code === '42501', 'System events must reject another tenant on insert');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_system_event_cross_tenant');
        await audit.query('RELEASE SAVEPOINT vision_ci_system_event_cross_tenant');
        assert.equal((await audit.query(`UPDATE invoices SET notes='blocked' WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        await audit.query('SAVEPOINT vision_ci_invoice_line_fk');
        await assert.rejects(audit.query(`INSERT INTO invoice_lines(tenant_id,invoice_id,description,quantity,unit_rate,line_total)
          VALUES($1,$2,'cross-tenant',1,1,1)`, [oneId, invoices.rows[1].id]),
        error => error.code === '23503', 'Invoice line must reject another tenant invoice');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_invoice_line_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_invoice_line_fk');
        await audit.query('SAVEPOINT vision_ci_invoice_payment_fk');
        await assert.rejects(audit.query(`INSERT INTO invoice_payments(tenant_id,invoice_id,amount,payment_date,recorded_by)
          VALUES($1,$2,1,'2026-09-29',$3)`, [oneId, invoices.rows[1].id, baselineUsers.rows[0].id]),
        error => error.code === '23503', 'Invoice payment must reject another tenant invoice');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_invoice_payment_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_invoice_payment_fk');
        assert.equal((await audit.query(`UPDATE contract_renewals SET status='negotiating' WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        await audit.query('SAVEPOINT vision_ci_renewal_fk');
        await assert.rejects(audit.query(`INSERT INTO contract_renewal_history(tenant_id,renewal_id,action,user_id)
          VALUES($1,$2,'cross-tenant',$3)`, [oneId, renewals.rows[1].id, baselineUsers.rows[0].id]),
        error => error.code === '23503', 'Renewal history must reject another tenant renewal');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_renewal_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_renewal_fk');
        assert.equal((await audit.query(`UPDATE client_report_schedules SET active=FALSE WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`UPDATE client_report_runs SET status='delivered' WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        await audit.query('SAVEPOINT vision_ci_report_fk');
        await assert.rejects(audit.query(`INSERT INTO client_report_runs(
          tenant_id,schedule_id,contract_id,period_start,period_end)
          VALUES($1,$2,$3,'2026-08-01','2026-08-31')`,
        [oneId, reportSchedules.rows[1].id, contracts.rows[0].id]),
        error => error.code === '23503', 'Client report run must reject another tenant schedule');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_report_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_report_fk');
        assert.equal((await audit.query(`INSERT INTO client_report_schedules(
          tenant_id,contract_id,recipient_email,frequency,next_run_date)
          VALUES($1,$2,'ci-one-extra@example.test','monthly','2026-11-01')`,
        [oneId, contracts.rows[0].id])).rowCount, 1);
        assert.equal((await audit.query(`UPDATE inspection_runs SET status='submitted' WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`UPDATE corrective_actions SET status='resolved' WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        await audit.query('SAVEPOINT vision_ci_quality_fk');
        await assert.rejects(audit.query(`INSERT INTO inspection_runs(tenant_id,template_id,site_id,assigned_user_id,scheduled_for)
          VALUES($1,$2,$3,$4,NOW())`, [oneId, inspectionTemplates.rows[1].id, oneSite.rows[0].id, baselineUsers.rows[0].id]),
        error => error.code === '23503', 'Inspection run must reject another tenant template');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_quality_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_quality_fk');
        assert.equal((await audit.query(`INSERT INTO inspection_templates(tenant_id,title,site_id,questions)
          VALUES($1,'CI one extra inspection',$2,'[{"text":"Check"}]'::jsonb)`,
        [oneId, oneSite.rows[0].id])).rowCount, 1);
        assert.equal((await audit.query(`UPDATE managed_assets SET condition='damaged'
          WHERE tenant_id=$1`, [twoId])).rowCount, 0,
        'Tenant one must not update tenant two assets');
        assert.equal((await audit.query(`UPDATE asset_custody SET status='acknowledged'
          WHERE tenant_id=$1`, [twoId])).rowCount, 0,
        'Tenant one must not update tenant two custody records');
        await audit.query('SAVEPOINT vision_ci_asset_fk');
        await assert.rejects(audit.query(`INSERT INTO asset_custody(tenant_id,asset_id,user_id)
          VALUES($1,$2,$3)`, [oneId, assets.rows[1].id, baselineUsers.rows[0].id]),
        error => error.code === '23503', 'Asset custody must reject another tenant asset');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_asset_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_asset_fk');
        await audit.query('SAVEPOINT vision_ci_asset_site_fk');
        await assert.rejects(audit.query(`INSERT INTO managed_assets(
          tenant_id,asset_type,name,asset_code,site_id)
          VALUES($1,'equipment','CI cross-tenant asset','CI-ASSET-CROSS',$2)`,
        [oneId, twoSite.rows[0].id]),
        error => error.code === '23503', 'Asset must reject another tenant site');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_asset_site_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_asset_site_fk');
        assert.equal((await audit.query(`INSERT INTO managed_assets(
          tenant_id,asset_type,name,asset_code,site_id)
          VALUES($1,'equipment','CI one extra asset','CI-ASSET-ONE-EXTRA',$2)`,
        [oneId, oneSite.rows[0].id])).rowCount, 1,
        'Tenant one must be able to create its own asset');
        assert.equal((await audit.query(`UPDATE training_assignments SET status='completed'
          WHERE tenant_id=$1`, [twoId])).rowCount, 0,
        'Tenant one must not update tenant two training assignments');
        await audit.query('SAVEPOINT vision_ci_training_fk');
        await assert.rejects(audit.query(`INSERT INTO training_assignments(tenant_id,material_id,user_id)
          VALUES($1,$2,$3)`, [oneId, materials.rows[1].id, baselineUsers.rows[0].id]),
        error => error.code === '23503', 'Training assignment must reject another tenant material');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_training_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_training_fk');
        await audit.query('SAVEPOINT vision_ci_training_site_fk');
        await assert.rejects(audit.query(`INSERT INTO training_materials(
          tenant_id,title,material_type,content,site_id)
          VALUES($1,'CI cross-tenant material','training','CI only',$2)`, [oneId, twoSite.rows[0].id]),
        error => error.code === '23503', 'Training material must reject another tenant site');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_training_site_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_training_site_fk');
        assert.equal((await audit.query(`INSERT INTO training_materials(
          tenant_id,title,material_type,content,site_id)
          VALUES($1,'CI one extra material','training','CI only',$2)`,
        [oneId, oneSite.rows[0].id])).rowCount, 1,
        'Tenant one must be able to create its own training material');
        assert.equal((await audit.query(`UPDATE handover_logs SET status='acknowledged'
          WHERE tenant_id=$1`, [twoId])).rowCount, 0,
        'Tenant one must not update tenant two handovers');
        await audit.query('SAVEPOINT vision_ci_handover_fk');
        await assert.rejects(audit.query(`INSERT INTO handover_logs(tenant_id,site_id,from_user_id,summary)
          VALUES($1,$2,$3,'CI cross-tenant handover')`,
        [oneId, twoSite.rows[0].id, baselineUsers.rows[0].id]),
        error => error.code === '23503', 'Handover must reject another tenant site');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_handover_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_handover_fk');
        assert.equal((await audit.query(`INSERT INTO handover_logs(tenant_id,site_id,from_user_id,summary)
          VALUES($1,$2,$3,'CI one extra handover')`,
        [oneId, oneSite.rows[0].id, baselineUsers.rows[0].id])).rowCount, 1,
        'Tenant one must be able to create its own handover');
        assert.equal((await audit.query(`UPDATE service_tickets SET status='closed' WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`UPDATE service_tickets SET status='in_progress' WHERE tenant_id=$1`, [oneId])).rowCount, 1);
        await audit.query(`RESET ROLE`);
        await audit.query('SAVEPOINT vision_ci_ticket_fk');
        await assert.rejects(audit.query(`INSERT INTO service_ticket_comments(tenant_id,ticket_id,author_type,comment)
          VALUES($1,$2,'admin','cross-tenant')`, [oneId, tickets.rows[1].id]),
          error => error.code === '23503', 'Ticket comment must reject a ticket from another tenant');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_ticket_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_ticket_fk');
        await audit.query(`SET LOCAL ROLE ${TEST_ROLE}`);
        assert.equal((await audit.query(`UPDATE client_users SET email='blocked@example.test' WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`DELETE FROM client_users WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        await audit.query('SAVEPOINT vision_ci_client_site_fk');
        await assert.rejects(audit.query(`INSERT INTO client_users(tenant_id,site_id,email,password_hash)
          VALUES($1,$2,'cross-site@example.test','ci-only')`, [oneId, twoSite.rows[0].id]),
          error => error.code === '23503', 'Client account must reject another tenant site');
        await audit.query('ROLLBACK TO SAVEPOINT vision_ci_client_site_fk');
        await audit.query('RELEASE SAVEPOINT vision_ci_client_site_fk');
        assert.equal((await audit.query(`INSERT INTO client_users(tenant_id,site_id,email,password_hash)
          VALUES($1,$2,'ci-one-extra@example.test','ci-only')`, [oneId, oneSite.rows[0].id])).rowCount, 1);
        assert.equal((await audit.query(`UPDATE guard_locations SET latitude=0 WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        for (const [label, sql, params] of [
          ['team message', `INSERT INTO team_messages(tenant_id,conversation_id,sender_user_id,sender_role,message)
            VALUES($1,$2,100,'admin','CI cross-tenant')`, [oneId, otherConversationId]],
          ['message receipt', `INSERT INTO communication_notification_receipts(tenant_id,notification_id,user_id)
            VALUES($1,$2,100)`, [oneId, otherNotificationId]],
          ['lone-worker check-in', `INSERT INTO lone_worker_checkins(tenant_id,setting_id,user_id,site_id)
            VALUES($1,$2,100,$3)`, [oneId, otherSettingId, oneSite.rows[0].id]],
          ['crisis update', `INSERT INTO crisis_updates(tenant_id,crisis_id,message,created_by_user_id)
            VALUES($1,$2,'CI cross-tenant',$3)`, [oneId, crises.rows[1].id, baselineUsers.rows[0].id]],
          ['client retention snapshot', `INSERT INTO client_retention_snapshots(tenant_id,site_id,contract_id,
            horizon_days,risk_score,risk_band) VALUES($1,$2,$3,30,10,'low')`,
            [oneId, oneSite.rows[0].id, contracts.rows[1].id]],
          ['identity verification event', `INSERT INTO identity_verification_events(
            tenant_id,user_id,device_id,action_type,resource_type,outcome,enforcement_mode)
            VALUES($1,$2,$3,'patrol_scan','patrol_log','verified','observe')`,
            [oneId, baselineUsers.rows[0].id, trustedDevices.rows[1].id]],
          ['risk scenario', `INSERT INTO site_risk_scenarios(
            tenant_id,site_id,name,baseline_score,projected_score,projected_band)
            VALUES($1,$2,'CI cross-tenant scenario',10,20,'low')`,
            [oneId, twoSite.rows[0].id]]
        ]) {
          await audit.query('SAVEPOINT vision_ci_cross_tenant_fk');
          await assert.rejects(audit.query(sql, params), error => error.code === '23503',
            `${label} must reject a parent belonging to another tenant`);
          await audit.query('ROLLBACK TO SAVEPOINT vision_ci_cross_tenant_fk');
          await audit.query('RELEASE SAVEPOINT vision_ci_cross_tenant_fk');
        }
        assert.equal((await audit.query(`UPDATE dispatch_jobs SET status='accepted' WHERE tenant_id=$1 AND title='CI dispatch'`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`UPDATE sos_alerts SET status='resolved' WHERE tenant_id=$1`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`UPDATE patrol_routes SET active=FALSE WHERE tenant_id=$1 AND name='CI Route'`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`DELETE FROM patrol_routes WHERE tenant_id=$1 AND name='CI Route'`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`UPDATE shifts SET notes='blocked' WHERE tenant_id=$1 AND shift_date='2026-09-16'`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`DELETE FROM shifts WHERE tenant_id=$1 AND shift_date='2026-09-16'`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`INSERT INTO patrol_routes(tenant_id,site_id,name) VALUES($1,$2,'CI One Extra') RETURNING id`,
          [oneId, oneSite.rows[0].id])).rowCount, 1);
        assert.equal((await audit.query(`INSERT INTO shifts(tenant_id,site_id,user_id,shift_date,start_time,end_time)
          VALUES($1,$2,101,'2026-09-17','08:00','16:00') RETURNING id`, [oneId, oneSite.rows[0].id])).rowCount, 1);
        for (const tenantId of [oneId, twoId]) {
          await audit.query('SAVEPOINT vision_ci_immutable_system_event');
          await assert.rejects(
            audit.query(`UPDATE system_events SET message='blocked' WHERE tenant_id=$1 AND event_type='vision_ci'`, [tenantId]),
            error => error.code === '42501',
            'Restricted tenant role must not modify immutable system events'
          );
          await audit.query('ROLLBACK TO SAVEPOINT vision_ci_immutable_system_event');
          await audit.query('RELEASE SAVEPOINT vision_ci_immutable_system_event');
        }
        await audit.query(`SELECT set_config('app.current_tenant',$1,true)`, [String(twoId)]);
        for (const table of existingPolicyTables) {
          assert.equal(await baselineCount(table), 1, `${table} must show only tenant two's row`);
        }
        assert.equal(await visible(), 1, 'Tenant two must see only its own row');
        assert.equal(await visibleRoutes(), 1, 'Tenant two must see only its own route');
        assert.equal(await visibleShifts(), 1, 'Tenant two must see only its own shift');
        assert.equal(await visibleDispatch(), 1, 'Tenant two must see only its own dispatch');
        assert.equal(await visibleSos(), 1, 'Tenant two must see only its own SOS alert');
        assert.equal(await visibleHandovers(), 1, 'Tenant two must see only its own handover');
        assert.equal(await visibleTrainingMaterials(), 1, 'Tenant two must see only its own training material');
        assert.equal(await visibleTrainingAssignments(), 1, 'Tenant two must see only its own training assignment');
        assert.equal(await visibleAssets(), 1, 'Tenant two must see only its own asset');
        assert.equal(await visibleAssetCustody(), 1, 'Tenant two must see only its own asset custody');
        assert.equal(await visibleInspectionTemplates(), 1, 'Tenant two must see only its own inspection template');
        assert.equal(await visibleInspectionRuns(), 1, 'Tenant two must see only its own inspection run');
        assert.equal(await visibleCorrectiveActions(), 1, 'Tenant two must see only its own corrective action');
        assert.equal(await visibleReportSchedules(), 1, 'Tenant two must see only its own report schedule');
        assert.equal(await visibleReportRuns(), 1, 'Tenant two must see only its own report run');
        assert.equal(await visibleRenewals(), 1, 'Tenant two must see only its own renewal');
        assert.equal(await visibleRenewalHistory(), 1, 'Tenant two must see only its own renewal history');
        assert.equal(await visibleInvoices(), 1, 'Tenant two must see only its own invoice');
        assert.equal(await visibleInvoiceLines(), 1, 'Tenant two must see only its own invoice line');
        assert.equal(await visibleInvoicePayments(), 1, 'Tenant two must see only its own invoice payment');
        assert.equal(await visibleAuditLogs(), 1, 'Tenant two must see only its own audit log');
        assert.equal(await visibleSecurityEvents(), 1, 'Tenant two must see only its own security event');
        assert.equal(await visibleCertifications(), 1, 'Tenant two must see only its own certification');
        assert.equal(await visibleEmailDeliveries(), 1, 'Tenant two must see only its own email delivery');
        assert.equal(await visibleLocations(), 1, 'Tenant two must see only its own live location');
        assert.equal(await visibleLocationHistory(), 1, 'Tenant two must see only its own location history');
        assert.equal(await visibleClientUsers(), 1, 'Tenant two must see only its own client account');
        console.log(`Existing RLS behavior passed for ${existingPolicyTables.length} tenant tables: no-context and cross-tenant reads/updates denied.`);
        console.log(`Owner/security RLS behavior passed for ${ownerSecurityTables.length} tenant tables: restricted-role access denied with and without tenant context.`);
        console.log(`Disposable RLS policy prototype passed: ${after.rows[0].protected}/${after.rows[0].total} tenant-keyed tables; cross-tenant route/shift access denied, own inserts allowed.`);
      } finally { await audit.query('ROLLBACK'); }
      // Only after baseline inventory and rollback, prepare the disposable DB
      // for one real HTTP write through the restricted tenant connection.
      // This committed fixture is dropped with TEST_DB at the end of this run.
      await audit.query('BEGIN');
      try {
        for (const table of ['guard_locations', 'guard_location_history']) {
          await audit.query(`ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY`);
          await audit.query(`CREATE POLICY vision_ci_location_tenant ON public.${table} TO ${TEST_ROLE}
            USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)`);
        }
        await audit.query(`GRANT SELECT,INSERT,UPDATE ON public.guard_locations TO ${TEST_ROLE}`);
        await audit.query(`GRANT SELECT,INSERT ON public.guard_location_history TO ${TEST_ROLE}`);
        await audit.query(`GRANT USAGE,SELECT ON SEQUENCE public.guard_locations_id_seq,public.guard_location_history_id_seq TO ${TEST_ROLE}`);
        await audit.query(`INSERT INTO guard_assignments(tenant_id,site_id,user_id)
          VALUES($1,$2,$3)`, [ownTenantId, site.rows[0].id, guard.rows[0].id]);
        await audit.query('COMMIT');
      } catch (error) { await audit.query('ROLLBACK'); throw error; }
      const assignedLocation = await fetch(`http://127.0.0.1:${port}/api/guard-locations`, {
        method: 'POST', headers: { Authorization: `Bearer ${guardToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: ownTenantId, site_id: site.rows[0].id, latitude: 35.9, longitude: 14.5 }),
        signal: AbortSignal.timeout(5000)
      });
      assert.equal(assignedLocation.status, 200, `Assigned guard location should succeed: ${await assignedLocation.text()}`);
      const locationRows = await audit.query(`SELECT
        (SELECT COUNT(*)::int FROM guard_locations WHERE tenant_id=$1 AND user_id=$2 AND site_id=$3) AS current_count,
        (SELECT COUNT(*)::int FROM guard_location_history WHERE tenant_id=$1 AND user_id=$2 AND site_id=$3) AS history_count`,
        [ownTenantId, guard.rows[0].id, site.rows[0].id]);
      assert.deepEqual(locationRows.rows[0], { current_count: 1, history_count: 1 });
      console.log('Assigned guard HTTP location write passed; one current and one history row recorded in disposable CI.');
      // Real ticket endpoints, with only their reviewed tables enabled for the
      // restricted connection. All fixtures are in this disposable CI database.
      await audit.query('BEGIN');
      try {
        for (const table of ['service_tickets', 'service_ticket_comments', 'client_users']) {
          await audit.query(`ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY`);
          await audit.query(`CREATE POLICY vision_ci_ticket_tenant ON public.${table} TO ${TEST_ROLE}
            USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)`);
        }
        await audit.query(`GRANT SELECT,UPDATE ON public.service_tickets TO ${TEST_ROLE}`);
        await audit.query(`GRANT SELECT ON public.service_ticket_comments,public.client_users TO ${TEST_ROLE}`);
        await audit.query('COMMIT');
      } catch (error) { await audit.query('ROLLBACK'); throw error; }
      const otherSite = await audit.query(`INSERT INTO sites(tenant_id,name)
        VALUES($1,'Other CI Site') RETURNING id`, [otherTenantId]);
      const otherAdmin = await audit.query(`INSERT INTO users(tenant_id,email,role)
        VALUES($1,'vision-http-other-admin@example.test','admin') RETURNING id`, [otherTenantId]);
      const clientAccount = await audit.query(`INSERT INTO client_users(tenant_id,site_id,email,password_hash)
        VALUES($1,$2,'vision-http-client@example.test','ci-only') RETURNING id`, [ownTenantId, site.rows[0].id]);
      const ownClientToken = jwt.sign({ tenant_id: ownTenantId, role: 'client',
        site_id: site.rows[0].id, client_user_id: clientAccount.rows[0].id },
      process.env.JWT_SECRET || 'patrolsync-dev-secret', { expiresIn: '5m' });
      const otherAdminToken = jwt.sign({ user_id: otherAdmin.rows[0].id,
        tenant_id: otherTenantId, role: 'admin' },
      process.env.JWT_SECRET || 'patrolsync-dev-secret', { expiresIn: '5m' });
      const tickets = await audit.query(`INSERT INTO service_tickets(tenant_id,site_id,reference_code,subject,description)
        VALUES($1,$2,'VISION-HTTP-OWN','Own CI ticket','CI only'),
              ($3,$4,'VISION-HTTP-OTHER','Other CI ticket','CI only') RETURNING id,tenant_id`,
      [ownTenantId, site.rows[0].id, otherTenantId, otherSite.rows[0].id]);
      const ownTicketId = tickets.rows.find(row => Number(row.tenant_id) === Number(ownTenantId)).id;
      const otherTicketId = tickets.rows.find(row => Number(row.tenant_id) === Number(otherTenantId)).id;
      const ticketRequest = (route, actorToken, method = 'GET', body) => fetch(`http://127.0.0.1:${port}${route}`, {
        method, headers: { Authorization: `Bearer ${actorToken}`,
          ...(body ? { 'Content-Type': 'application/json' } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(5000)
      });
      const clientTickets = await ticketRequest('/api/client-portal/service-tickets', ownClientToken);
      assert.equal(clientTickets.status, 200);
      assert.deepEqual((await clientTickets.json()).map(row => row.id), [ownTicketId]);
      const adminTickets = await ticketRequest('/api/service-tickets', token);
      assert.equal(adminTickets.status, 200);
      assert.deepEqual((await adminTickets.json()).map(row => row.id), [ownTicketId]);
      assert.equal((await ticketRequest(`/api/service-tickets/${otherTicketId}/comments`, ownClientToken)).status, 404);
      assert.equal((await ticketRequest(`/api/service-tickets/${ownTicketId}/comments`, guardToken)).status, 404);
      assert.equal((await ticketRequest(`/api/service-tickets/${ownTicketId}/comments`, guardToken, 'POST',
        { comment: 'Guard must not write' })).status, 404);
      assert.equal((await ticketRequest(`/api/service-tickets/${otherTicketId}`, token, 'PATCH',
        { status: 'closed' })).status, 404);
      assert.equal((await ticketRequest(`/api/service-tickets/${ownTicketId}`, otherAdminToken, 'PATCH',
        { status: 'closed' })).status, 404);
      const ownPatch = await ticketRequest(`/api/service-tickets/${ownTicketId}`, token, 'PATCH',
        { status: 'in_progress' });
      assert.equal(ownPatch.status, 200, `Own-company ticket update failed: ${await ownPatch.text()}`);
      const created = await ticketRequest('/api/client-portal/service-tickets', ownClientToken, 'POST',
        { subject: 'Client CI request', description: 'Disposable CI only' });
      assert.equal(created.status, 201, 'Own-site client ticket creation must succeed');
      const createdTicket = await created.json();
      assert.equal(Number(createdTicket.tenant_id), Number(ownTenantId));
      assert.equal(Number(createdTicket.site_id), Number(site.rows[0].id));
      assert.equal((await audit.query('SELECT COUNT(*)::int AS count FROM service_ticket_comments WHERE ticket_id=$1',
        [createdTicket.id])).rows[0].count, 1);
      console.log('Ticket HTTP isolation passed: client/admin own access, cross-tenant denial, guard denial, and own-site creation.');
      await runControlledRollback(target.href);
      await verifyControlledRollback(target.href);
      const rollbackLedger = await audit.query('SELECT version FROM patrolsync_schema_migrations ORDER BY version');
      assert.deepEqual(rollbackLedger.rows.map(row => row.version), ['0001_migration_foundation']);
      const rollbackState = await audit.query(`
        SELECT
          COUNT(*) FILTER (WHERE p.policyname='patrolsync_tenant_isolation')::int AS policies,
          COUNT(*) FILTER (WHERE c.relrowsecurity)::int AS rls_enabled,
          COUNT(*)::int AS total
        FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_policies p ON p.schemaname=n.nspname AND p.tablename=c.relname
        WHERE n.nspname='public' AND c.relname=ANY($1::text[])
      `, [EXPECTED_UNCOVERED_TABLES]);
      assert.equal(rollbackState.rows[0].policies, 0, 'Rollback must remove migration 0002 policies');
      assert.equal(rollbackState.rows[0].rls_enabled, rollbackState.rows[0].total,
        'Rollback must leave RLS enabled as a fail-closed boundary');
      const rollbackPrivileges = await audit.query(`SELECT COUNT(*)::int AS count
        FROM unnest($2::text[]) AS target(table_name)
        WHERE has_table_privilege($1,format('public.%I',target.table_name),'SELECT')
          OR has_table_privilege($1,format('public.%I',target.table_name),'INSERT')
          OR has_table_privilege($1,format('public.%I',target.table_name),'UPDATE')
          OR has_table_privilege($1,format('public.%I',target.table_name),'DELETE')`,
      [TEST_ROLE, EXPECTED_UNCOVERED_TABLES]);
      assert.equal(rollbackPrivileges.rows[0].count, 0,
        'Rollback must revoke all migrated restricted-role table privileges');
      const rollbackConstraints = await audit.query(`SELECT COUNT(*)::int AS count FROM pg_constraint
        WHERE conname LIKE 'patrolsync\\_%\\_tenant\\_%' ESCAPE '\\'`);
      assert.equal(rollbackConstraints.rows[0].count, 0, 'Rollback must remove migration 0003 constraints');
      console.log('Controlled rollback passed: ledger restored to foundation; migrated access revoked; RLS remains fail-closed.');
    } finally { await audit.end(); }
    console.log(`Disposable startup passed: HTTP /health 200, ${tables} public tables, Vision disabled.`);
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(3000)]);
      if (child.exitCode === null) child.kill('SIGKILL');
    }
    await admin.query(`DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE)`);
    await admin.query(`DROP ROLE IF EXISTS ${TEST_ROLE}`);
    await admin.end();
  }
}

main().catch(error => {
  console.error(error);
  if (process.env.GITHUB_ACTIONS === 'true') {
    const annotation = String(error?.stack || error)
      .replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
    console.error(`::error title=Disposable startup verification failed::${annotation}`);
  }
  process.exitCode = 1;
});
