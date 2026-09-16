'use strict';

// Boots the real API against an empty, disposable CI database. Never point this at Render.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');
const { Client } = require('pg');

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

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
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
      await db.query(`GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO ${TEST_ROLE}`);
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
      const readable = privileges.rows.filter(row => row.can_select);
      const writable = privileges.rows.filter(row => row.can_insert && row.can_update && row.can_delete);
      console.log(`Restricted-role tenant-table grants: ${readable.length}/${privileges.rowCount} readable; ${writable.length}/${privileges.rowCount} full CRUD.`);
      console.log(`Tenant-keyed tables without restricted-role SELECT: ${privileges.rows.filter(row => !row.can_select).map(row => row.table_name).join(', ')}.`);
      // Prototype the missing-table policy in this disposable CI database only.
      // ROLLBACK ensures this test does not represent an applied migration.
      await audit.query('BEGIN');
      try {
        for (const tableName of uncovered) {
          const policies = await audit.query(`SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename=$1`, [tableName]);
          assert.equal(policies.rowCount, 0, `${tableName} has an existing policy requiring manual review`);
          const table = `"${tableName.replaceAll('"', '""')}"`;
          await audit.query(`ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY`);
          await audit.query(`CREATE POLICY vision_ci_tenant_isolation ON public.${table}
            TO ${TEST_ROLE}
            USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)`);
        }
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
          WHERE schemaname='public' AND policyname='vision_ci_tenant_isolation'
          ORDER BY tablename
        `);
        assert.deepEqual(addedPolicies.rows.map(row => row.tablename), EXPECTED_UNCOVERED_TABLES);
        assert.ok(addedPolicies.rows.every(row => row.roles.includes(TEST_ROLE)
          && row.qual?.includes('app.current_tenant')
          && row.with_check?.includes('app.current_tenant')),
        'Every added policy must be scoped to the restricted role and tenant context');
        assert.ok(uncovered.includes('system_events'), 'Representative previously unprotected table was not found');
        const first = await audit.query(`INSERT INTO tenants(name,slug) VALUES('CI One','vision-ci-one') RETURNING id`);
        const second = await audit.query(`INSERT INTO tenants(name,slug) VALUES('CI Two','vision-ci-two') RETURNING id`);
        const oneId = first.rows[0].id, twoId = second.rows[0].id;
        await audit.query(`INSERT INTO system_events(tenant_id,event_type,message) VALUES($1,'vision_ci','one'),($2,'vision_ci','two')`, [oneId, twoId]);
        await audit.query(`GRANT USAGE ON SCHEMA public TO ${TEST_ROLE}`);
        await audit.query(`GRANT SELECT,UPDATE ON public.system_events TO ${TEST_ROLE}`);
        await audit.query(`SET LOCAL ROLE ${TEST_ROLE}`);
        const visible = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM system_events WHERE event_type='vision_ci'`)).rows[0].count);
        assert.equal(await visible(), 0, 'Restricted role must see no rows without tenant context');
        await audit.query(`SELECT set_config('app.current_tenant',$1,true)`, [String(oneId)]);
        assert.equal(await visible(), 1, 'Tenant one must see only its own row');
        assert.equal((await audit.query(`UPDATE system_events SET message='blocked' WHERE tenant_id=$1 AND event_type='vision_ci'`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`UPDATE system_events SET message='allowed' WHERE tenant_id=$1 AND event_type='vision_ci'`, [oneId])).rowCount, 1);
        await audit.query(`SELECT set_config('app.current_tenant',$1,true)`, [String(twoId)]);
        assert.equal(await visible(), 1, 'Tenant two must see only its own row');
        console.log(`Disposable RLS policy prototype passed: ${after.rows[0].protected}/${after.rows[0].total} tenant-keyed tables; cross-tenant read/update denied.`);
      } finally { await audit.query('ROLLBACK'); }
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

main().catch(error => { console.error(error); process.exitCode = 1; });

