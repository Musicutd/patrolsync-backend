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
        // Parent IDs are globally unique, but the existing single-column FKs
        // do not prevent an own-tenant child from referencing another tenant's
        // parent. Prototype matching composite FKs before child-table grants.
        for (const [parent, child, childColumn] of [
          ['communication_notifications', 'communication_notification_receipts', 'notification_id'],
          ['team_conversations', 'team_messages', 'conversation_id'],
          ['team_conversations', 'team_conversation_reads', 'conversation_id'],
          ['lone_worker_settings', 'lone_worker_checkins', 'setting_id'],
          ['lone_worker_settings', 'lone_worker_alerts', 'setting_id']
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
        const reviewedGrants = { ...CORE_WORKFLOW_GRANTS, ...WORKFORCE_GRANTS,
          ...DISPATCH_SAFETY_GRANTS, ...COMMUNICATION_LONE_WORKER_GRANTS,
          ...LOCATION_GRANTS, ...CLIENT_ACCESS_GRANTS };
        for (const [table, operations] of Object.entries(reviewedGrants)) {
          assert.ok(EXPECTED_UNCOVERED_TABLES.includes(table), `${table} needs separate review before adding a grant`);
          await audit.query(`GRANT ${operations} ON public."${table}" TO ${TEST_ROLE}`);
          for (const operation of ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) {
            const granted = (await audit.query(`SELECT has_table_privilege($1,$2,$3) AS allowed`,
              [TEST_ROLE, `public.${table}`, operation])).rows[0].allowed;
            assert.equal(granted, operations.split(',').includes(operation),
              `${table} ${operation} differs from reviewed core-workflow scope`);
          }
        }
        console.log(`Disposable workflow grant prototype passed: ${Object.keys(reviewedGrants).length} tables; no blanket grant.`);
        assert.ok(uncovered.includes('system_events'), 'Representative previously unprotected table was not found');
        const first = await audit.query(`INSERT INTO tenants(name,slug) VALUES('CI One','vision-ci-one') RETURNING id`);
        const second = await audit.query(`INSERT INTO tenants(name,slug) VALUES('CI Two','vision-ci-two') RETURNING id`);
        const oneId = first.rows[0].id, twoId = second.rows[0].id;
        const oneSite = await audit.query(`INSERT INTO sites(tenant_id,name) VALUES($1,'CI One Site') RETURNING id`, [oneId]);
        const twoSite = await audit.query(`INSERT INTO sites(tenant_id,name) VALUES($1,'CI Two Site') RETURNING id`, [twoId]);
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
        const conversations = await audit.query(`INSERT INTO team_conversations(tenant_id,title,kind)
          VALUES($1,'CI One Announcements','company'),($2,'CI Two Announcements','company') RETURNING id,tenant_id`, [oneId, twoId]);
        const messages = await audit.query(`INSERT INTO communication_notifications(tenant_id,title,message)
          VALUES($1,'CI One Notice','one'),($2,'CI Two Notice','two') RETURNING id,tenant_id`, [oneId, twoId]);
        const settings = await audit.query(`INSERT INTO lone_worker_settings(tenant_id,user_id,site_id)
          VALUES($1,100,$2),($3,200,$4) RETURNING id,tenant_id`, [oneId, oneSite.rows[0].id, twoId, twoSite.rows[0].id]);
        const otherConversationId = conversations.rows.find(row => Number(row.tenant_id) === twoId).id;
        const otherNotificationId = messages.rows.find(row => Number(row.tenant_id) === twoId).id;
        const otherSettingId = settings.rows.find(row => Number(row.tenant_id) === twoId).id;
        await audit.query(`GRANT USAGE ON SCHEMA public TO ${TEST_ROLE}`);
        await audit.query(`GRANT SELECT,UPDATE ON public.system_events TO ${TEST_ROLE}`);
        await audit.query(`GRANT USAGE,SELECT ON SEQUENCE public.patrol_routes_id_seq TO ${TEST_ROLE}`);
        await audit.query(`GRANT USAGE,SELECT ON SEQUENCE public.shifts_id_seq TO ${TEST_ROLE}`);
        await audit.query(`GRANT USAGE,SELECT ON SEQUENCE public.team_messages_id_seq TO ${TEST_ROLE}`);
        await audit.query(`GRANT USAGE,SELECT ON SEQUENCE public.lone_worker_checkins_id_seq TO ${TEST_ROLE}`);
        await audit.query(`GRANT USAGE,SELECT ON SEQUENCE public.client_users_id_seq TO ${TEST_ROLE}`);
        await audit.query(`SET LOCAL ROLE ${TEST_ROLE}`);
        const visible = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM system_events WHERE event_type='vision_ci'`)).rows[0].count);
        const visibleRoutes = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM patrol_routes WHERE name='CI Route'`)).rows[0].count);
        const visibleShifts = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM shifts WHERE shift_date='2026-09-16'`)).rows[0].count);
        const visibleDispatch = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM dispatch_jobs WHERE title='CI dispatch'`)).rows[0].count);
        const visibleSos = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM sos_alerts`)).rows[0].count);
        const visibleLocations = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM guard_locations`)).rows[0].count);
        const visibleLocationHistory = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM guard_location_history`)).rows[0].count);
        const visibleClientUsers = async () => Number((await audit.query(`SELECT COUNT(*)::int AS count FROM client_users`)).rows[0].count);
        assert.equal(await visible(), 0, 'Restricted role must see no rows without tenant context');
        assert.equal(await visibleRoutes(), 0, 'Restricted role must see no routes without tenant context');
        assert.equal(await visibleShifts(), 0, 'Restricted role must see no shifts without tenant context');
        assert.equal(await visibleDispatch(), 0, 'Restricted role must see no dispatches without tenant context');
        assert.equal(await visibleSos(), 0, 'Restricted role must see no SOS alerts without tenant context');
        assert.equal(await visibleLocations(), 0, 'Restricted role must see no live locations without tenant context');
        assert.equal(await visibleLocationHistory(), 0, 'Restricted role must see no location history without tenant context');
        assert.equal(await visibleClientUsers(), 0, 'Restricted role must see no client accounts without tenant context');
        await audit.query(`SELECT set_config('app.current_tenant',$1,true)`, [String(oneId)]);
        assert.equal(await visible(), 1, 'Tenant one must see only its own row');
        assert.equal(await visibleRoutes(), 1, 'Tenant one must see only its own route');
        assert.equal(await visibleShifts(), 1, 'Tenant one must see only its own shift');
        assert.equal(await visibleDispatch(), 1, 'Tenant one must see only its own dispatch');
        assert.equal(await visibleSos(), 1, 'Tenant one must see only its own SOS alert');
        assert.equal(await visibleLocations(), 1, 'Tenant one must see only its own live location');
        assert.equal(await visibleLocationHistory(), 1, 'Tenant one must see only its own location history');
        assert.equal(await visibleClientUsers(), 1, 'Tenant one must see only its own client account');
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
            VALUES($1,$2,100,$3)`, [oneId, otherSettingId, oneSite.rows[0].id]]
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
        assert.equal((await audit.query(`UPDATE system_events SET message='blocked' WHERE tenant_id=$1 AND event_type='vision_ci'`, [twoId])).rowCount, 0);
        assert.equal((await audit.query(`UPDATE system_events SET message='allowed' WHERE tenant_id=$1 AND event_type='vision_ci'`, [oneId])).rowCount, 1);
        await audit.query(`SELECT set_config('app.current_tenant',$1,true)`, [String(twoId)]);
        assert.equal(await visible(), 1, 'Tenant two must see only its own row');
        assert.equal(await visibleRoutes(), 1, 'Tenant two must see only its own route');
        assert.equal(await visibleShifts(), 1, 'Tenant two must see only its own shift');
        assert.equal(await visibleDispatch(), 1, 'Tenant two must see only its own dispatch');
        assert.equal(await visibleSos(), 1, 'Tenant two must see only its own SOS alert');
        assert.equal(await visibleLocations(), 1, 'Tenant two must see only its own live location');
        assert.equal(await visibleLocationHistory(), 1, 'Tenant two must see only its own location history');
        assert.equal(await visibleClientUsers(), 1, 'Tenant two must see only its own client account');
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

