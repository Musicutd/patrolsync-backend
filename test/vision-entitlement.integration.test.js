'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { queryVisionFlag } = require('../vision-access');
const { resolveTenantEntitlement } = require('../vision-entitlement');
const { registerVisionRoutes } = require('../vision-routes');

test('Vision HTTP access follows real tenant-scoped flag and entitlement queries', { skip: !process.env.VISION_TEST_DATABASE_URL }, async t => {
  const { Client } = require('pg');
  const express = require('express');
  const jwt = require('jsonwebtoken');
  const bcrypt = require('bcryptjs');
  const crypto = require('node:crypto');
  const admin = new Client({ connectionString: process.env.VISION_TEST_DATABASE_URL });
  const url = new URL(process.env.VISION_TEST_DATABASE_URL);
  const reader = new Client({ host: url.hostname, port: Number(url.port || 5432), database: url.pathname.slice(1), user: 'vision_v01_entitlement_reader', password: 'vision_v01_test_only' });
  let readerConnected = false;
  await admin.connect();
  try {
    await admin.query(`CREATE ROLE vision_v01_entitlement_reader LOGIN PASSWORD 'vision_v01_test_only'`);
    await admin.query(`CREATE SCHEMA vision_v01_entitlement`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.feature_flags(id BIGSERIAL PRIMARY KEY,code TEXT UNIQUE NOT NULL,enabled_globally BOOLEAN NOT NULL)`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.feature_flag_tenants(flag_id BIGINT NOT NULL,tenant_id INTEGER NOT NULL,enabled BOOLEAN NOT NULL)`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.plan_catalog(id BIGSERIAL PRIMARY KEY,code TEXT NOT NULL,name TEXT NOT NULL,version TEXT NOT NULL)`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.feature_catalog(id BIGSERIAL PRIMARY KEY,code TEXT UNIQUE NOT NULL,unit TEXT NOT NULL)`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.plan_features(plan_id BIGINT NOT NULL,feature_id BIGINT NOT NULL,enabled BOOLEAN NOT NULL, included_quantity NUMERIC,soft_limit NUMERIC,hard_limit NUMERIC)`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.tenant_subscriptions(tenant_id INTEGER NOT NULL,plan_id BIGINT NOT NULL,status TEXT NOT NULL)`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.tenant_entitlement_overrides(tenant_id INTEGER NOT NULL,feature_id BIGINT NOT NULL,enabled BOOLEAN,included_quantity NUMERIC,reason TEXT,expires_at TIMESTAMPTZ)`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.tenants(id INTEGER PRIMARY KEY,account_active BOOLEAN NOT NULL)`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.users(id INTEGER PRIMARY KEY,tenant_id INTEGER NOT NULL,role TEXT NOT NULL,email TEXT NOT NULL,password_hash TEXT,permissions TEXT[] NOT NULL DEFAULT '{}',account_active BOOLEAN NOT NULL,email_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,password_changed_at TIMESTAMPTZ)`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.auth_sessions(id UUID PRIMARY KEY,tenant_id INTEGER NOT NULL,user_id INTEGER NOT NULL,role TEXT NOT NULL,ip_address TEXT,user_agent TEXT,revoked_at TIMESTAMPTZ,expires_at TIMESTAMPTZ NOT NULL,last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
    await admin.query(`CREATE TABLE vision_v01_entitlement.system_events(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,event_type TEXT NOT NULL,severity TEXT NOT NULL,message TEXT NOT NULL,details JSONB NOT NULL,request_id TEXT)`);
    for (const table of ['feature_flag_tenants','tenant_subscriptions','tenant_entitlement_overrides','users']) {
      await admin.query(`ALTER TABLE vision_v01_entitlement.${table} ENABLE ROW LEVEL SECURITY`);
      await admin.query(`CREATE POLICY tenant_isolation ON vision_v01_entitlement.${table} USING (tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
    }
    await admin.query(`GRANT USAGE ON SCHEMA vision_v01_entitlement TO vision_v01_entitlement_reader`);
    await admin.query(`GRANT SELECT ON ALL TABLES IN SCHEMA vision_v01_entitlement TO vision_v01_entitlement_reader`);
    const flag = (await admin.query(`INSERT INTO vision_v01_entitlement.feature_flags(code,enabled_globally) VALUES('vision_rollout',TRUE) RETURNING id`)).rows[0].id;
    const plan = (await admin.query(`INSERT INTO vision_v01_entitlement.plan_catalog(code,name,version) VALUES('starter','Starter','test') RETURNING id`)).rows[0].id;
    const feature = (await admin.query(`INSERT INTO vision_v01_entitlement.feature_catalog(code,unit) VALUES('vision_access','boolean') RETURNING id`)).rows[0].id;
    await admin.query(`INSERT INTO vision_v01_entitlement.feature_flag_tenants(flag_id,tenant_id,enabled) VALUES($1,11,TRUE),($1,22,TRUE)`, [flag]);
    await admin.query(`INSERT INTO vision_v01_entitlement.tenant_subscriptions(tenant_id,plan_id,status) VALUES(11,$1,'active'),(22,$1,'active')`, [plan]);
    await admin.query(`INSERT INTO vision_v01_entitlement.tenants(id,account_active) VALUES(11,TRUE),(22,TRUE)`);
    const passwordHash = await bcrypt.hash('vision-test-password-only', 4);
    await admin.query(`INSERT INTO vision_v01_entitlement.users(id,tenant_id,role,email,password_hash,permissions,account_active) VALUES(101,11,'admin','admin@test.invalid',$1,'{}',TRUE),(102,11,'staff','staff@test.invalid',$1,'{}',TRUE),(103,11,'guard','guard@test.invalid',$1,'{}',TRUE),(201,22,'admin','other@test.invalid',$1,'{}',TRUE)`, [passwordHash]);
    await admin.query(`SET search_path TO vision_v01_entitlement`);
    await reader.connect();
    readerConnected = true;
    await reader.query(`SET search_path TO vision_v01_entitlement`);
    let globalOn = true;
    const withTenant = async (tenantId, fn) => {
      await reader.query(`SELECT set_config('app.current_tenant',$1,FALSE)`, [String(tenantId)]);
      try { return await fn(reader); }
      finally { await reader.query(`RESET app.current_tenant`); }
    };
    const app = express();
    app.use(express.json());
    // Load the unchanged middleware declarations from index.js without booting
    // the full production server or its unrelated schema/background jobs.
    const source = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');
    const authStart = source.indexOf('async function requireAuth(req, res, next) {');
    const authEnd = source.indexOf('\nfunction permissionForPath(', authStart);
    const adminEnd = source.indexOf('\nfunction requireOwnerAdmin(', authEnd);
    assert.ok(authStart >= 0 && authEnd > authStart && adminEnd > authEnd);
    const { requireAuth, requireAdmin } = vm.runInNewContext(
      `${source.slice(authStart, adminEnd)}\n({ requireAuth, requireAdmin })`,
      { pool: admin, jwt, JWT_SECRET: 'vision-test-secret', VISION_PERMISSIONS: { view: 'vision_view' } }
    );
    const trackedStart = source.indexOf('async function createTrackedToken(user,req){');
    const trackedEnd = source.indexOf('\nfunction mfaDigest(', trackedStart);
    const loginStart = source.indexOf("app.post('/api/auth/login', async (req, res) => {");
    const loginEnd = source.indexOf("\napp.post('/api/auth/mfa/verify'", loginStart);
    assert.ok(trackedStart >= 0 && trackedEnd > trackedStart && loginStart >= 0 && loginEnd > loginStart);
    const loginContext = {
      app, pool: admin, withTenant, jwt, bcrypt, crypto,
      JWT_SECRET: 'vision-test-secret',
      requestIp: () => '127.0.0.1',
      process: { env: {} },
      EMAIL_FROM_ADDRESS: '',
      createEmailMfaChallenge: () => { throw new Error('MFA is outside this login test'); }
    };
    vm.runInNewContext(`${source.slice(trackedStart, trackedEnd)}\n${source.slice(loginStart, loginEnd)}`, loginContext);
    registerVisionRoutes(app, {
      globalEnabled: () => globalOn,
      requireAuth,
      requireAdmin,
      requireEntitlementSchema: async () => {},
      withTenant,
      resolveTenantEntitlement
    });
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const tokenFor = (tenantId, userId, role, withSession = false) => jwt.sign({ tenant_id: tenantId, user_id: userId, role, ...(withSession ? { session_id: sessionId } : {}) }, 'vision-test-secret', { expiresIn: '1h' });
    const login = async (tenantId, email, password = 'vision-test-password-only') => fetch(`http://127.0.0.1:${server.address().port}/api/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenant_id: tenantId, email, password })
    });
    assert.equal((await login(11, 'admin@test.invalid', 'wrong-password')).status, 401);
    const loginResponse = await login(11, 'admin@test.invalid');
    assert.equal(loginResponse.status, 200);
    const loginBody = await loginResponse.json();
    const adminToken = loginBody.token;
    const sessionId = jwt.verify(adminToken, 'vision-test-secret').session_id;
    assert.equal(loginBody.tenant_id, 11);
    assert.ok(sessionId);
    const statusResponse = token => fetch(`http://127.0.0.1:${server.address().port}/api/vision/status`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    const status = async token => {
      const response = await statusResponse(token);
      assert.equal(response.status, 200);
      return response.json();
    };

    assert.equal((await statusResponse()).status, 401);
    assert.equal((await statusResponse('invalid-token')).status, 401);
    // A rollout flag alone cannot grant a plan entitlement.
    assert.equal((await status(adminToken)).enabled, false);
    await admin.query(`INSERT INTO vision_v01_entitlement.tenant_entitlement_overrides(tenant_id,feature_id,enabled,reason) VALUES(11,$1,TRUE,'test only')`, [feature]);
    assert.equal((await status(adminToken)).enabled, true);
    assert.equal((await status(tokenFor(22, 201, 'admin'))).enabled, false);
    assert.equal((await statusResponse(tokenFor(11, 103, 'guard'))).status, 403);
    assert.equal((await statusResponse(tokenFor(11, 102, 'staff'))).status, 403);
    await admin.query(`UPDATE vision_v01_entitlement.users SET permissions=ARRAY['vision_view'] WHERE id=102`);
    assert.equal((await status(tokenFor(11, 102, 'staff'))).enabled, true);
    await admin.query(`UPDATE vision_v01_entitlement.users SET account_active=FALSE WHERE id=102`);
    assert.equal((await statusResponse(tokenFor(11, 102, 'staff'))).status, 401);
    await admin.query(`UPDATE vision_v01_entitlement.auth_sessions SET revoked_at=NOW() WHERE id=$1`, [sessionId]);
    assert.equal((await statusResponse(adminToken)).status, 401);
    await admin.query(`UPDATE vision_v01_entitlement.auth_sessions SET revoked_at=NULL WHERE id=$1`, [sessionId]);
    await withTenant(22, async client => {
      assert.equal(await queryVisionFlag(client, 11).then(row => row.flag_tenant_id), null);
      assert.equal(await resolveTenantEntitlement(11, 'vision_access', client), null);
    });
    await admin.query(`UPDATE vision_v01_entitlement.tenant_entitlement_overrides SET expires_at=NOW()-INTERVAL '1 minute' WHERE tenant_id=11`);
    assert.equal((await status(adminToken)).enabled, false);
    globalOn = false;
    assert.equal((await status(adminToken)).enabled, false);
  } finally {
    if (readerConnected) await reader.end();
    await admin.query(`DROP SCHEMA IF EXISTS vision_v01_entitlement CASCADE`);
    await admin.query(`DROP ROLE IF EXISTS vision_v01_entitlement_reader`);
    await admin.end();
  }
});

