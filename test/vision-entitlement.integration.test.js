'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { queryVisionFlag } = require('../vision-access');
const { resolveTenantEntitlement } = require('../vision-entitlement');
const { registerVisionRoutes } = require('../vision-routes');

test('Vision HTTP access follows real tenant-scoped flag and entitlement queries', { skip: !process.env.VISION_TEST_DATABASE_URL }, async t => {
  const { Client } = require('pg');
  const express = require('express');
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
    for (const table of ['feature_flag_tenants','tenant_subscriptions','tenant_entitlement_overrides']) {
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
    registerVisionRoutes(app, {
      globalEnabled: () => globalOn,
      requireAuth: (req, res, next) => { req.auth = { tenant_id: Number(req.headers['x-test-tenant']), role: 'admin' }; next(); },
      requireAdmin: (_req, _res, next) => next(),
      requireEntitlementSchema: async () => {},
      withTenant,
      resolveTenantEntitlement
    });
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const status = async tenantId => {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/api/vision/status`, { headers: { 'x-test-tenant': String(tenantId) } });
      assert.equal(response.status, 200);
      return response.json();
    };

    // A rollout flag alone cannot grant a plan entitlement.
    assert.equal((await status(11)).enabled, false);
    await admin.query(`INSERT INTO vision_v01_entitlement.tenant_entitlement_overrides(tenant_id,feature_id,enabled,reason) VALUES(11,$1,TRUE,'test only')`, [feature]);
    assert.equal((await status(11)).enabled, true);
    assert.equal((await status(22)).enabled, false);
    await withTenant(22, async client => {
      assert.equal(await queryVisionFlag(client, 11).then(row => row.flag_tenant_id), null);
      assert.equal(await resolveTenantEntitlement(11, 'vision_access', client), null);
    });
    await admin.query(`UPDATE vision_v01_entitlement.tenant_entitlement_overrides SET expires_at=NOW()-INTERVAL '1 minute' WHERE tenant_id=11`);
    assert.equal((await status(11)).enabled, false);
    globalOn = false;
    assert.equal((await status(11)).enabled, false);
  } finally {
    if (readerConnected) await reader.end();
    await admin.query(`DROP SCHEMA IF EXISTS vision_v01_entitlement CASCADE`);
    await admin.query(`DROP ROLE IF EXISTS vision_v01_entitlement_reader`);
    await admin.end();
  }
});

