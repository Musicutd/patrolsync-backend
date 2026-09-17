'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { registerVisionRoutes } = require('../vision-routes');

let hasExpress = true;
try { require.resolve('express'); } catch (_) { hasExpress = false; }

test('Vision HTTP routes fail closed across switch, tenancy, entitlement and roles', { skip: !hasExpress }, async t => {
  const express = require('express');
  const app = express();
  let globalOn = false;
  let schemaHealthy = true;
  const flags = new Map([[11, true], [22, false]]);
  const entitlements = new Map([[11, true], [22, true]]);
  const requireAuth = (req, res, next) => {
    if (!req.headers.authorization) return res.status(401).json({ error: 'No token provided' });
    req.auth = {
      tenant_id: Number(req.headers['x-test-tenant'] || 11),
      role: req.headers['x-test-role'] || 'admin',
      permissions: req.headers['x-test-permission'] === 'vision_view' ? ['vision_view'] : []
    };
    next();
  };
  const requireAdmin = (req, res, next) => {
    if (!['admin', 'staff'].includes(req.auth.role)) return res.status(403).json({ error: 'Admin access required' });
    next();
  };
  registerVisionRoutes(app, {
    requireAuth,
    requireAdmin,
    globalEnabled: () => globalOn,
    requireEntitlementSchema: async () => { if (!schemaHealthy) throw new Error('Schema unavailable'); },
    withTenant: async (tenantId, fn) => fn({ query: async (_sql, args) => ({ rows: [{ platform_flag: true, tenant_flag: Boolean(flags.get(Number(args[0]))), flag_tenant_id: flags.has(Number(args[0])) ? Number(args[0]) : null }] }) }),
    resolveTenantEntitlement: async tenantId => ({ tenant_id: tenantId, enabled: Boolean(entitlements.get(Number(tenantId))), subscription_status: 'active' })
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const get = (route, headers = {}) => fetch(base + route, { headers: { Authorization: 'Bearer test-only', ...headers } });

  assert.equal((await fetch(base + '/api/vision/status')).status, 401);
  let response = await get('/api/vision/status');
  assert.equal(response.status, 200);
  assert.equal((await response.json()).enabled, false);
  assert.equal((await get('/api/vision/capabilities')).status, 403);

  globalOn = true;
  response = await get('/api/vision/status');
  assert.equal((await response.json()).enabled, true);
  assert.equal((await get('/api/vision/capabilities')).status, 200);
  response = await get('/api/vision/status', { 'x-test-tenant': '22' });
  assert.equal((await response.json()).enabled, false);
  assert.equal((await get('/api/vision/capabilities', { 'x-test-tenant': '22' })).status, 403);

  entitlements.set(11, false);
  response = await get('/api/vision/status');
  assert.equal((await response.json()).enabled, false);
  entitlements.set(11, true);

  for (const role of ['guard', 'client']) assert.equal((await get('/api/vision/status', { 'x-test-role': role })).status, 403);
  assert.equal((await get('/api/vision/status', { 'x-test-role': 'staff' })).status, 403);
  response = await get('/api/vision/status', { 'x-test-role': 'staff', 'x-test-permission': 'vision_view' });
  assert.equal((await response.json()).enabled, true);

  schemaHealthy = false;
  assert.equal((await get('/api/vision/status')).status, 503);
});
