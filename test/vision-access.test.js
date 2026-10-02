'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { visionGlobalEnabled, visionDecision, VISION_PERMISSIONS } = require('../vision-access');

const allowed = { globalEnabled: true, platformFlag: true, tenantFlag: true, entitlement: true, tenantId: 9, flagTenantId: 9, entitlementTenantId: 9, role: 'admin' };

test('global switch fails closed', () => {
  assert.equal(visionGlobalEnabled(undefined), false);
  assert.equal(visionGlobalEnabled('false'), false);
  assert.equal(visionGlobalEnabled('TRUE'), false);
  assert.equal(visionGlobalEnabled('true'), true);
  assert.equal(visionDecision({ ...allowed, globalEnabled: false }).enabled, false);
});

test('platform flag, tenant flag and entitlement are all required', () => {
  for (const key of ['platformFlag', 'tenantFlag', 'entitlement']) {
    assert.equal(visionDecision({ ...allowed, [key]: false }).enabled, false, key);
  }
  assert.equal(visionDecision(allowed).enabled, true);
});

test('staff need explicit Vision view permission; guards and clients are denied', () => {
  assert.equal(visionDecision({ ...allowed, role: 'staff' }).enabled, false);
  assert.equal(visionDecision({ ...allowed, role: 'staff', permissions: [VISION_PERMISSIONS.view] }).enabled, true);
  assert.equal(visionDecision({ ...allowed, role: 'guard', permissions: [VISION_PERMISSIONS.view] }).enabled, false);
  assert.equal(visionDecision({ ...allowed, role: 'client', permissions: [VISION_PERMISSIONS.view] }).enabled, false);
});

test('tenant flag and entitlement must belong to the authenticated tenant', () => {
  assert.equal(visionDecision({ ...allowed, flagTenantId: 10 }).enabled, false);
  assert.equal(visionDecision({ ...allowed, entitlementTenantId: 10 }).enabled, false);
  assert.equal(visionDecision({ ...allowed, tenantId: undefined }).enabled, false);
});
