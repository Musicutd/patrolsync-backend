'use strict';

const VISION_FLAG = 'vision_rollout';
const VISION_FEATURE = 'vision_access';
const VISION_PERMISSIONS = Object.freeze({
  view: 'vision_view',
  operate: 'vision_operate',
  configure: 'vision_configure',
  billing: 'vision_billing'
});

function visionGlobalEnabled(value = process.env.VISION_ENABLED) {
  return value === 'true';
}

function visionDecision({ globalEnabled, platformFlag, tenantFlag, entitlement, tenantId, flagTenantId, entitlementTenantId, role, permissions = [] }) {
  if (!globalEnabled || !platformFlag || !tenantFlag || !entitlement) return { enabled: false, reason: 'not_enabled' };
  if (!Number.isSafeInteger(Number(tenantId)) || Number(tenantId) < 1 || Number(flagTenantId) !== Number(tenantId) || Number(entitlementTenantId) !== Number(tenantId)) return { enabled: false, reason: 'not_enabled' };
  if (role === 'admin') return { enabled: true, reason: null };
  if (role === 'staff' && permissions.includes(VISION_PERMISSIONS.view)) return { enabled: true, reason: null };
  return { enabled: false, reason: 'permission_required' };
}

module.exports = { VISION_FLAG, VISION_FEATURE, VISION_PERMISSIONS, visionGlobalEnabled, visionDecision };
