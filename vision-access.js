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

async function queryVisionFlag(client, tenantId) {
  const result = await client.query(
    `SELECT f.enabled_globally platform_flag, COALESCE(ft.enabled,FALSE) tenant_flag, ft.tenant_id flag_tenant_id
       FROM feature_flags f
       LEFT JOIN feature_flag_tenants ft ON ft.flag_id=f.id AND ft.tenant_id=$1
      WHERE f.code=$2`,
    [tenantId, VISION_FLAG]
  );
  return result.rows[0] || null;
}

function visionDecision({ globalEnabled, platformFlag, tenantFlag, entitlement, tenantId, flagTenantId, entitlementTenantId, role, permissions = [] }) {
  if (!globalEnabled || !platformFlag || !tenantFlag || !entitlement) return { enabled: false, reason: 'not_enabled' };
  if (!Number.isSafeInteger(Number(tenantId)) || Number(tenantId) < 1 || Number(flagTenantId) !== Number(tenantId) || Number(entitlementTenantId) !== Number(tenantId)) return { enabled: false, reason: 'not_enabled' };
  if (role === 'admin') return { enabled: true, reason: null };
  if (role === 'staff' && permissions.includes(VISION_PERMISSIONS.view)) return { enabled: true, reason: null };
  return { enabled: false, reason: 'permission_required' };
}

module.exports = { VISION_FLAG, VISION_FEATURE, VISION_PERMISSIONS, visionGlobalEnabled, queryVisionFlag, visionDecision };
