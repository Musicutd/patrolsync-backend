'use strict';

async function resolveTenantEntitlement(tenantId, featureCode, client) {
  const result = await client.query(`SELECT ts.tenant_id,ts.status subscription_status,p.code plan_code,p.name plan_name,p.version plan_version,f.code feature_code,f.unit,COALESCE(o.enabled,pf.enabled,FALSE) enabled,COALESCE(o.included_quantity,pf.included_quantity) included_quantity,pf.soft_limit,COALESCE(o.included_quantity,pf.hard_limit) hard_limit,o.reason override_reason,o.expires_at override_expires_at FROM tenant_subscriptions ts JOIN plan_catalog p ON p.id=ts.plan_id JOIN feature_catalog f ON f.code=$2 LEFT JOIN plan_features pf ON pf.plan_id=ts.plan_id AND pf.feature_id=f.id LEFT JOIN tenant_entitlement_overrides o ON o.tenant_id=ts.tenant_id AND o.feature_id=f.id AND(o.expires_at IS NULL OR o.expires_at>NOW()) WHERE ts.tenant_id=$1`, [tenantId, featureCode]);
  return result.rows[0] || null;
}

module.exports = { resolveTenantEntitlement };

