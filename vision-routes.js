'use strict';

const { VISION_FEATURE, VISION_PERMISSIONS, visionGlobalEnabled, queryVisionFlag, visionDecision } = require('./vision-access');

function registerVisionRoutes(app, { requireAuth, requireAdmin, requireEntitlementSchema, withTenant, resolveTenantEntitlement, globalEnabled = visionGlobalEnabled }) {
  async function resolveVisionAccess(req) {
    if (!globalEnabled()) return { enabled: false, reason: 'not_enabled' };
    await requireEntitlementSchema();
    return withTenant(req.auth.tenant_id, async client => {
      const flag = await queryVisionFlag(client, req.auth.tenant_id);
      const entitlement = await resolveTenantEntitlement(req.auth.tenant_id, VISION_FEATURE, client);
      return visionDecision({
        globalEnabled: true,
        platformFlag: Boolean(flag?.platform_flag),
        tenantFlag: Boolean(flag?.tenant_flag),
        entitlement: Boolean(entitlement?.enabled && ['active', 'trialing'].includes(entitlement.subscription_status)),
        tenantId: req.auth.tenant_id,
        flagTenantId: flag?.flag_tenant_id,
        entitlementTenantId: entitlement?.tenant_id,
        role: req.auth.role,
        permissions: req.auth.permissions || []
      });
    });
  }

  function requireVisionPermission(level) {
    const permission = VISION_PERMISSIONS[level];
    if (!permission) throw new Error('Invalid Vision permission');
    return (req, res, next) => {
      if (req.auth?.role === 'admin') return next();
      if (req.auth?.role !== 'staff' || !req.auth.permissions?.includes(permission)) return res.status(403).json({ error: 'Vision permission required' });
      next();
    };
  }

  async function requireVisionAccess(req, res, next) {
    try {
      const access = await resolveVisionAccess(req);
      if (!access.enabled) return res.status(403).json({ error: 'Vision is not available' });
      next();
    } catch (_) {
      res.status(503).json({ error: 'Vision access is temporarily unavailable' });
    }
  }

  app.get('/api/vision/status', requireAuth, requireAdmin, requireVisionPermission('view'), async (req, res) => {
    try {
      const access = await resolveVisionAccess(req);
      res.json({ enabled: access.enabled, reason: access.reason, capabilities: access.enabled ? { overview: true, cameras: false, events: false, occupancy: false } : null });
    } catch (_) {
      res.status(503).json({ error: 'Vision status is temporarily unavailable' });
    }
  });
  app.get('/api/vision/capabilities', requireAuth, requireAdmin, requireVisionPermission('view'), requireVisionAccess, (req, res) => {
    res.json({ overview: true, cameras: false, events: false, occupancy: false });
  });
}

module.exports = { registerVisionRoutes };
