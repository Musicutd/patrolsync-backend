'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { CONFIRMATION, ROLE, reviewedPrivileges, validateTarget } = require('../scripts/verify-vision-staging-tenant-isolation');

const valid = {
  PATROLSYNC_STAGING_TENANT_AUDIT: CONFIRMATION,
  RENDER_SERVICE_ID: 'srv-dal8ne3l550s73ck8l40', RENDER_GIT_BRANCH: 'feature/vision-v01-scaffold',
  VISION_ENABLED: 'false', STAGING_DATABASE_OWNER: 'patrolsyncvisionstagingdb_abc123_user',
  SYSTEM_DATABASE_URL: 'postgresql://patrolsyncvisionstagingdb_abc123_user:secret@dpg-dal8lpbm8hqs73f9nsk0-a.internal/patrolsync_vision_staging_db',
  STAGING_TENANT_ROLE_PASSWORD: 'x'.repeat(32)
};

test('tenant isolation audit is complete and staging-only', () => {
  assert.equal(ROLE, 'patrolsync_vision_staging_tenant');
  const privileges = reviewedPrivileges();
  assert.equal(privileges.size, 56);
  assert.ok([...privileges.values()].some(operations => operations.has('SELECT')));
  assert.doesNotThrow(() => validateTarget(valid));
  assert.throws(() => validateTarget({ ...valid, PATROLSYNC_STAGING_TENANT_AUDIT: 'yes' }), /confirmation/);
});
