'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { CONFIRMATION, TENANT_ROLE, validateTarget } = require('../scripts/migrate-vision-staging');

const valid = {
  PATROLSYNC_STAGING_MIGRATE: CONFIRMATION,
  RENDER_SERVICE_ID: 'srv-dal8ne3l550s73ck8l40',
  RENDER_GIT_BRANCH: 'feature/vision-v01-scaffold',
  VISION_ENABLED: 'false',
  SYSTEM_DATABASE_URL: 'postgresql://patrolsyncvisionstagingdb_abc123_user:secret@dpg-dal8lpbm8hqs73f9nsk0-a.internal/patrolsync_vision_staging_db',
  STAGING_DATABASE_OWNER: 'patrolsyncvisionstagingdb_abc123_user',
  STAGING_TENANT_ROLE_PASSWORD: 'x'.repeat(32)
};

test('controlled staging migrations require the exact one-time trigger and target', () => {
  assert.equal(TENANT_ROLE, 'patrolsync_vision_staging_tenant');
  assert.doesNotThrow(() => validateTarget(valid));
  assert.throws(() => validateTarget({ ...valid, PATROLSYNC_STAGING_MIGRATE: 'yes' }), /confirmation/);
  assert.throws(() => validateTarget({ ...valid, VISION_ENABLED: 'true' }), /disabled Vision/);
  assert.throws(() => validateTarget({ ...valid, SYSTEM_DATABASE_URL: valid.SYSTEM_DATABASE_URL.replace('staging', 'production') }));
});
