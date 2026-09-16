'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { validateTarget, validateStagingConnection } = require('../scripts/bootstrap-vision-staging');

const valid = {
  PATROLSYNC_STAGING_BOOTSTRAP: 'BOOTSTRAP_EMPTY_VISION_DB',
  RENDER_SERVICE_ID: 'srv-dal8ne3l550s73ck8l40',
  RENDER_GIT_BRANCH: 'feature/vision-v01-scaffold',
  VISION_ENABLED: 'false',
  SYSTEM_DATABASE_URL: 'postgresql://patrolsync_vision_staging_db_user:owner-secret@dpg-dal8lpbm8hqs73f9nsk0-a.frankfurt-postgres.render.com/patrolsync_vision_staging_db',
  STAGING_TENANT_ROLE_PASSWORD: 'staging-role-password-longer-than-32-chars'
};

test('only the approved staging service and database can bootstrap', () => {
  assert.equal(validateTarget(valid).rolePassword, valid.STAGING_TENANT_ROLE_PASSWORD);
  for (const [key, value] of [
    ['RENDER_SERVICE_ID', 'srv-production'],
    ['RENDER_GIT_BRANCH', 'main'],
    ['VISION_ENABLED', 'true'],
    ['PATROLSYNC_STAGING_BOOTSTRAP', 'yes'],
    ['SYSTEM_DATABASE_URL', 'postgresql://patrolsync_db_user:secret@dpg-production-a.frankfurt-postgres.render.com/patrolsync_db'],
    ['SYSTEM_DATABASE_URL', 'postgresql://patrolsync_vision_staging_db_user:secret@dpg-production-a.frankfurt-postgres.render.com/patrolsync_vision_staging_db'],
    ['STAGING_TENANT_ROLE_PASSWORD', 'short']
  ]) {
    assert.throws(() => validateTarget({ ...valid, [key]: value }), key);
  }
});

test('read-only checks can validate the staging connection without bootstrap permission', () => {
  const checking = { ...valid, PATROLSYNC_STAGING_BOOTSTRAP: '' };
  assert.equal(validateStagingConnection(checking).rolePassword, valid.STAGING_TENANT_ROLE_PASSWORD);
  assert.throws(() => validateTarget(checking));
  assert.throws(() => validateStagingConnection({ ...checking, RENDER_SERVICE_ID: 'srv-production' }));
});

