'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const {
  BASELINE_TABLES, CONFIRMATION, buildExpansion, migrationInventory,
  sourceTableDefinitions, orderDefinitions, validateTarget
} = require('../scripts/expand-vision-staging-schema');

const valid = {
  PATROLSYNC_STAGING_EXPAND: CONFIRMATION,
  RENDER_SERVICE_ID: 'srv-dal8ne3l550s73ck8l40',
  RENDER_GIT_BRANCH: 'feature/vision-v01-scaffold',
  VISION_ENABLED: 'false',
  SYSTEM_DATABASE_URL: 'postgresql://patrolsyncvisionstagingdb_abc123_user:secret@dpg-dal8lpbm8hqs73f9nsk0-a.internal/patrolsync_vision_staging_db',
  STAGING_DATABASE_OWNER: 'patrolsyncvisionstagingdb_abc123_user',
  STAGING_TENANT_ROLE_PASSWORD: 'x'.repeat(32)
};

test('schema expansion requires its exact one-time confirmation and staging identity', () => {
  assert.doesNotThrow(() => validateTarget(valid));
  assert.throws(() => validateTarget({ ...valid, PATROLSYNC_STAGING_EXPAND: 'yes' }), /confirmation/);
  assert.throws(() => validateTarget({ ...valid, RENDER_SERVICE_ID: 'srv-production' }), /service/);
});

test('reviewed migration inventory has a complete, static, dependency-ordered definition set', () => {
  const expansion = buildExpansion(path.join(__dirname, '..'));
  assert.ok(expansion.inventory.length > 60);
  assert.equal(expansion.ordered.length, expansion.inventory.filter(table => !BASELINE_TABLES.includes(table)).length);
  assert.equal(new Set(expansion.ordered.map(item => item.table)).size, expansion.ordered.length);
  assert.ok(expansion.ordered.every(item => item.sql.startsWith('CREATE TABLE IF NOT EXISTS')));
  assert.ok(expansion.ordered.every(item => !item.sql.includes('${')));
  assert.deepEqual(expansion.extraColumns.map(sql => sql.match(/EXISTS ([a-z_]+)/)[1]).sort(),
    ['archived_by_user_id', 'replaced_by_id', 'replacement_for_id']);
});

test('parsers fail closed for incomplete or dynamic source', () => {
  assert.throws(() => migrationInventory('tenant_tables text[] := ARRAY[];', ''), /inventory/);
  assert.throws(() => sourceTableDefinitions('`CREATE TABLE IF NOT EXISTS unsafe (id ${type})`'), /Dynamic/);
  assert.throws(() => orderDefinitions(['missing'], new Map()), /missing reviewed/);
});
