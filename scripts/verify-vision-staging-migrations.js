'use strict';

const path = require('node:path');
const { spawn } = require('node:child_process');
const { validateStagingConnection } = require('./bootstrap-vision-staging');

const CONFIRMATION = 'VERIFY_REVIEWED_VISION_MIGRATIONS';
const TENANT_ROLE = 'patrolsync_vision_staging_tenant';

function validateTarget(env) {
  if (env.PATROLSYNC_STAGING_MIGRATION_VERIFY !== CONFIRMATION) {
    throw new Error('Staging migration-verification confirmation is missing');
  }
  return validateStagingConnection(env);
}

function verify(env = process.env) {
  validateTarget(env);
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(__dirname, 'verify-controlled-vision-migrations.js')], {
      env: {
        ...process.env,
        VERIFY_ENVIRONMENT: 'staging',
        VERIFY_CONFIRMATION: 'VERIFY PATROLSYNC STAGING VISION MIGRATIONS',
        VERIFY_DATABASE_URL: env.SYSTEM_DATABASE_URL,
        VERIFY_TENANT_ROLE: TENANT_ROLE
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.resume();
    child.once('error', reject);
    child.once('close', code => {
      if (code !== 0) return reject(new Error(`controlled migration verifier exited ${code}`));
      let result;
      try { result = JSON.parse(stdout); }
      catch (_) { return reject(new Error('controlled migration verifier returned an invalid result')); }
      const expected = { environment: 'staging', migrations: 3, policies: 56,
        privilegeMaps: 56, tenantForeignKeys: 59, tenantParentKeys: 18 };
      for (const [key, value] of Object.entries(expected)) {
        if (result[key] !== value) return reject(new Error(`controlled migration verifier result differs at ${key}`));
      }
      resolve(result);
    });
  });
}

if (require.main === module) {
  verify().then(result => console.log(`Vision staging migration audit passed: ${result.migrations} migrations, ${result.policies} policies, ${result.tenantForeignKeys} tenant foreign keys; API remains inactive.`))
    .catch(error => { console.error(`Vision staging migration audit refused: ${error.code || error.message}`); process.exitCode = 1; });
}

module.exports = { CONFIRMATION, TENANT_ROLE, validateTarget, verify };
