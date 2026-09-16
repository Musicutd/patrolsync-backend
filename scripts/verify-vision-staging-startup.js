'use strict';

// Boots the real API against an empty, disposable CI database. Never point this at Render.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');
const { Client } = require('pg');

const TEST_DB = 'vision_startup_ci';
const TEST_ROLE = 'vision_startup_reader';

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function main() {
  const source = new URL(process.env.VISION_TEST_DATABASE_URL || '');
  assert.ok(['127.0.0.1', 'localhost'].includes(source.hostname), 'CI database must be on loopback');
  assert.equal(source.pathname, '/vision_ci', 'Refusing any database other than the CI fixture');
  const admin = new Client({ connectionString: source.href });
  const target = new URL(source.href);
  target.pathname = `/${TEST_DB}`;
  let child;
  let output = '';
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${TEST_DB}`);
    const db = new Client({ connectionString: target.href });
    await db.connect();
    try {
      await db.query(`CREATE ROLE ${TEST_ROLE}`);
      const fixture = fs.readFileSync(path.join(__dirname, '..', 'test', 'fixtures', 'vision-staging-base.sql'), 'utf8');
      await db.query(fixture.replaceAll('vision_base_reader', TEST_ROLE));
    } finally { await db.end(); }

    const port = await freePort();
    child = spawn(process.execPath, [
      '--require', path.join(__dirname, '..', 'test', 'helpers', 'local-postgres-no-ssl.js'),
      path.join(__dirname, '..', 'index.js')
    ], {
      cwd: path.join(__dirname, '..'),
      env: {
        ...process.env, NODE_ENV: 'test', VISION_ENABLED: 'false',
        DATABASE_URL: target.href, SYSTEM_DATABASE_URL: target.href,
        TENANT_DATABASE_URL: target.href, VISION_TEST_DATABASE_URL: target.href,
        PORT: String(port), AI_ASSISTANT_ENABLED: 'false',
        STRIPE_SECRET_KEY: '', OPENAI_API_KEY: '', BREVO_API_KEY: ''
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
      output = (output + chunk.toString()).slice(-20000);
    });

    let healthy = false;
    let tables = 0;
    let missingTables = [];
    const sourceCode = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    const expectedTables = new Set([...sourceCode.matchAll(/CREATE TABLE IF NOT EXISTS\s+([a-z_][a-z0-9_]*)/gi)]
      .map(match => match[1].toLowerCase()));
    for (const name of ['tenants', 'sites', 'users', 'checkpoints', 'patrol_schedules', 'patrol_logs', 'alert_log']) {
      expectedTables.add(name);
    }
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline && child.exitCode === null) {
      try {
        const response = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(1000) });
        healthy = response.status === 200;
        const count = new Client({ connectionString: target.href });
        await count.connect();
        try {
          const found = new Set((await count.query(`SELECT tablename FROM pg_tables WHERE schemaname='public'`))
            .rows.map(row => row.tablename));
          tables = found.size;
          missingTables = [...expectedTables].filter(name => !found.has(name)).sort();
        } finally { await count.end(); }
        if (healthy && missingTables.length === 0) break;
      } catch (_) { /* Server is still starting. */ }
      await delay(500);
    }
    assert.ok(healthy, `API health did not become ready. Output:\n${output}`);
    assert.deepEqual(missingTables, [], `Missing startup tables: ${missingTables.join(', ')}. ${tables} tables initialized. Output:\n${output}`);
    assert.doesNotMatch(output, /setup failed:|unhandled_rejection/i, `Startup error:\n${output}`);
    console.log(`Disposable startup passed: HTTP /health 200, ${tables} public tables, Vision disabled.`);
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(3000)]);
      if (child.exitCode === null) child.kill('SIGKILL');
    }
    await admin.query(`DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE)`);
    await admin.query(`DROP ROLE IF EXISTS ${TEST_ROLE}`);
    await admin.end();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });

