'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('disposable staging baseline creates legacy tables and isolates tenants', {
  skip: !process.env.VISION_TEST_DATABASE_URL
}, async () => {
  const { Client } = require('pg');
  const admin = new Client({ connectionString: process.env.VISION_TEST_DATABASE_URL });
  const url = new URL(process.env.VISION_TEST_DATABASE_URL);
  const reader = new Client({
    host: url.hostname, port: Number(url.port || 5432), database: url.pathname.slice(1),
    user: 'vision_base_reader', password: 'vision_base_test_only'
  });
  await admin.connect();
  let readerConnected = false;
  try {
    await admin.query(`CREATE ROLE vision_base_reader LOGIN PASSWORD 'vision_base_test_only'`);
    await admin.query(`CREATE SCHEMA vision_base_test`);
    await admin.query(`SET search_path TO vision_base_test`);
    const sql = fs.readFileSync(path.join(__dirname, 'fixtures', 'vision-staging-base.sql'), 'utf8');
    await admin.query(sql);
    const tables = await admin.query(`SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname='vision_base_test' ORDER BY tablename`);
    assert.deepEqual(tables.rows.map(row => row.tablename), [
      'alert_log', 'checkpoints', 'guard_assignments', 'patrol_logs',
      'patrol_schedules', 'sites', 'tenants', 'users'
    ]);
    assert.ok(tables.rows.every(row => row.rowsecurity));
    await admin.query(`GRANT USAGE ON SCHEMA vision_base_test TO vision_base_reader`);
    await admin.query(`GRANT SELECT ON ALL TABLES IN SCHEMA vision_base_test TO vision_base_reader`);
    const one = await admin.query(`INSERT INTO tenants(name,slug) VALUES('One','one') RETURNING id`);
    const two = await admin.query(`INSERT INTO tenants(name,slug) VALUES('Two','two') RETURNING id`);
    await admin.query(`INSERT INTO sites(tenant_id,name) VALUES($1,'One site'),($2,'Two site')`, [one.rows[0].id, two.rows[0].id]);
    await reader.connect();
    readerConnected = true;
    await reader.query(`SET search_path TO vision_base_test`);
    await reader.query(`SELECT set_config('app.current_tenant',$1,false)`, [String(one.rows[0].id)]);
    assert.equal((await reader.query(`SELECT count(*)::int AS count FROM tenants`)).rows[0].count, 1);
    assert.equal((await reader.query(`SELECT count(*)::int AS count FROM sites`)).rows[0].count, 1);
    await reader.query(`SELECT set_config('app.current_tenant',$1,false)`, [String(two.rows[0].id)]);
    assert.equal((await reader.query(`SELECT count(*)::int AS count FROM tenants`)).rows[0].count, 1);
    assert.equal((await reader.query(`SELECT count(*)::int AS count FROM sites`)).rows[0].count, 1);
  } finally {
    if (readerConnected) await reader.end();
    await admin.query(`DROP SCHEMA IF EXISTS vision_base_test CASCADE`);
    await admin.query(`DROP ROLE IF EXISTS vision_base_reader`);
    await admin.end();
  }
});

