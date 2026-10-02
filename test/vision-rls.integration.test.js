'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { queryVisionFlag } = require('../vision-access');

test('restricted database role cannot read another tenant rollout flag', { skip: !process.env.VISION_TEST_DATABASE_URL }, async () => {
  const { Client } = require('pg');
  const admin = new Client({ connectionString: process.env.VISION_TEST_DATABASE_URL });
  const url = new URL(process.env.VISION_TEST_DATABASE_URL);
  const reader = new Client({
    host: url.hostname,
    port: Number(url.port || 5432),
    database: url.pathname.slice(1),
    user: 'vision_v01_reader',
    password: 'vision_v01_test_only'
  });
  await admin.connect();
  let readerConnected = false;
  try {
    await admin.query(`CREATE ROLE vision_v01_reader LOGIN PASSWORD 'vision_v01_test_only'`);
    await admin.query(`CREATE SCHEMA vision_v01_test`);
    await admin.query(`CREATE TABLE vision_v01_test.feature_flags(id BIGSERIAL PRIMARY KEY,code TEXT UNIQUE NOT NULL,enabled_globally BOOLEAN NOT NULL)`);
    await admin.query(`CREATE TABLE vision_v01_test.feature_flag_tenants(id BIGSERIAL PRIMARY KEY,flag_id BIGINT NOT NULL,tenant_id INTEGER NOT NULL,enabled BOOLEAN NOT NULL)`);
    await admin.query(`ALTER TABLE vision_v01_test.feature_flag_tenants ENABLE ROW LEVEL SECURITY`);
    await admin.query(`CREATE POLICY tenant_isolation ON vision_v01_test.feature_flag_tenants USING (tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
    await admin.query(`GRANT USAGE ON SCHEMA vision_v01_test TO vision_v01_reader`);
    await admin.query(`GRANT SELECT ON vision_v01_test.feature_flags,vision_v01_test.feature_flag_tenants TO vision_v01_reader`);
    const flag = await admin.query(`INSERT INTO vision_v01_test.feature_flags(code,enabled_globally) VALUES('vision_rollout',TRUE) RETURNING id`);
    await admin.query(`INSERT INTO vision_v01_test.feature_flag_tenants(flag_id,tenant_id,enabled) VALUES($1,11,TRUE)`, [flag.rows[0].id]);
    await reader.connect();
    readerConnected = true;
    await reader.query(`SET search_path TO vision_v01_test`);
    await reader.query(`SELECT set_config('app.current_tenant','11',FALSE)`);
    const own = await queryVisionFlag(reader, 11);
    assert.equal(own.tenant_flag, true);
    assert.equal(own.flag_tenant_id, 11);
    await reader.query(`SELECT set_config('app.current_tenant','22',FALSE)`);
    const other = await queryVisionFlag(reader, 11);
    assert.equal(other.tenant_flag, false);
    assert.equal(other.flag_tenant_id, null);
    const missing = await queryVisionFlag(reader, 22);
    assert.equal(missing.tenant_flag, false);
  } finally {
    if (readerConnected) await reader.end();
    await admin.query(`DROP SCHEMA IF EXISTS vision_v01_test CASCADE`);
    await admin.query(`DROP ROLE IF EXISTS vision_v01_reader`);
    await admin.end();
  }
});
