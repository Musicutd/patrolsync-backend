'use strict';

// One-time, schema-only expansion for the dedicated disposable Vision staging DB.
// It deliberately does not load index.js or start the application.
const fs = require('node:fs');
const path = require('node:path');
const { validateStagingConnection } = require('./bootstrap-vision-staging');

const CONFIRMATION = 'EXPAND_REVIEWED_EXISTING_SCHEMA';
const BASELINE_TABLES = Object.freeze([
  'alert_log', 'checkpoints', 'guard_assignments', 'patrol_logs',
  'patrol_schedules', 'service_contracts', 'sites', 'tenants', 'users'
]);
const EXTRA_COLUMNS = Object.freeze([
  'ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS archived_by_user_id INTEGER',
  'ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS replacement_for_id INTEGER',
  'ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS replaced_by_id INTEGER'
]);

function quotedNames(text) {
  return [...text.matchAll(/'([a-z][a-z0-9_]*)'/g)].map(match => match[1]);
}

function migrationInventory(migration2, migration3) {
  const policyBlock = migration2.match(/tenant_tables\s+text\[\]\s*:=\s*ARRAY\[([\s\S]*?)\];/);
  const parentBlock = migration3.match(/FROM unnest\(ARRAY\[([\s\S]*?)\]\) AS parent_table/);
  const relationshipsBlock = migration3.match(/FROM \(VALUES([\s\S]*?)\) AS relationships/);
  if (!policyBlock || !parentBlock || !relationshipsBlock) {
    throw new Error('Reviewed migration inventory could not be parsed');
  }
  const relationships = [...relationshipsBlock[1].matchAll(/\('([a-z][a-z0-9_]*)','[^']+','[^']+','([a-z][a-z0-9_]*)'\)/g)];
  if (relationships.length < 50) throw new Error('Relationship migration inventory is unexpectedly small');
  return [...new Set([
    ...quotedNames(policyBlock[1]),
    ...quotedNames(parentBlock[1]),
    ...relationships.flatMap(match => [match[1], match[2]])
  ])].sort();
}

function sourceTableDefinitions(source) {
  const definitions = new Map();
  for (const match of source.matchAll(/`\s*(CREATE TABLE IF NOT EXISTS\s+([a-z][a-z0-9_]*)\s*\([\s\S]*?\))\s*`/g)) {
    if (match[1].includes('${')) throw new Error(`Dynamic CREATE TABLE is not permitted for ${match[2]}`);
    if (!definitions.has(match[2])) definitions.set(match[2], match[1]);
  }
  return definitions;
}

function orderDefinitions(inventory, definitions) {
  const wanted = new Set(inventory.filter(table => !BASELINE_TABLES.includes(table)));
  const missing = [...wanted].filter(table => !definitions.has(table));
  if (missing.length) throw new Error(`Application source is missing reviewed table definitions: ${missing.join(', ')}`);
  const ordered = [];
  const pending = new Set(wanted);
  while (pending.size) {
    let progress = false;
    for (const table of [...pending]) {
      const dependencies = [...definitions.get(table).matchAll(/REFERENCES\s+(?:public\.)?([a-z][a-z0-9_]*)\s*\(/gi)]
        .map(match => match[1]).filter(parent => wanted.has(parent));
      if (dependencies.every(parent => !pending.has(parent) || parent === table)) {
        ordered.push({ table, sql: definitions.get(table) });
        pending.delete(table);
        progress = true;
      }
    }
    if (!progress) throw new Error(`CREATE TABLE dependency cycle or unresolved ordering: ${[...pending].join(', ')}`);
  }
  return ordered;
}

function buildExpansion(root = path.join(__dirname, '..')) {
  const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');
  const inventory = migrationInventory(
    read(path.join('migrations', 'vision', '0002_tenant_workflow_policies_and_grants.sql')),
    read(path.join('migrations', 'vision', '0003_tenant_parent_child_constraints.sql'))
  );
  const ordered = orderDefinitions(inventory, sourceTableDefinitions(read('index.js')));
  return { inventory, ordered, extraColumns: [...EXTRA_COLUMNS] };
}

function validateTarget(env) {
  if (env.PATROLSYNC_STAGING_EXPAND !== CONFIRMATION) {
    throw new Error('Staging schema-expansion confirmation is missing');
  }
  return validateStagingConnection(env);
}

async function expand(env = process.env) {
  const { connectionString, expectedOwner } = validateTarget(env);
  const { inventory, ordered, extraColumns } = buildExpansion();
  const { Client } = require('pg');
  const client = new Client({ connectionString, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    await client.query('BEGIN');
    const identity = (await client.query(`SELECT current_database() AS db, session_user AS login_role,
      current_user AS active_role, pg_get_userbyid(datdba) AS database_owner
      FROM pg_database WHERE datname=current_database()`)).rows[0];
    if (identity.db !== 'patrolsync_vision_staging_db' || identity.login_role !== expectedOwner ||
        identity.active_role !== identity.database_owner) {
      throw new Error('Connected database identity differs from the approved staging target');
    }
    const tables = await client.query("SELECT tablename,rowsecurity FROM pg_tables WHERE schemaname='public' ORDER BY tablename");
    if (JSON.stringify(tables.rows.map(row => row.tablename)) !== JSON.stringify(BASELINE_TABLES) ||
        !tables.rows.every(row => row.rowsecurity)) {
      throw new Error('Refusing to expand anything other than the exact reviewed baseline');
    }
    const policies = await client.query("SELECT DISTINCT tablename FROM pg_policies WHERE schemaname='public' ORDER BY tablename");
    if (JSON.stringify(policies.rows.map(row => row.tablename)) !== JSON.stringify(BASELINE_TABLES)) {
      throw new Error('Refusing to expand a baseline without the reviewed tenant policies');
    }
    const role = (await client.query(`SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb
      FROM pg_roles WHERE rolname='patrolsync_vision_staging_tenant'`)).rows[0];
    if (!role?.rolcanlogin || role.rolsuper || role.rolbypassrls || role.rolcreaterole || role.rolcreatedb) {
      throw new Error('Refusing to expand without the restricted staging tenant role');
    }
    const counts = await Promise.all(BASELINE_TABLES.map(table => client.query(`SELECT COUNT(*)::int AS count FROM ${table}`)));
    if (counts.some(result => result.rows[0].count !== 0)) {
      throw new Error('Refusing to expand a baseline containing data');
    }
    for (const { sql } of ordered) await client.query(sql);
    for (const sql of extraColumns) await client.query(sql);
    for (const table of ordered.map(item => item.table)) {
      await client.query(`REVOKE ALL PRIVILEGES ON TABLE ${table} FROM PUBLIC, patrolsync_vision_staging_tenant`);
      const sequence = (await client.query('SELECT pg_get_serial_sequence($1,\'id\') AS name', [`public.${table}`])).rows[0].name;
      if (sequence) await client.query(`REVOKE ALL PRIVILEGES ON SEQUENCE ${sequence} FROM PUBLIC, patrolsync_vision_staging_tenant`);
    }
    const finalTables = await client.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename");
    const expected = [...new Set([...BASELINE_TABLES, ...inventory])].sort();
    if (JSON.stringify(finalTables.rows.map(row => row.tablename)) !== JSON.stringify(expected)) {
      throw new Error('Expanded schema does not match the reviewed migration inventory');
    }
    await client.query('COMMIT');
    return { tables: expected.length, added: ordered.length };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { await client.end(); }
}

if (require.main === module) {
  expand().then(result => console.log(`Vision staging schema expanded by ${result.added} tables (${result.tables} total); access remains revoked and API inactive.`))
    .catch(error => { console.error(`Vision staging schema expansion refused: ${error.code || error.message}`); process.exitCode = 1; });
}

module.exports = { BASELINE_TABLES, CONFIRMATION, buildExpansion, migrationInventory, sourceTableDefinitions, orderDefinitions, validateTarget, expand };
