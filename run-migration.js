// run-migration.js
// One-time script to apply the multi-tenant schema migration.
// Uses the same DATABASE_URL env var your backend already uses on Render.
//
// USAGE (via Render Shell on the backend service):
//   node run-migration.js
//
// Requires the "pg" package (you likely already have it installed since
// your backend connects to Postgres). If not: npm install pg

const { Client } = require('pg');

const sql = `
BEGIN;

CREATE TABLE IF NOT EXISTS organizations (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id);

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'guard';

ALTER TABLE checkpoints
  ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id);

DO $$
DECLARE
  demo_org_id INTEGER;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM organizations WHERE name = 'Demo Org (migrate me)') THEN
    INSERT INTO organizations (name) VALUES ('Demo Org (migrate me)')
    RETURNING id INTO demo_org_id;
  ELSE
    SELECT id INTO demo_org_id FROM organizations WHERE name = 'Demo Org (migrate me)';
  END IF;

  UPDATE users SET organization_id = demo_org_id WHERE organization_id IS NULL;
  UPDATE checkpoints SET organization_id = demo_org_id WHERE organization_id IS NULL;
END $$;

ALTER TABLE users ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE checkpoints ALTER COLUMN organization_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_checkpoints_org ON checkpoints(organization_id);
CREATE INDEX IF NOT EXISTS idx_patrol_logs_checkpoint ON patrol_logs(checkpoint_id);
CREATE INDEX IF NOT EXISTS idx_patrol_logs_user ON patrol_logs(user_id);

COMMIT;
`;

async function main() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }, // Render requires SSL for external connections
  });

  try {
    await client.connect();
    console.log('Connected to database. Running migration...');
    await client.query(sql);
    console.log('Migration completed successfully.');

    const { rows: orgs } = await client.query('SELECT * FROM organizations');
    console.log('Organizations:', orgs);

    const { rows: userCheck } = await client.query(
      'SELECT id, name, organization_id FROM users LIMIT 5'
    );
    console.log('Sample users:', userCheck);
  } catch (err) {
    console.error('Migration failed:', err.message);
    process.exitCode = 1;
  } finally {
    await client.end();
  }
}

main();
