const { Client } = require('pg');

const sql = `
BEGIN;

ALTER TABLE users DROP COLUMN IF EXISTS organization_id;
ALTER TABLE checkpoints DROP COLUMN IF EXISTS organization_id;
DROP TABLE IF EXISTS organizations;

COMMIT;
`;

async function main() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });

  await client.connect();
  console.log('Connected. Removing redundant organization_id columns and organizations table...');
  await client.query(sql);
  console.log('Cleanup complete.');

  const usersCols = await client.query(
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'users' ORDER BY ordinal_position"
  );
  console.log('users columns now:', usersCols.rows);

  const checkpointCols = await client.query(
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'checkpoints' ORDER BY ordinal_position"
  );
  console.log('checkpoints columns now:', checkpointCols.rows);

  await client.end();
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exitCode = 1;
});
