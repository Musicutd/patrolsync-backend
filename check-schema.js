const { Client } = require('pg');

async function main() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });

  await client.connect();

  const cols = await client.query(
    "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users' ORDER BY ordinal_position"
  );
  console.log('--- users table columns ---');
  console.log(cols.rows);

  const sample = await client.query('SELECT * FROM users LIMIT 3');
  console.log('--- sample users rows ---');
  console.log(sample.rows);

  const checkpointCols = await client.query(
    "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'checkpoints' ORDER BY ordinal_position"
  );
  console.log('--- checkpoints table columns ---');
  console.log(checkpointCols.rows);

  await client.end();
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exitCode = 1;
});
