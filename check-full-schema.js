const { Client } = require('pg');

async function main() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });

  await client.connect();

  const tables = await client.query(
    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"
  );
  console.log('--- all tables ---');
  console.log(tables.rows);

  for (const t of tables.rows) {
    const cols = await client.query(
      `SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '${t.table_name}' ORDER BY ordinal_position`
    );
    console.log(`--- ${t.table_name} columns ---`);
    console.log(cols.rows);
  }

  await client.end();
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exitCode = 1;
});
