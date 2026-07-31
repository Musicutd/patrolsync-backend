const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'PatrolSync Backend', timestamp: new Date().toISOString() });
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'unhealthy', error: err.message });
  }
});

app.post('/api/tenants', async (req, res) => {
  const { name, slug, plan } = req.body;
  if (!name || !slug) return res.status(400).json({ error: 'name and slug are required' });
  try {
    const result = await pool.query(
      'INSERT INTO tenants (name, slug, plan) VALUES ($1, $2, $3) RETURNING *',
      [name, slug, plan || 'starter']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tenants', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tenants ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function withTenant(tenantId, fn) {
  const client = await pool.connect();
  try {
    await client.query(`SET app.current_tenant = '${tenantId}'`);
    return await fn(client);
  } finally {
    client.release();
  }
}

app.post('/api/sites', async (req, res) => {
  const { tenant_id, name, address } = req.body;
  if (!tenant_id || !name) return res.status(400).json({ error: 'tenant_id and name are required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'INSERT INTO sites (tenant_id, name, address) VALUES ($1, $2, $3) RETURNING *',
        [tenant_id, name, address || null]
      )
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sites', async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query('SELECT * FROM sites WHERE tenant_id = $1 ORDER BY created_at DESC', [tenant_id])
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/checkpoints', async (req, res) => {
  const { tenant_id, site_id, name, qr_code, latitude, longitude } = req.body;
  if (!tenant_id || !site_id || !name || !qr_code) {
    return res.status(400).json({ error: 'tenant_id, site_id, name, and qr_code are required' });
  }
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'INSERT INTO checkpoints (tenant_id, site_id, name, qr_code, latitude, longitude) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
        [tenant_id, site_id, name, qr_code, latitude || null, longitude || null]
      )
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/checkpoints', async (req, res) => {
  const { tenant_id, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      site_id
        ? client.query('SELECT * FROM checkpoints WHERE tenant_id = $1 AND site_id = $2 ORDER BY created_at DESC', [tenant_id, site_id])
        : client.query('SELECT * FROM checkpoints WHERE tenant_id = $1 ORDER BY created_at DESC', [tenant_id])
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`PatrolSync backend running on port ${PORT}`);
});
