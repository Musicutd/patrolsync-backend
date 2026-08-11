/*
  GUARD CERTIFICATION / LICENSE TRACKING — additions for index.js
  =================================================================
  1. Add ensureGuardCertificationsTable() near the other ensure* functions
     and call it once at startup, same pattern as ensureClientUsersTable().
  2. Add the four endpoints below anywhere after requireAuth/requireAdmin
     are defined.
  3. Optionally wire certification expiry into the existing notification
     sweep (see note at the bottom) so expiring/expired certs show up in
     the same Alerts panel guards/admins already check.
*/

async function ensureGuardCertificationsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guard_certifications (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      cert_name TEXT NOT NULL,
      cert_number TEXT,
      issue_date DATE,
      expiry_date DATE NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_guard_certifications_lookup ON guard_certifications (tenant_id, user_id)`);
  console.log('Guard certifications table ready');
}
ensureGuardCertificationsTable();

const CERT_EXPIRY_WARNING_DAYS = 30;

// Shared status calculation — used by both the list endpoint and the
// dedicated "expiring" endpoint, so status logic lives in exactly one
// place and can't drift between the two views.
function computeCertStatus(expiryDate) {
  const today = DateTime.now().startOf('day');
  const expiry = DateTime.fromJSDate(new Date(expiryDate)).startOf('day');
  const daysRemaining = Math.round(expiry.diff(today, 'days').days);

  let status;
  if (daysRemaining < 0) status = 'expired';
  else if (daysRemaining <= CERT_EXPIRY_WARNING_DAYS) status = 'expiring_soon';
  else status = 'valid';

  return { status, days_remaining: daysRemaining };
}

app.post('/api/certifications', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, user_id, cert_name, cert_number, issue_date, expiry_date } = req.body;
  if (!tenant_id || !user_id || !cert_name || !expiry_date) {
    return res.status(400).json({ error: 'tenant_id, user_id, cert_name, and expiry_date are required' });
  }
  const parsedExpiry = new Date(expiry_date);
  if (isNaN(parsedExpiry.getTime())) {
    return res.status(400).json({ error: 'expiry_date must be a valid date' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const guardCheck = await client.query(
        "SELECT id FROM users WHERE id = $1 AND tenant_id = $2 AND role = 'guard'",
        [user_id, tenant_id]
      );
      if (guardCheck.rows.length === 0) {
        const err = new Error('Guard not found for this tenant');
        err.statusCode = 404;
        throw err;
      }
      return client.query(
        `INSERT INTO guard_certifications (tenant_id, user_id, cert_name, cert_number, issue_date, expiry_date)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [tenant_id, user_id, cert_name, cert_number || null, issue_date || null, expiry_date]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/certifications', requireAuth, async (req, res) => {
  const { tenant_id, user_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });

  if (req.auth.role !== 'admin' && Number(user_id) !== req.auth.user_id) {
    return res.status(403).json({ error: 'Guards can only view their own certifications' });
  }

  try {
    const result = await withTenant(tenant_id, (client) =>
      user_id
        ? client.query(
            `SELECT gc.*, u.email as guard_email FROM guard_certifications gc
             JOIN users u ON u.id = gc.user_id
             WHERE gc.tenant_id = $1 AND gc.user_id = $2 ORDER BY gc.expiry_date ASC`,
            [tenant_id, user_id]
          )
        : client.query(
            `SELECT gc.*, u.email as guard_email FROM guard_certifications gc
             JOIN users u ON u.id = gc.user_id
             WHERE gc.tenant_id = $1 ORDER BY gc.expiry_date ASC`,
            [tenant_id]
          )
    );
    const withStatus = result.rows.map(cert => ({ ...cert, ...computeCertStatus(cert.expiry_date) }));
    res.json(withStatus);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Dedicated endpoint for the "expiring soon / expired" widget — avoids
// making the dashboard fetch every certification and filter client-side.
app.get('/api/certifications/expiring', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `SELECT gc.*, u.email as guard_email FROM guard_certifications gc
         JOIN users u ON u.id = gc.user_id
         WHERE gc.tenant_id = $1 ORDER BY gc.expiry_date ASC`,
        [tenant_id]
      )
    );
    const flagged = result.rows
      .map(cert => ({ ...cert, ...computeCertStatus(cert.expiry_date) }))
      .filter(cert => cert.status === 'expired' || cert.status === 'expiring_soon');
    res.json(flagged);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/certifications/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, cert_name, cert_number, issue_date, expiry_date } = req.body;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `UPDATE guard_certifications
         SET cert_name = COALESCE($1, cert_name),
             cert_number = $2,
             issue_date = $3,
             expiry_date = COALESCE($4, expiry_date)
         WHERE id = $5 AND tenant_id = $6 RETURNING *`,
        [cert_name || null, cert_number || null, issue_date || null, expiry_date || null, id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Certification not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/certifications/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query('DELETE FROM guard_certifications WHERE id = $1 AND tenant_id = $2 RETURNING *', [id, tenant_id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Certification not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/*
  NOTE on tying this into the existing Alerts panel:
  The dashboard's "Alerts" section currently only shows overdue checkpoints
  (from the `notifications` table via runComplianceSweep). Certification
  expiry is a different kind of alert (no site_id/checkpoint_id), so rather
  than force-fitting it into that table, this design keeps it as its own
  widget backed by GET /api/certifications/expiring — same UX (color-coded,
  auto-refreshing) without corrupting the existing notifications schema.
*/
