const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { DateTime } = require('luxon');
const QRCode = require('qrcode');
const PDFDocument = require('pdfkit');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '12mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'patrolsync-dev-secret';
const FIXED_WINDOW_MINUTES = 30;
const ALERT_SWEEP_INTERVAL_MS = 5 * 60 * 1000;
const LOCATION_HISTORY_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const LOCATION_HISTORY_RETENTION_HOURS = 48;
const MAX_PHOTOS_PER_INCIDENT = 3;
const MAX_PHOTO_BASE64_LENGTH = 3 * 1024 * 1024;

const PLAN_LIMITS = {
  starter: { locations: 1, checkpoints: 10, guards: 3, client_accounts: 1, monthly_price: 39, overage: null },
  medium: { locations: 1, checkpoints: 20, guards: 6, client_accounts: 2, monthly_price: 79, overage: null },
  pro: { locations: 2, checkpoints: 50, guards: 10, client_accounts: 5, monthly_price: 149, overage: null },
  diamond: { locations: 3, checkpoints: 100, guards: 15, client_accounts: 10, monthly_price: 299, overage: null },
  enterprise: {
    locations: Infinity,
    checkpoints: Infinity,
    guards: Infinity,
    client_accounts: Infinity,
    monthly_price: 499,
    overage: { location: 80, checkpoint: 10, guard: 15, client_account: 20 }
  }
};
const VALID_PLANS = Object.keys(PLAN_LIMITS);

const FALLBACK_TIMEZONES = [
  'UTC', 'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'Europe/Madrid', 'Europe/Rome',
  'Europe/Amsterdam', 'Europe/Warsaw', 'Europe/Moscow', 'Europe/Istanbul', 'Africa/Cairo',
  'Africa/Johannesburg', 'Africa/Lagos', 'Asia/Dubai', 'Asia/Karachi', 'Asia/Kolkata',
  'Asia/Dhaka', 'Asia/Bangkok', 'Asia/Jakarta', 'Asia/Singapore', 'Asia/Hong_Kong',
  'Asia/Shanghai', 'Asia/Tokyo', 'Asia/Seoul', 'Australia/Perth', 'Australia/Sydney',
  'Pacific/Auckland', 'America/Sao_Paulo', 'America/Argentina/Buenos_Aires', 'America/Mexico_City',
  'America/Bogota', 'America/Lima', 'America/New_York', 'America/Chicago', 'America/Denver',
  'America/Los_Angeles', 'America/Anchorage', 'Pacific/Honolulu'
];

function getAllTimezones() {
  try {
    if (typeof Intl.supportedValuesOf === 'function') {
      const zones = Intl.supportedValuesOf('timeZone');
      if (zones && zones.length) return zones;
    }
  } catch (err) {}
  return FALLBACK_TIMEZONES;
}

async function withTenant(tenantId, fn) {
  const client = await pool.connect();
  try {
    await client.query(`SET app.current_tenant = '${tenantId}'`);
    return await fn(client);
  } finally {
    client.release();
  }
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.auth || req.auth.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

function requireClient(req, res, next) {
  if (!req.auth || req.auth.role !== 'client') {
    return res.status(403).json({ error: 'Client access required' });
  }
  next();
}

async function checkPlanLimit(client, tenantId, resource) {
  const tenantRes = await client.query('SELECT plan FROM tenants WHERE id = $1', [tenantId]);
  const plan = (tenantRes.rows[0] && tenantRes.rows[0].plan) || 'starter';
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.starter;
  const max = limits[resource];

  if (max === Infinity || max === undefined) return { allowed: true, plan, max, current: null };

  let countQuery;
  if (resource === 'locations') countQuery = 'SELECT COUNT(*) FROM sites WHERE tenant_id = $1';
  else if (resource === 'checkpoints') countQuery = 'SELECT COUNT(*) FROM checkpoints WHERE tenant_id = $1';
  else if (resource === 'guards') countQuery = "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role = 'guard'";
  else if (resource === 'client_accounts') countQuery = 'SELECT COUNT(*) FROM client_users WHERE tenant_id = $1';
  else return { allowed: true, plan, max, current: null };

  const countRes = await client.query(countQuery, [tenantId]);
  const current = parseInt(countRes.rows[0].count, 10);
  return { allowed: current < max, plan, max, current };
}

async function ensureIncidentsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS incidents (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      checkpoint_id INTEGER,
      user_id INTEGER NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'low',
      reported_at TIMESTAMP DEFAULT NOW()
    )
  `);
}
ensureIncidentsTable();

async function ensureIncidentPhotosTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS incident_photos (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      incident_id INTEGER NOT NULL,
      photo_data TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
}
ensureIncidentPhotosTable();

async function ensureAuthColumn() {
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT`);
}
ensureAuthColumn();

async function ensureFirebaseUidNullable() {
  await pool.query(`ALTER TABLE users ALTER COLUMN firebase_uid DROP NOT NULL`);
}
ensureFirebaseUidNullable();

async function ensureTimezoneColumn() {
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS timezone TEXT DEFAULT 'UTC'`);
}
ensureTimezoneColumn();

async function ensureEmergencyContactColumns() {
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS emergency_phone TEXT`);
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS emergency_whatsapp TEXT`);
}
ensureEmergencyContactColumns();

async function ensureNotificationsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      site_name TEXT NOT NULL,
      checkpoint_id INTEGER NOT NULL,
      checkpoint_name TEXT NOT NULL,
      message TEXT NOT NULL,
      hours_overdue NUMERIC DEFAULT 0,
      resolved BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMP
    )
  `);
}
ensureNotificationsTable();

async function ensureGuardAssignmentsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guard_assignments (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id, site_id, user_id)
    )
  `);
}
ensureGuardAssignmentsTable();

async function ensureRoundSizeColumn() {
  await pool.query(`ALTER TABLE guard_assignments ADD COLUMN IF NOT EXISTS round_size INTEGER`);
}
ensureRoundSizeColumn();

async function ensureCheckpointMetaColumns() {
  await pool.query(`ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS building TEXT`);
  await pool.query(`ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS floor TEXT`);
}
ensureCheckpointMetaColumns();

async function ensureSosAlertsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sos_alerts (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      message TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMP,
      resolved_by INTEGER
    )
  `);
}
ensureSosAlertsTable();

async function ensureGuardLocationsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guard_locations (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      site_id INTEGER,
      latitude DOUBLE PRECISION NOT NULL,
      longitude DOUBLE PRECISION NOT NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id, user_id)
    )
  `);
}
ensureGuardLocationsTable();

async function ensureGuardLocationHistoryTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guard_location_history (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      site_id INTEGER,
      latitude DOUBLE PRECISION NOT NULL,
      longitude DOUBLE PRECISION NOT NULL,
      recorded_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_guard_location_history_lookup ON guard_location_history (tenant_id, user_id, recorded_at)`);
}
ensureGuardLocationHistoryTable();

async function cleanupLocationHistory() {
  try {
    const cutoff = new Date(Date.now() - LOCATION_HISTORY_RETENTION_HOURS * 3600000);
    await pool.query('DELETE FROM guard_location_history WHERE recorded_at < $1', [cutoff]);
  } catch (err) {
    console.error('Location history cleanup failed:', err.message);
  }
}
setInterval(cleanupLocationHistory, LOCATION_HISTORY_CLEANUP_INTERVAL_MS);
setTimeout(cleanupLocationHistory, 20000);

async function ensureClientUsersTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS client_users (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      email TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id, email)
    )
  `);
}
ensureClientUsersTable();

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
}
ensureGuardCertificationsTable();

const CERT_EXPIRY_WARNING_DAYS = 30;

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

function mostRecentFixedOccurrenceUTC(times, nowUTC, zone) {
  const nowLocal = DateTime.fromJSDate(nowUTC, { zone });
  const candidates = [];
  [0, -1].forEach(dayOffset => {
    const base = nowLocal.plus({ days: dayOffset });
    times.forEach(t => {
      const [h, m] = t.split(':').map(Number);
      const occLocal = base.set({ hour: h || 0, minute: m || 0, second: 0, millisecond: 0 });
      const occUTC = occLocal.toUTC();
      if (occUTC.toJSDate() <= nowUTC) candidates.push(occUTC.toJSDate());
    });
  });
  if (candidates.length === 0) return null;
  return new Date(Math.max(...candidates.map(d => d.getTime())));
}

function todayStartUTC(zone) {
  return DateTime.now().setZone(zone).startOf('day').toUTC().toJSDate();
}

async function computeSiteCompliance(client, tenantId, siteId) {
  const tenantRes = await client.query('SELECT timezone FROM tenants WHERE id = $1', [tenantId]);
  const schedulesRes = await client.query('SELECT * FROM patrol_schedules WHERE tenant_id = $1 AND site_id = $2', [tenantId, siteId]);
  const checkpointsRes = await client.query('SELECT * FROM checkpoints WHERE tenant_id = $1 AND site_id = $2', [tenantId, siteId]);
  const checkpointIds = checkpointsRes.rows.map(c => c.id);
  const logsRes = checkpointIds.length
    ? await client.query('SELECT * FROM patrol_logs WHERE tenant_id = $1 AND checkpoint_id = ANY($2) ORDER BY scanned_at DESC', [tenantId, checkpointIds])
    : { rows: [] };

  const zone = (tenantRes.rows[0] && tenantRes.rows[0].timezone) || 'UTC';
  const now = new Date();
  const hourlySchedules = schedulesRes.rows.filter(s => s.schedule_type === 'hourly');
  const fixedSchedules = schedulesRes.rows.filter(s => s.schedule_type === 'fixed');
  const hasCustomOnly = hourlySchedules.length === 0 && fixedSchedules.length === 0 && schedulesRes.rows.some(s => s.schedule_type === 'custom');
  const shortestHourly = hourlySchedules.length ? Math.min(...hourlySchedules.map(s => Number(s.config.interval_hours) || Infinity)) : null;
  const allFixedTimes = Array.from(new Set(fixedSchedules.flatMap(s => (Array.isArray(s.config.times) ? s.config.times : []))));

  return checkpointsRes.rows.map(cp => {
    const lastLog = logsRes.rows.find(l => l.checkpoint_id === cp.id);
    const lastScan = lastLog ? new Date(lastLog.scanned_at) : null;
    let status = 'no_schedule';
    let hoursOverdue = 0;
    let scheduleType = null;

    if (shortestHourly !== null && shortestHourly !== Infinity) {
      scheduleType = 'hourly';
      if (!lastScan) status = 'overdue';
      else {
        const hoursSince = (now - lastScan) / 3600000;
        if (hoursSince > shortestHourly) {
          status = 'overdue';
          hoursOverdue = Math.round((hoursSince - shortestHourly) * 10) / 10;
        } else {
          status = 'ok';
        }
      }
    } else if (allFixedTimes.length > 0) {
      scheduleType = 'fixed';
      const targetOcc = mostRecentFixedOccurrenceUTC(allFixedTimes, now, zone);
      if (!targetOcc) status = 'ok';
      else {
        const windowStart = new Date(targetOcc.getTime() - FIXED_WINDOW_MINUTES * 60000);
        const windowEnd = new Date(targetOcc.getTime() + FIXED_WINDOW_MINUTES * 60000);
        const matchedScan = logsRes.rows.find(l => {
          const t = new Date(l.scanned_at);
          return l.checkpoint_id === cp.id && t >= windowStart && t <= windowEnd;
        });
        if (matchedScan) status = 'ok';
        else if (now < windowEnd) status = 'ok';
        else {
          status = 'overdue';
          hoursOverdue = Math.round(((now - windowEnd) / 3600000) * 10) / 10;
        }
      }
    } else if (hasCustomOnly) {
      status = 'unmonitored';
    }

    return { checkpoint_id: cp.id, checkpoint_name: cp.name, last_scan: lastScan, status, hours_overdue: hoursOverdue, schedule_type: scheduleType };
  });
}

async function runComplianceSweep() {
  try {
    const tenantsRes = await pool.query('SELECT id FROM tenants');
    for (const tenant of tenantsRes.rows) {
      await withTenant(tenant.id, async client => {
        const sitesRes = await client.query('SELECT id, name FROM sites WHERE tenant_id = $1', [tenant.id]);
        for (const site of sitesRes.rows) {
          const compliance = await computeSiteCompliance(client, tenant.id, site.id);
          for (const cp of compliance) {
            const openRes = await client.query('SELECT id FROM notifications WHERE tenant_id = $1 AND checkpoint_id = $2 AND resolved = FALSE', [tenant.id, cp.checkpoint_id]);
            const hasOpen = openRes.rows.length > 0;
            if (cp.status === 'overdue' && !hasOpen) {
              const message = cp.hours_overdue ? `${cp.checkpoint_name} is ${cp.hours_overdue}h overdue` : `${cp.checkpoint_name} has never been scanned`;
              await client.query(
                `INSERT INTO notifications (tenant_id, site_id, site_name, checkpoint_id, checkpoint_name, message, hours_overdue)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [tenant.id, site.id, site.name, cp.checkpoint_id, cp.checkpoint_name, message, cp.hours_overdue]
              );
            } else if (cp.status !== 'overdue' && hasOpen) {
              await client.query('UPDATE notifications SET resolved = TRUE, resolved_at = NOW() WHERE tenant_id = $1 AND checkpoint_id = $2 AND resolved = FALSE', [tenant.id, cp.checkpoint_id]);
            }
          }
        }
      });
    }
  } catch (err) {
    console.error('Compliance sweep failed:', err.message);
  }
}
setInterval(runComplianceSweep, ALERT_SWEEP_INTERVAL_MS);
setTimeout(runComplianceSweep, 15000);

async function fetchReportData(client, tenantId, siteId, startDt, endDt) {
  const tenantRes = await client.query('SELECT name, timezone FROM tenants WHERE id = $1', [tenantId]);
  const siteRes = await client.query('SELECT name FROM sites WHERE id = $1 AND tenant_id = $2', [siteId, tenantId]);
  if (siteRes.rows.length === 0) {
    const err = new Error('Site not found');
    err.statusCode = 404;
    throw err;
  }

  const checkpointsRes = await client.query('SELECT id, name, building, floor FROM checkpoints WHERE tenant_id = $1 AND site_id = $2 ORDER BY name', [tenantId, siteId]);
  const checkpointIds = checkpointsRes.rows.map(c => c.id);
  const logsRes = checkpointIds.length
    ? await client.query(
        `SELECT pl.*, u.email as guard_email FROM patrol_logs pl
         LEFT JOIN users u ON u.id = pl.user_id
         WHERE pl.tenant_id = $1 AND pl.checkpoint_id = ANY($2)
           AND pl.scanned_at >= $3 AND pl.scanned_at <= $4
         ORDER BY pl.scanned_at ASC`,
        [tenantId, checkpointIds, startDt.toJSDate(), endDt.toJSDate()]
      )
    : { rows: [] };

  const incidentsRes = await client.query(
    `SELECT i.*, u.email as guard_email, COALESCE(p.photo_count, 0) as photo_count
     FROM incidents i
     LEFT JOIN users u ON u.id = i.user_id
     LEFT JOIN (
       SELECT incident_id, COUNT(*) AS photo_count FROM incident_photos WHERE tenant_id = $1 GROUP BY incident_id
     ) p ON p.incident_id = i.id
     WHERE i.tenant_id = $1 AND i.site_id = $2
       AND i.reported_at >= $3 AND i.reported_at <= $4
     ORDER BY i.reported_at ASC`,
    [tenantId, siteId, startDt.toJSDate(), endDt.toJSDate()]
  );

  const checkpointLookup = {};
  checkpointsRes.rows.forEach(cp => { checkpointLookup[cp.id] = cp; });
  const perCheckpoint = checkpointsRes.rows.map(cp => {
    const scansForCp = logsRes.rows.filter(l => l.checkpoint_id === cp.id);
    const lastScanInRange = scansForCp.length ? scansForCp[scansForCp.length - 1].scanned_at : null;
    return { id: cp.id, name: cp.name, location: [cp.building, cp.floor].filter(Boolean).join(' / ') || '-', scanCount: scansForCp.length, lastScan: lastScanInRange };
  });
  const scannedCheckpoints = perCheckpoint.filter(cp => cp.scanCount > 0).length;

  return {
    tenantName: tenantRes.rows[0] ? tenantRes.rows[0].name : 'PatrolSync Client',
    timezone: (tenantRes.rows[0] && tenantRes.rows[0].timezone) || 'UTC',
    siteName: siteRes.rows[0].name,
    checkpointLookup,
    perCheckpoint,
    logs: logsRes.rows,
    incidents: incidentsRes.rows,
    stats: {
      totalCheckpoints: checkpointsRes.rows.length,
      totalScans: logsRes.rows.length,
      scannedCheckpoints,
      totalIncidents: incidentsRes.rows.length
    }
  };
}

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const str = String(value);
  if (/[",\n]/.test(str)) return '"' + str.replace(/"/g, '""') + '"';
  return str;
}

function buildCsv(headers, rows) {
  const lines = [headers.map(csvEscape).join(',')];
  rows.forEach(row => lines.push(row.map(csvEscape).join(',')));
  return lines.join('\r\n');
}

function drawReportHeader(doc, tenantName, siteName, startLabel, endLabel) {
  doc.fontSize(20).fillColor('#1e293b').text('Patrol Compliance Report', { align: 'left' });
  doc.moveDown(0.3);
  doc.fontSize(11).fillColor('#64748b').text(tenantName, { align: 'left' });
  doc.moveDown(0.8);
  doc.fontSize(13).fillColor('#111827').text('Site: ' + siteName);
  doc.fontSize(11).fillColor('#374151').text('Period: ' + startLabel + ' to ' + endLabel);
  doc.fontSize(9).fillColor('#9ca3af').text('Generated ' + DateTime.now().toFormat('dd LLL yyyy, HH:mm') + ' by PatrolSync');
  doc.moveDown(1);
  doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#e5e7eb').stroke();
  doc.moveDown(1);
}

function drawSectionTitle(doc, title) {
  doc.fontSize(14).fillColor('#1e293b').text(title);
  doc.moveDown(0.4);
}

function drawSummaryStats(doc, stats) {
  const boxWidth = 123;
  const boxHeight = 60;
  const startX = 50;
  const startY = doc.y;
  const items = [
    { label: 'Checkpoints', value: String(stats.totalCheckpoints) },
    { label: 'Total Scans', value: String(stats.totalScans) },
    { label: 'Checkpoints Scanned', value: stats.scannedCheckpoints + '/' + stats.totalCheckpoints },
    { label: 'Incidents Logged', value: String(stats.totalIncidents) }
  ];

  items.forEach((item, i) => {
    const x = startX + i * (boxWidth + 6);
    doc.roundedRect(x, startY, boxWidth, boxHeight, 6).fillAndStroke('#f8fafc', '#e5e7eb');
    doc.fontSize(20).fillColor('#2563eb').text(item.value, x, startY + 10, { width: boxWidth, align: 'center' });
    doc.fontSize(9).fillColor('#64748b').text(item.label, x, startY + 38, { width: boxWidth, align: 'center' });
  });

  doc.y = startY + boxHeight + 20;
}

function severityColor(sev) {
  if (sev === 'critical') return '#7f1d1d';
  if (sev === 'high') return '#dc2626';
  if (sev === 'medium') return '#d97706';
  return '#2563eb';
}

function parseReportDateRange(start_date, end_date) {
  const startDt = DateTime.fromISO(start_date).startOf('day');
  const endDt = DateTime.fromISO(end_date).endOf('day');
  if (!startDt.isValid || !endDt.isValid || endDt < startDt) {
    const err = new Error('Invalid or reversed date range');
    err.statusCode = 400;
    throw err;
  }
  return { startDt, endDt };
}

function safeFilenamePart(str) {
  return String(str).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

async function ensureShiftsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shifts (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      shift_date DATE NOT NULL,
      start_time TIME NOT NULL,
      end_time TIME NOT NULL,
      employment_type TEXT NOT NULL DEFAULT 'full_time',
      recurrence TEXT NOT NULL DEFAULT 'none',
      recurrence_group_id TEXT,
      notes TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query('CREATE INDEX IF NOT EXISTS idx_shifts_tenant_date ON shifts (tenant_id, shift_date)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_shifts_tenant_user ON shifts (tenant_id, user_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_shifts_group ON shifts (tenant_id, recurrence_group_id)');
}
ensureShiftsTable();

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const userRes = await pool.query(
      "SELECT id, email, password_hash, role FROM users WHERE LOWER(email) = $1 AND role = 'admin'",
      [normalizedEmail]
    );

    if (userRes.rows.length > 0) {
      const dbUser = userRes.rows[0];
      if (!dbUser.password_hash) {
        return res.status(401).json({ error: 'This admin has no password set yet' });
      }
      const ok = await bcrypt.compare(password, dbUser.password_hash);
      if (ok) {
        const user = { id: dbUser.id, email: dbUser.email, role: dbUser.role || 'admin' };
        const token = jwt.sign({ user_id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '12h' });
        return res.json({ token, user });
      }
    }
  } catch (err) {
    console.error('Admin login DB error:', err.message);
    return res.status(500).json({ error: 'Admin login failed' });
  }

  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@patrolsync.co';
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password123';
  if (normalizedEmail === ADMIN_EMAIL.toLowerCase() && password === ADMIN_PASSWORD) {
    const user = { id: 1, email: ADMIN_EMAIL, role: 'admin', name: 'Admin' };
    const token = jwt.sign({ user_id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '12h' });
    return res.json({ token, user });
  }

  return res.status(401).json({ error: 'Invalid email or password' });
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'unhealthy', error: err.message });
  }
});

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

app.get('/api/timezones', (req, res) => res.json(getAllTimezones()));
app.get('/api/plans', (req, res) => res.json(PLAN_LIMITS));

app.get('/api/usage', requireAuth, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const data = await withTenant(tenant_id, async client => {
      const tenantRes = await client.query('SELECT plan FROM tenants WHERE id = $1', [tenant_id]);
      const plan = (tenantRes.rows[0] && tenantRes.rows[0].plan) || 'starter';
      const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.starter;
      const sitesRes = await client.query('SELECT COUNT(*) FROM sites WHERE tenant_id = $1', [tenant_id]);
      const checkpointsRes = await client.query('SELECT COUNT(*) FROM checkpoints WHERE tenant_id = $1', [tenant_id]);
      const guardsRes = await client.query("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role = 'guard'", [tenant_id]);
      const clientAccountsRes = await client.query('SELECT COUNT(*) FROM client_users WHERE tenant_id = $1', [tenant_id]);
      return {
        plan,
        limits,
        usage: {
          locations: parseInt(sitesRes.rows[0].count, 10),
          checkpoints: parseInt(checkpointsRes.rows[0].count, 10),
          guards: parseInt(guardsRes.rows[0].count, 10),
          client_accounts: parseInt(clientAccountsRes.rows[0].count, 10)
        }
      };
    });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/guard-certifications', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, async client => {
      const certs = await client.query(
        `SELECT gc.*, u.email AS guard_email
         FROM guard_certifications gc
         JOIN users u ON u.id = gc.user_id
         WHERE gc.tenant_id = $1
         ORDER BY gc.expiry_date ASC`,
        [tenant_id]
      );
      return certs.rows.map(row => ({ ...row, ...computeCertStatus(row.expiry_date) }));
    });
    res.json(result);
  } catch (err) {
    console.error('Certifications fetch error:', err.message);
    res.status(500).json({ error: 'Failed to load certifications' });
  }
});

app.get('/api/notifications', requireAuth, async (req, res) => {
  const { tenant_id, status } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client => {
      if (status === 'resolved') {
        return client.query('SELECT * FROM notifications WHERE tenant_id = $1 AND resolved = TRUE ORDER BY resolved_at DESC LIMIT 50', [tenant_id]);
      } else if (status === 'all') {
        return client.query('SELECT * FROM notifications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100', [tenant_id]);
      }
      return client.query('SELECT * FROM notifications WHERE tenant_id = $1 AND resolved = FALSE ORDER BY created_at DESC', [tenant_id]);
    });
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/notifications/:id/resolve', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client =>
      client.query('UPDATE notifications SET resolved = TRUE, resolved_at = NOW() WHERE id = $1 AND tenant_id = $2 RETURNING *', [id, tenant_id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Notification not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sos', requireAuth, async (req, res) => {
  const { tenant_id, site_id, latitude, longitude, message } = req.body;
  const user_id = req.auth.user_id;
  if (!tenant_id || !site_id) return res.status(400).json({ error: 'tenant_id and site_id are required' });
  try {
    const result = await withTenant(tenant_id, async client => {
      const existing = await client.query("SELECT * FROM sos_alerts WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'", [tenant_id, user_id]);
      if (existing.rows.length > 0) return { row: existing.rows[0], alreadyActive: true };
      const inserted = await client.query(
        `INSERT INTO sos_alerts (tenant_id, site_id, user_id, latitude, longitude, message)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [tenant_id, site_id, user_id, latitude ?? null, longitude ?? null, message || null]
      );
      return { row: inserted.rows[0], alreadyActive: false };
    });
    res.status(result.alreadyActive ? 200 : 201).json(result.row);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sos', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, status } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client => {
      const base = `SELECT sa.*, u.email as guard_email, s.name as site_name
        FROM sos_alerts sa
        JOIN users u ON u.id = sa.user_id
        JOIN sites s ON s.id = sa.site_id
        WHERE sa.tenant_id = $1`;
      if (status === 'resolved') {
        return client.query(base + " AND sa.status = 'resolved' ORDER BY sa.resolved_at DESC LIMIT 50", [tenant_id]);
      } else if (status === 'all') {
        return client.query(base + ' ORDER BY sa.created_at DESC LIMIT 100', [tenant_id]);
      }
      return client.query(base + " AND sa.status = 'active' ORDER BY sa.created_at DESC", [tenant_id]);
    });
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/sos/:id/resolve', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.body;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id is required' });
  try {
    const result = await withTenant(tenant_id, async client => {
      const existing = await client.query("SELECT * FROM sos_alerts WHERE id = $1 AND tenant_id = $2 AND status = 'active'", [id, tenant_id]);
      if (existing.rows.length === 0) return { rows: [] };
      const alert = existing.rows[0];
      const isOwner = alert.user_id === req.auth.user_id;
      const isAdmin = req.auth.role === 'admin';
      if (!isOwner && !isAdmin) {
        const err = new Error('You can only cancel your own SOS alert');
        err.statusCode = 403;
        throw err;
      }
      return client.query(
        `UPDATE sos_alerts SET status = 'resolved', resolved_at = NOW(), resolved_by = $1
         WHERE id = $2 AND tenant_id = $3 AND status = 'active' RETURNING *`,
        [req.auth.user_id, id, tenant_id]
      );
    });
    if (result.rows.length === 0) return res.status(404).json({ error: 'Active SOS alert not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.post('/api/guard-locations', requireAuth, async (req, res) => {
  const { tenant_id, site_id, latitude, longitude } = req.body;
  const user_id = req.auth.user_id;
  if (!tenant_id || latitude === undefined || longitude === undefined) {
    return res.status(400).json({ error: 'tenant_id, latitude, and longitude are required' });
  }
  try {
    const result = await withTenant(tenant_id, async client => {
      const upserted = await client.query(
        `INSERT INTO guard_locations (tenant_id, user_id, site_id, latitude, longitude, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW())
         ON CONFLICT (tenant_id, user_id)
         DO UPDATE SET site_id = $3, latitude = $4, longitude = $5, updated_at = NOW()
         RETURNING *`,
        [tenant_id, user_id, site_id || null, latitude, longitude]
      );
      await client.query(
        `INSERT INTO guard_location_history (tenant_id, user_id, site_id, latitude, longitude)
         VALUES ($1, $2, $3, $4, $5)`,
        [tenant_id, user_id, site_id || null, latitude, longitude]
      );
      return upserted.rows[0];
    });
    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/guard-locations', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client =>
      client.query(
        `SELECT gl.*, u.email as guard_email, s.name as site_name
         FROM guard_locations gl
         JOIN users u ON u.id = gl.user_id
         LEFT JOIN sites s ON s.id = gl.site_id
         WHERE gl.tenant_id = $1
         ORDER BY gl.updated_at DESC`,
        [tenant_id]
      )
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/guard-locations/history', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, user_id, hours } = req.query;
  if (!tenant_id || !user_id) return res.status(400).json({ error: 'tenant_id and user_id query params are required' });
  let hoursNum = hours ? Number(hours) : 12;
  if (!Number.isFinite(hoursNum) || hoursNum <= 0) hoursNum = 12;
  if (hoursNum > LOCATION_HISTORY_RETENTION_HOURS) hoursNum = LOCATION_HISTORY_RETENTION_HOURS;

  try {
    const cutoff = new Date(Date.now() - hoursNum * 3600000);
    const result = await withTenant(tenant_id, client =>
      client.query(
        `SELECT glh.*, s.name as site_name
         FROM guard_location_history glh
         LEFT JOIN sites s ON s.id = glh.site_id
         WHERE glh.tenant_id = $1 AND glh.user_id = $2 AND glh.recorded_at >= $3
         ORDER BY glh.recorded_at ASC`,
        [tenant_id, user_id, cutoff]
      )
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/client-users', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, email, password } = req.body;
  if (!tenant_id || !site_id || !email || !password) return res.status(400).json({ error: 'tenant_id, site_id, email, and password are required' });
  if (password.length < 6) return res.status(400).json({ error: 'password must be at least 6 characters' });
  try {
    const result = await withTenant(tenant_id, async client => {
      const siteCheck = await client.query('SELECT id FROM sites WHERE id = $1 AND tenant_id = $2', [site_id, tenant_id]);
      if (siteCheck.rows.length === 0) {
        const err = new Error('Site not found for this tenant');
        err.statusCode = 404;
        throw err;
      }

      const limitCheck = await checkPlanLimit(client, tenant_id, 'client_accounts');
      if (!limitCheck.allowed) {
        const err = new Error(`Your ${limitCheck.plan} plan allows up to ${limitCheck.max} client portal account(s). Upgrade your plan to add more.`);
        err.statusCode = 403;
        throw err;
      }

      const hash = await bcrypt.hash(password, 10);
      return client.query(
        'INSERT INTO client_users (tenant_id, site_id, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, tenant_id, site_id, email, created_at',
        [tenant_id, site_id, email.toLowerCase().trim(), hash]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A client account with this email already exists for this tenant' });
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/client-users', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client =>
      site_id
        ? client.query(
            `SELECT cu.id, cu.tenant_id, cu.site_id, cu.email, cu.created_at, s.name as site_name
             FROM client_users cu JOIN sites s ON s.id = cu.site_id
             WHERE cu.tenant_id = $1 AND cu.site_id = $2 ORDER BY cu.created_at DESC`,
            [tenant_id, site_id]
          )
        : client.query(
            `SELECT cu.id, cu.tenant_id, cu.site_id, cu.email, cu.created_at, s.name as site_name
             FROM client_users cu JOIN sites s ON s.id = cu.site_id
             WHERE cu.tenant_id = $1 ORDER BY cu.created_at DESC`,
            [tenant_id]
          )
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/client-users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client =>
      client.query('DELETE FROM client_users WHERE id = $1 AND tenant_id = $2 RETURNING id, email', [id, tenant_id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Client account not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/client-users/:id/reset-password', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, new_password } = req.body;
  if (!tenant_id || !new_password) return res.status(400).json({ error: 'tenant_id and new_password are required' });
  if (new_password.length < 6) return res.status(400).json({ error: 'new_password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(new_password, 10);
    const result = await withTenant(tenant_id, client =>
      client.query('UPDATE client_users SET password_hash = $1 WHERE id = $2 AND tenant_id = $3 RETURNING id, email', [hash, id, tenant_id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Client account not found' });
    res.json({ reset: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/clients/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
  const normalizedEmail = email.toLowerCase().trim();
  try {
    const tenantsRes = await pool.query('SELECT id FROM tenants');
    for (const t of tenantsRes.rows) {
      const result = await withTenant(t.id, client =>
        client.query('SELECT * FROM client_users WHERE tenant_id = $1 AND LOWER(email) = $2', [t.id, normalizedEmail])
      );
      if (result.rows.length > 0) {
        const candidate = result.rows[0];
        const valid = await bcrypt.compare(password, candidate.password_hash);
        if (valid) {
          const token = jwt.sign({ client_user_id: candidate.id, tenant_id: t.id, site_id: candidate.site_id, role: 'client' }, JWT_SECRET, { expiresIn: '12h' });
          const siteRes = await withTenant(t.id, client => client.query('SELECT name FROM sites WHERE id = $1 AND tenant_id = $2', [candidate.site_id, t.id]));
          return res.json({ token, client: { id: candidate.id, email: candidate.email }, tenant_id: t.id, site_id: candidate.site_id, site_name: siteRes.rows[0] ? siteRes.rows[0].name : null });
        }
      }
    }
    return res.status(401).json({ error: 'Invalid email or password' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/client-portal/compliance', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  try {
    const compliance = await withTenant(tenant_id, client => computeSiteCompliance(client, tenant_id, site_id));
    res.json(compliance);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/client-portal/incidents', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  const { date } = req.query;
  try {
    const result = await withTenant(tenant_id, client =>
      date
        ? client.query(
            `SELECT i.description, i.severity, i.reported_at, COALESCE(p.photo_count, 0) as photo_count
             FROM incidents i
             LEFT JOIN (
               SELECT incident_id, COUNT(*) AS photo_count FROM incident_photos WHERE tenant_id = $1 GROUP BY incident_id
             ) p ON p.incident_id = i.id
             WHERE i.tenant_id = $1 AND i.site_id = $2 AND i.reported_at::date = $3
             ORDER BY i.reported_at DESC`,
            [tenant_id, site_id, date]
          )
        : client.query(
            `SELECT i.description, i.severity, i.reported_at, COALESCE(p.photo_count, 0) as photo_count
             FROM incidents i
             LEFT JOIN (
               SELECT incident_id, COUNT(*) AS photo_count FROM incident_photos WHERE tenant_id = $1 GROUP BY incident_id
             ) p ON p.incident_id = i.id
             WHERE i.tenant_id = $1 AND i.site_id = $2
             ORDER BY i.reported_at DESC LIMIT 200`,
            [tenant_id, site_id]
          )
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/client-portal/site-info', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  try {
    const result = await withTenant(tenant_id, client =>
      client.query(
        `SELECT s.name as site_name, s.address, t.name as tenant_name
         FROM sites s JOIN tenants t ON t.id = s.tenant_id
         WHERE s.id = $1 AND s.tenant_id = $2`,
        [site_id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Site not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/client-portal/reports/compliance-pdf', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  const { start_date, end_date } = req.query;
  if (!start_date || !end_date) return res.status(400).json({ error: 'start_date and end_date are required' });
  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, client => fetchReportData(client, tenant_id, site_id, startDt, endDt));
    const startLabel = startDt.toFormat('dd LLL yyyy');
    const endLabel = endDt.toFormat('dd LLL yyyy');
    const filename = 'compliance-report-' + safeFilenamePart(reportData.siteName) + '-' + startDt.toFormat('yyyy-MM-dd') + '.pdf';
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    doc.pipe(res);
    drawReportHeader(doc, reportData.tenantName, reportData.siteName, startLabel, endLabel);
    drawSectionTitle(doc, 'Summary');
    drawSummaryStats(doc, reportData.stats);
    drawSectionTitle(doc, 'Checkpoint Activity');
    if (reportData.perCheckpoint.length === 0) {
      doc.fontSize(10).fillColor('#6b7280').text('No checkpoints configured for this site.');
    } else {
      const colX = { name: 50, location: 220, scans: 370, lastScan: 430 };
      const headerY = doc.y;
      doc.fontSize(9).fillColor('#374151');
      doc.text('Checkpoint', colX.name, headerY);
      doc.text('Location', colX.location, headerY);
      doc.text('Scans', colX.scans, headerY);
      doc.text('Last Scan', colX.lastScan, headerY);
      doc.moveDown(0.3);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#e5e7eb').stroke();
      doc.moveDown(0.3);
      reportData.perCheckpoint.forEach(cp => {
        if (doc.y > 720) { doc.addPage(); doc.y = 50; }
        const rowY = doc.y;
        doc.fontSize(9).fillColor(cp.scanCount === 0 ? '#dc2626' : '#111827');
        doc.text(cp.name, colX.name, rowY, { width: 165 });
        doc.fillColor('#6b7280').text(cp.location, colX.location, rowY, { width: 140 });
        doc.fillColor(cp.scanCount === 0 ? '#dc2626' : '#111827').text(String(cp.scanCount), colX.scans, rowY, { width: 50 });
        doc.fillColor('#6b7280').text(cp.lastScan ? DateTime.fromJSDate(new Date(cp.lastScan)).setZone(reportData.timezone).toFormat('dd LLL, HH:mm') : 'Not scanned', colX.lastScan, rowY, { width: 110 });
        doc.moveDown(0.6);
      });
    }

    doc.moveDown(1);
    if (doc.y > 680) { doc.addPage(); doc.y = 50; }
    drawSectionTitle(doc, 'Incidents Reported (' + reportData.incidents.length + ')');
    if (reportData.incidents.length === 0) {
      doc.fontSize(10).fillColor('#16a34a').text('No incidents reported during this period.');
    } else {
      reportData.incidents.forEach(inc => {
        if (doc.y > 700) { doc.addPage(); doc.y = 50; }
        const dateLabel = DateTime.fromJSDate(new Date(inc.reported_at)).setZone(reportData.timezone).toFormat('dd LLL yyyy, HH:mm');
        doc.fontSize(9).fillColor(severityColor(inc.severity)).text('[' + inc.severity.toUpperCase() + '] ' + dateLabel, { continued: false });
        doc.fontSize(10).fillColor('#111827').text(inc.description, { width: 495 });
        if (inc.guard_email) doc.fontSize(8).fillColor('#9ca3af').text('Reported by: ' + inc.guard_email);
        doc.moveDown(0.6);
      });
    }
    doc.end();
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/client-portal/reports/compliance-csv', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  const { start_date, end_date } = req.query;
  if (!start_date || !end_date) return res.status(400).json({ error: 'start_date and end_date are required' });
  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, client => fetchReportData(client, tenant_id, site_id, startDt, endDt));
    const rows = reportData.logs.map(log => {
      const cp = reportData.checkpointLookup[log.checkpoint_id] || {};
      const scannedLocal = DateTime.fromJSDate(new Date(log.scanned_at)).setZone(reportData.timezone);
      return [reportData.siteName, cp.name || 'Checkpoint #' + log.checkpoint_id, [cp.building, cp.floor].filter(Boolean).join(' / ') || '', log.guard_email || '', scannedLocal.toFormat('yyyy-MM-dd'), scannedLocal.toFormat('HH:mm:ss'), log.latitude ?? '', log.longitude ?? ''];
    });
    const csv = buildCsv(['Site', 'Checkpoint', 'Location', 'Guard Email', 'Date', 'Time', 'Latitude', 'Longitude'], rows);
    const filename = 'scan-log-' + safeFilenamePart(reportData.siteName) + '-' + startDt.toFormat('yyyy-MM-dd') + '.csv';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send('\uFEFF' + csv);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/client-portal/reports/incidents-csv', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  const { start_date, end_date } = req.query;
  if (!start_date || !end_date) return res.status(400).json({ error: 'start_date and end_date are required' });
  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, client => fetchReportData(client, tenant_id, site_id, startDt, endDt));
    const rows = reportData.incidents.map(inc => {
      const reportedLocal = DateTime.fromJSDate(new Date(inc.reported_at)).setZone(reportData.timezone);
      return [reportData.siteName, reportedLocal.toFormat('yyyy-MM-dd'), reportedLocal.toFormat('HH:mm:ss'), inc.severity, inc.guard_email || '', inc.description, inc.photo_count];
    });
    const csv = buildCsv(['Site', 'Date', 'Time', 'Severity', 'Guard Email', 'Description', 'Photo Count'], rows);
    const filename = 'incidents-' + safeFilenamePart(reportData.siteName) + '-' + startDt.toFormat('yyyy-MM-dd') + '.csv';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send('\uFEFF' + csv);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.post('/api/shifts', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, user_id, start_date, start_time, end_time, employment_type, recurrence, repeat_until, days_of_week, notes } = req.body;
  if (!tenant_id || !site_id || !user_id || !start_date || !start_time || !end_time) {
    return res.status(400).json({ error: 'tenant_id, site_id, user_id, start_date, start_time, and end_time are required' });
  }

  const validEmploymentType = employment_type === 'part_time' ? 'part_time' : 'full_time';
  const validRecurrence = ['none', 'weekly', 'monthly'].includes(recurrence) ? recurrence : 'none';
  const start = DateTime.fromISO(`${start_date}T${start_time}`);
  if (!start.isValid) return res.status(400).json({ error: 'Invalid shift start date/time' });

  const buildShiftDates = () => {
    const dates = [];
    if (validRecurrence === 'none') {
      dates.push(start.toISODate());
      return dates;
    }
    const until = DateTime.fromISO(repeat_until);
    if (!until.isValid) return null;
    if (validRecurrence === 'weekly') {
      if (!Array.isArray(days_of_week) || days_of_week.length === 0) return null;
      let cursor = DateTime.fromISO(start_date).startOf('day');
      const endCursor = until.endOf('day');
      while (cursor <= endCursor) {
        if (days_of_week.map(Number).includes(cursor.weekday % 7)) dates.push(cursor.toISODate());
        cursor = cursor.plus({ days: 1 });
      }
    } else if (validRecurrence === 'monthly') {
      let cursor = DateTime.fromISO(start_date).startOf('day');
      const endCursor = until.endOf('day');
      const targetDay = DateTime.fromISO(start_date).day;
      while (cursor <= endCursor) {
        if (cursor.day === targetDay) dates.push(cursor.toISODate());
        cursor = cursor.plus({ days: 1 });
      }
    }
    return dates;
  };

  try {
    const dates = buildShiftDates();
    if (dates === null || dates.length === 0) return res.status(400).json({ error: 'No shift dates generated. Check recurrence settings.' });

    const result = await withTenant(tenant_id, async client => {
      const exists = await client.query('SELECT id FROM users WHERE tenant_id = $1 AND id = $2 AND role = $3', [tenant_id, user_id, 'guard']);
      if (exists.rows.length === 0) {
        const err = new Error('Guard not found for this tenant');
        err.statusCode = 404;
        throw err;
      }
      const siteExists = await client.query('SELECT id FROM sites WHERE tenant_id = $1 AND id = $2', [tenant_id, site_id]);
      if (siteExists.rows.length === 0) {
        const err = new Error('Site not found for this tenant');
        err.statusCode = 404;
        throw err;
      }
      const recurrenceGroupId = validRecurrence === 'none' ? null : `shiftgrp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      const created = [];
      for (const shiftDate of dates) {
        const inserted = await client.query(
          `INSERT INTO shifts (tenant_id, site_id, user_id, shift_date, start_time, end_time, employment_type, recurrence, recurrence_group_id, notes)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
          [tenant_id, site_id, user_id, shiftDate, start_time, end_time, validEmploymentType, validRecurrence, recurrenceGroupId, notes || null]
        );
        created.push(inserted.rows[0]);
      }
      return created;
    });

    res.status(201).json({ created_count: result.length, shifts: result });
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/shifts', requireAuth, async (req, res) => {
  const { tenant_id, user_id, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client => {
      let query = `
        SELECT sh.*, u.email as guard_email, s.name as site_name,
          CASE
            WHEN sh.end_time > sh.start_time THEN
              ROUND(EXTRACT(EPOCH FROM (TO_TIMESTAMP(sh.end_time, 'HH24:MI') - TO_TIMESTAMP(sh.start_time, 'HH24:MI'))) / 3600.0, 2)
            ELSE
              ROUND(EXTRACT(EPOCH FROM ((TO_TIMESTAMP('23:59', 'HH24:MI') - TO_TIMESTAMP(sh.start_time, 'HH24:MI')) +
              (TO_TIMESTAMP(sh.end_time, 'HH24:MI') - TO_TIMESTAMP('00:00', 'HH24:MI')))) / 3600.0, 2)
          END as duration_hours
        FROM shifts sh
        JOIN users u ON u.id = sh.user_id
        JOIN sites s ON s.id = sh.site_id
        WHERE sh.tenant_id = $1
      `;
      const params = [tenant_id];
      if (user_id) { params.push(user_id); query += ` AND sh.user_id = $${params.length}`; }
      if (site_id) { params.push(site_id); query += ` AND sh.site_id = $${params.length}`; }
      query += ' ORDER BY sh.shift_date ASC, sh.start_time ASC';
      return client.query(query, params);
    });
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/shifts/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, shift_date, start_time, end_time, employment_type, notes } = req.body;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id is required' });
  try {
    const result = await withTenant(tenant_id, client =>
      client.query(
        `UPDATE shifts
         SET shift_date = COALESCE($1, shift_date),
             start_time = COALESCE($2, start_time),
             end_time = COALESCE($3, end_time),
             employment_type = COALESCE($4, employment_type),
             notes = COALESCE($5, notes)
         WHERE id = $6 AND tenant_id = $7
         RETURNING *`,
        [shift_date || null, start_time || null, end_time || null, employment_type || null, notes || null, id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/shifts/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client => client.query('DELETE FROM shifts WHERE id = $1 AND tenant_id = $2 RETURNING *', [id, tenant_id]));
    if (result.rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/shifts/series/:groupId', requireAuth, requireAdmin, async (req, res) => {
  const { groupId } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client => client.query(
      `DELETE FROM shifts WHERE tenant_id = $1 AND recurrence_group_id = $2 AND shift_date >= CURRENT_DATE RETURNING *`,
      [tenant_id, groupId]
    ));
    res.json({ deleted_count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/incidents', requireAuth, async (req, res) => {
  const { tenant_id, site_id, checkpoint_id, description, severity, photos } = req.body;
  const user_id = req.auth.user_id;
  if (!tenant_id || !site_id || !description) {
    return res.status(400).json({ error: 'tenant_id, site_id, and description are required' });
  }

  const photoList = Array.isArray(photos) ? photos.slice(0, MAX_PHOTOS_PER_INCIDENT) : [];
  for (const p of photoList) {
    if (typeof p !== 'string' || p.length === 0) return res.status(400).json({ error: 'Each photo must be a non-empty base64 data URL string' });
    if (p.length > MAX_PHOTO_BASE64_LENGTH) return res.status(400).json({ error: 'One or more photos are too large. Please retake at a lower quality.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET app.current_tenant = '${tenant_id}'`);
    const incidentResult = await client.query('INSERT INTO incidents (tenant_id, site_id, checkpoint_id, user_id, description, severity) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [tenant_id, site_id, checkpoint_id || null, user_id, description, severity || 'low']);
    const incident = incidentResult.rows[0];
    for (const photoData of photoList) {
      await client.query('INSERT INTO incident_photos (tenant_id, incident_id, photo_data) VALUES ($1, $2, $3)', [tenant_id, incident.id, photoData]);
    }
    await client.query('COMMIT');
    res.status(201).json({ ...incident, photo_count: photoList.length });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/incidents', requireAuth, async (req, res) => {
  const { tenant_id, date } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client => {
      const baseQuery = `
        SELECT i.*, COALESCE(p.photo_count, 0) AS photo_count
        FROM incidents i
        LEFT JOIN (
          SELECT incident_id, COUNT(*) AS photo_count
          FROM incident_photos
          WHERE tenant_id = $1
          GROUP BY incident_id
        ) p ON p.incident_id = i.id
        WHERE i.tenant_id = $1
      `;
      return date ? client.query(baseQuery + ' AND i.reported_at::date = $2 ORDER BY i.reported_at DESC', [tenant_id, date]) : client.query(baseQuery + ' ORDER BY i.reported_at DESC', [tenant_id]);
    });
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/incidents/:id/photos', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client => client.query('SELECT id, photo_data, created_at FROM incident_photos WHERE incident_id = $1 AND tenant_id = $2 ORDER BY created_at ASC', [id, tenant_id]));
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/incidents/:id/photos', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, client => client.query('DELETE FROM incident_photos WHERE incident_id = $1 AND tenant_id = $2 RETURNING id', [id, tenant_id]));
    res.json({ deleted_count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`PatrolSync backend running on port ${PORT}`);
});
