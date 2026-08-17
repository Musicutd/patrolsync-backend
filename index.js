const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { DateTime } = require('luxon');
const QRCode = require('qrcode');
const PDFDocument = require('pdfkit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '12mb' }));

const databaseSsl = { rejectUnauthorized: false };
const systemDatabaseUrl = process.env.SYSTEM_DATABASE_URL || process.env.DATABASE_URL;
const tenantDatabaseUrl = process.env.TENANT_DATABASE_URL || process.env.DATABASE_URL;
const systemPool = new Pool({ connectionString: systemDatabaseUrl, ssl: databaseSsl });
// Existing direct database work remains on the trusted system path. Tenant-scoped
// work uses tenantPool through withTenant(). Until TENANT_DATABASE_URL is supplied,
// both names intentionally share one pool so this deployment remains compatible.
const tenantPool = tenantDatabaseUrl === systemDatabaseUrl
  ? systemPool
  : new Pool({ connectionString: tenantDatabaseUrl, ssl: databaseSsl });
const pool = systemPool;
const DATABASE_PATHS_SEPARATED = tenantPool !== systemPool;

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'patrolsync-dev-secret';
const FIXED_WINDOW_MINUTES = 30;
const ALERT_SWEEP_INTERVAL_MS = 5 * 60 * 1000;
const LOCATION_HISTORY_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const LOCATION_HISTORY_RETENTION_HOURS = 48;
const MAX_PHOTOS_PER_INCIDENT = 3;
const MAX_PHOTO_BASE64_LENGTH = 3 * 1024 * 1024;
const APP_STARTED_AT = new Date();
const REQUEST_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const AUTH_REQUEST_LIMIT = Number(process.env.AUTH_REQUEST_LIMIT || 20);
const API_KEY_REQUEST_LIMIT = Number(process.env.API_KEY_REQUEST_LIMIT || 300);
const AUDIT_RETENTION_DAYS = Number(process.env.AUDIT_RETENTION_DAYS || 365);
const WEBHOOK_RETENTION_DAYS = Number(process.env.WEBHOOK_RETENTION_DAYS || 90);
const requestWindows = new Map();

function requestIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim(); }
function fixedWindowRateLimit(name, limit) {
  return (req, res, next) => {
    const now = Date.now(), key = `${name}:${requestIp(req)}`;
    let state = requestWindows.get(key);
    if (!state || now >= state.resetAt) state = { count: 0, resetAt: now + REQUEST_LIMIT_WINDOW_MS };
    state.count += 1; requestWindows.set(key, state);
    res.setHeader('X-RateLimit-Limit', String(limit)); res.setHeader('X-RateLimit-Remaining', String(Math.max(0, limit-state.count))); res.setHeader('X-RateLimit-Reset', String(Math.ceil(state.resetAt/1000)));
    if (state.count > limit) { res.setHeader('Retry-After', String(Math.ceil((state.resetAt-now)/1000))); return res.status(429).json({error:'Too many requests. Please wait and try again.',request_id:req.requestId}); }
    next();
  };
}
app.use((req,res,next)=>{
  req.requestId=String(req.headers['x-request-id']||crypto.randomUUID()).slice(0,100);req.requestStartedAt=Date.now();
  res.setHeader('X-Request-ID',req.requestId);res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');
  res.on('finish',()=>{if(res.statusCode>=500)console.error(JSON.stringify({level:'error',type:'http_5xx',request_id:req.requestId,method:req.method,path:req.path,status:res.statusCode,duration_ms:Date.now()-req.requestStartedAt}))});next();
});
app.use(['/api/auth/login','/api/client-auth/login'],fixedWindowRateLimit('login',AUTH_REQUEST_LIMIT));
app.use('/api/public/v1',fixedWindowRateLimit('integration-api',API_KEY_REQUEST_LIMIT));

const PLAN_LIMITS = {
  starter:    { locations: 1,        checkpoints: 10,       guards: 3,        client_accounts: 1,        monthly_price: 39,  overage: null },
  medium:     { locations: 1,        checkpoints: 20,       guards: 6,        client_accounts: 2,        monthly_price: 79,  overage: null },
  pro:        { locations: 2,        checkpoints: 50,       guards: 10,       client_accounts: 5,        monthly_price: 149, overage: null },
  diamond:    { locations: 3,        checkpoints: 100,      guards: 15,       client_accounts: 10,       monthly_price: 299, overage: null },
  enterprise: { locations: Infinity, checkpoints: Infinity, guards: Infinity, client_accounts: Infinity, monthly_price: 499, overage: { location: 80, checkpoint: 10, guard: 15, client_account: 20 } }
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
  const normalizedTenantId = Number(tenantId);
  if (!Number.isInteger(normalizedTenantId) || normalizedTenantId < 1) {
    const err = new Error('A valid tenant ID is required');
    err.statusCode = 400;
    throw err;
  }
  const client = await tenantPool.connect();
  let resetError = null;
  try {
    await client.query(`SELECT set_config('app.current_tenant',$1,false)`, [String(normalizedTenantId)]);
    return await fn(client);
  } finally {
    try { await client.query('RESET app.current_tenant'); }
    catch (err) { resetError = err; console.error('Tenant database context reset failed:', err.message); }
    client.release(resetError || undefined);
  }
}

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    if(req.auth.role==='client')return next();
    const check=await pool.query(`SELECT account_active,password_changed_at FROM users WHERE id=$1 AND tenant_id=$2`,[req.auth.user_id,req.auth.tenant_id]);
    if(!check.rowCount||check.rows[0].account_active===false)return res.status(401).json({error:'Account disabled or removed'});
    const changed=check.rows[0].password_changed_at?new Date(check.rows[0].password_changed_at).getTime():0,issued=Number(req.auth.iat||0)*1000;
    if(changed&&issued<changed-1000)return res.status(401).json({error:'Session expired after a security change. Please log in again.'});
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function permissionForPath(path=''){const rules=[['/api/dispatch','dispatch'],['/api/lone-worker','safety'],['/api/attendance','attendance'],['/api/timesheet','attendance'],['/api/shift','scheduling'],['/api/patrol','patrols'],['/api/checkpoint','patrols'],['/api/incident','incidents'],['/api/training','training'],['/api/certification','training'],['/api/assets','assets'],['/api/asset-custody','assets'],['/api/inspection','quality'],['/api/corrective','quality'],['/api/invoice','finance'],['/api/analytics','analytics'],['/api/service-contract','clients'],['/api/client-report','clients'],['/api/client-users','clients'],['/api/team-','communications'],['/api/communication-notifications','communications']];const found=rules.find(([prefix])=>path.startsWith(prefix));return found?found[1]:'administration';}
async function requireAdmin(req,res,next){if(!req.auth)return res.status(403).json({error:'Admin access required'});if(req.auth.role==='admin')return next();if(req.auth.role!=='staff')return res.status(403).json({error:'Admin access required'});try{const r=await pool.query(`SELECT permissions,account_active FROM users WHERE id=$1 AND tenant_id=$2 AND role='staff'`,[req.auth.user_id,req.auth.tenant_id]);if(!r.rowCount||r.rows[0].account_active===false)return res.status(403).json({error:'Staff account disabled'});const permissions=r.rows[0].permissions||[];if(req.method==='GET'&&['/api/users','/api/sites'].includes(req.path)){req.auth.permissions=permissions;return next();}const needed=permissionForPath(req.path);if(needed==='administration'||!permissions.includes(needed))return res.status(403).json({error:`Permission required: ${needed}`});req.auth.permissions=permissions;next()}catch(e){res.status(500).json({error:'Could not verify staff permissions'});}}
function requireOwnerAdmin(req,res,next){if(!req.auth||req.auth.role!=='admin')return res.status(403).json({error:'Company administrator access required'});next();}

function requireClient(req, res, next) {
  if (!req.auth || req.auth.role !== 'client') {
    return res.status(403).json({ error: 'Client access required' });
  }
  next();
}

function safeAuditDetails(body) {
  if (!body || typeof body !== 'object') return {};
  const hidden = new Set(['password', 'token', 'photo_base64', 'photos']);
  return Object.fromEntries(Object.entries(body).filter(([key]) => !hidden.has(key.toLowerCase())));
}

app.use((req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  res.on('finish', () => {
    if (!req.auth || res.statusCode >= 400 || req.path === '/api/login' || req.path === '/api/signup') return;
    const tenantId = Number((req.body && req.body.tenant_id) || req.query.tenant_id || req.auth.tenant_id);
    if (!Number.isInteger(tenantId) || tenantId !== Number(req.auth.tenant_id)) return;
    const routeName = req.route && req.route.path ? req.route.path : req.path;
    pool.query(
      `INSERT INTO audit_logs (tenant_id,user_id,user_email,user_role,action,resource,entity_id,details,ip_address)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [tenantId, req.auth.user_id, req.auth.email || null, req.auth.role, req.method, routeName,
       req.params && req.params.id ? String(req.params.id) : null, safeAuditDetails(req.body),
       String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim() || null]
    ).then(() => queueWebhookEvent(tenantId, `${req.method} ${routeName}`, { entity_id:req.params&&req.params.id?String(req.params.id):null, details:safeAuditDetails(req.body) }))
     .catch(err => console.error('Audit/webhook event write failed:', err.message));
  });
  next();
});

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

// ------------------------ SCHEMA HELPERS ------------------------

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
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS reference_code TEXT`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'general'`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'reported'`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_to INTEGER`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolution TEXT`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_reference ON incidents(tenant_id,reference_code) WHERE reference_code IS NOT NULL`);
  await pool.query(`CREATE TABLE IF NOT EXISTS incident_activities (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    user_id INTEGER,activity_type TEXT NOT NULL,note TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_incident_activities_incident ON incident_activities(tenant_id,incident_id,created_at)`);
  console.log('Incidents table ready');
}
ensureIncidentsTable();

async function ensureHandoverTable(){
  await pool.query(`CREATE TABLE IF NOT EXISTS handover_logs (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,from_user_id INTEGER NOT NULL,
    to_user_id INTEGER,summary TEXT NOT NULL,outstanding_actions TEXT,equipment_status TEXT NOT NULL DEFAULT 'ok',
    status TEXT NOT NULL DEFAULT 'pending',acknowledged_by INTEGER,acknowledged_at TIMESTAMPTZ,
    resolved_by INTEGER,resolved_at TIMESTAMPTZ,resolution_notes TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_handover_tenant_site_status ON handover_logs(tenant_id,site_id,status,created_at DESC)`);
  console.log('Handover table ready');
}
ensureHandoverTable();

async function ensureServiceContractsTable(){
  await pool.query(`CREATE TABLE IF NOT EXISTS service_contracts (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,reference_code TEXT NOT NULL,
    client_name TEXT NOT NULL,start_date DATE NOT NULL,end_date DATE,status TEXT NOT NULL DEFAULT 'draft',
    billing_model TEXT NOT NULL DEFAULT 'monthly',rate NUMERIC(12,2),currency TEXT NOT NULL DEFAULT 'EUR',
    sla_patrol_completion_pct NUMERIC(5,2) NOT NULL DEFAULT 95,
    sla_incident_ack_minutes INTEGER NOT NULL DEFAULT 15,sla_shift_coverage_pct NUMERIC(5,2) NOT NULL DEFAULT 98,
    report_frequency TEXT NOT NULL DEFAULT 'monthly',notes TEXT,created_by INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,reference_code)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_contracts_tenant_site_status ON service_contracts(tenant_id,site_id,status)`);
  console.log('Service contracts table ready');
}
ensureServiceContractsTable();

async function ensureClientReportAutomationTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS client_report_schedules (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,contract_id BIGINT NOT NULL REFERENCES service_contracts(id) ON DELETE CASCADE,
    recipient_email TEXT NOT NULL,frequency TEXT NOT NULL,next_run_date DATE NOT NULL,active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(contract_id,recipient_email)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS client_report_runs (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,schedule_id BIGINT REFERENCES client_report_schedules(id) ON DELETE SET NULL,
    contract_id BIGINT NOT NULL REFERENCES service_contracts(id),period_start DATE NOT NULL,period_end DATE NOT NULL,
    recipient_email TEXT,status TEXT NOT NULL DEFAULT 'generated',generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,delivered_by INTEGER,delivery_notes TEXT,UNIQUE(schedule_id,period_start,period_end)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_report_schedules_due ON client_report_schedules(active,next_run_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_report_runs_tenant_generated ON client_report_runs(tenant_id,generated_at DESC)`);
  console.log('Client report automation tables ready');
}
ensureClientReportAutomationTables();

async function ensureBillingTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS invoices (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,contract_id BIGINT NOT NULL REFERENCES service_contracts(id),
    invoice_number TEXT NOT NULL,period_start DATE NOT NULL,period_end DATE NOT NULL,issue_date DATE,due_date DATE,
    status TEXT NOT NULL DEFAULT 'draft',currency TEXT NOT NULL DEFAULT 'EUR',subtotal NUMERIC(12,2) NOT NULL DEFAULT 0,
    tax_rate NUMERIC(5,2) NOT NULL DEFAULT 0,tax_amount NUMERIC(12,2) NOT NULL DEFAULT 0,total NUMERIC(12,2) NOT NULL DEFAULT 0,
    amount_paid NUMERIC(12,2) NOT NULL DEFAULT 0,notes TEXT,created_by INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,invoice_number),UNIQUE(contract_id,period_start,period_end)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS invoice_lines (
    id BIGSERIAL PRIMARY KEY,invoice_id BIGINT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,description TEXT NOT NULL,
    quantity NUMERIC(12,2) NOT NULL,unit_rate NUMERIC(12,2) NOT NULL,line_total NUMERIC(12,2) NOT NULL
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS invoice_payments (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,invoice_id BIGINT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    amount NUMERIC(12,2) NOT NULL,payment_date DATE NOT NULL,method TEXT,reference TEXT,notes TEXT,recorded_by INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_invoices_tenant_status_due ON invoices(tenant_id,status,due_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_invoice_payments_invoice ON invoice_payments(invoice_id,payment_date)`);
  console.log('Billing tables ready');
}
ensureBillingTables();

async function ensureServiceTicketTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS service_tickets (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,client_user_id INTEGER,
    reference_code TEXT NOT NULL,request_type TEXT NOT NULL DEFAULT 'general',subject TEXT NOT NULL,description TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'normal',status TEXT NOT NULL DEFAULT 'open',assigned_to INTEGER,
    resolution TEXT,resolved_at TIMESTAMPTZ,closed_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,reference_code)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS service_ticket_comments (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,ticket_id BIGINT NOT NULL REFERENCES service_tickets(id) ON DELETE CASCADE,
    author_type TEXT NOT NULL,author_user_id INTEGER,author_client_user_id INTEGER,comment TEXT NOT NULL,internal BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_service_tickets_queue ON service_tickets(tenant_id,status,priority,updated_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_service_ticket_comments ON service_ticket_comments(ticket_id,created_at)`);
  console.log('Service ticket tables ready');
}
ensureServiceTicketTables();

async function ensureContractRenewalTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS contract_renewals (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,contract_id BIGINT NOT NULL REFERENCES service_contracts(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'not_started',owner_user_id INTEGER,proposed_start_date DATE,proposed_end_date DATE,
    proposed_rate NUMERIC(12,2),proposed_currency TEXT,notes TEXT,last_contact_at TIMESTAMPTZ,next_follow_up_date DATE,
    completed_contract_id BIGINT REFERENCES service_contracts(id),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(contract_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS contract_renewal_history (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,renewal_id BIGINT NOT NULL REFERENCES contract_renewals(id) ON DELETE CASCADE,
    action TEXT NOT NULL,note TEXT,user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE service_contracts ADD COLUMN IF NOT EXISTS previous_contract_id BIGINT`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_contract_renewals_pipeline ON contract_renewals(tenant_id,status,next_follow_up_date)`);
  console.log('Contract renewal tables ready');
}
ensureContractRenewalTables();

async function ensureEmailDeliveryTable(){
  await pool.query(`CREATE TABLE IF NOT EXISTS email_deliveries (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,event_type TEXT NOT NULL,entity_type TEXT,entity_id BIGINT,
    idempotency_key TEXT NOT NULL,recipient_email TEXT NOT NULL,subject TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'queued',
    provider TEXT,provider_message_id TEXT,payload JSONB NOT NULL DEFAULT '{}'::jsonb,attempt_count INTEGER NOT NULL DEFAULT 0,last_error TEXT,
    sent_at TIMESTAMPTZ,next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(idempotency_key,recipient_email)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_email_delivery_queue ON email_deliveries(status,next_attempt_at)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_email_delivery_tenant ON email_deliveries(tenant_id,created_at DESC)`);
  await pool.query(`ALTER TABLE email_deliveries ADD COLUMN IF NOT EXISTS payload JSONB NOT NULL DEFAULT '{}'::jsonb`);
  console.log('Email delivery table ready');
}
ensureEmailDeliveryTable();

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
  console.log('Incident photos table ready');
}
ensureIncidentPhotosTable();

async function ensureAuthColumn() {
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT`);
  console.log('Auth column ready');
}
ensureAuthColumn();

async function ensureFirebaseUidNullable() {
  await pool.query(`ALTER TABLE users ALTER COLUMN firebase_uid DROP NOT NULL`);
  console.log('firebase_uid is now nullable');
}
ensureFirebaseUidNullable();

async function ensureTimezoneColumn() {
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS timezone TEXT DEFAULT 'UTC'`);
  console.log('Timezone column ready');
}
ensureTimezoneColumn();

async function ensureEmergencyContactColumns() {
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS emergency_phone TEXT`);
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS emergency_whatsapp TEXT`);
  console.log('Emergency contact columns ready');
}
ensureEmergencyContactColumns();

async function ensureSiteGeofenceColumns() {
  await pool.query(`ALTER TABLE sites ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE sites ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE sites ADD COLUMN IF NOT EXISTS geofence_radius_m INTEGER NOT NULL DEFAULT 150`);
  await pool.query(`ALTER TABLE sites ADD COLUMN IF NOT EXISTS geofence_enabled BOOLEAN NOT NULL DEFAULT FALSE`);
  console.log('Site geofence columns ready');
}
ensureSiteGeofenceColumns();

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
  console.log('Notifications table ready');
}
ensureNotificationsTable();

async function ensureCommunicationNotificationsTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS communication_notifications (
      id BIGSERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'general',
      priority TEXT NOT NULL DEFAULT 'normal',
      audience TEXT NOT NULL DEFAULT 'all_guards',
      recipient_user_id INTEGER,
      action_url TEXT,
      requires_acknowledgement BOOLEAN NOT NULL DEFAULT FALSE,
      created_by_user_id INTEGER,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT communication_notification_priority CHECK (priority IN ('low','normal','high','critical')),
      CONSTRAINT communication_notification_audience CHECK (audience IN ('all','admins','all_guards','specific_guard'))
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS communication_notification_receipts (
      notification_id BIGINT NOT NULL REFERENCES communication_notifications(id) ON DELETE CASCADE,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      read_at TIMESTAMPTZ,
      acknowledged_at TIMESTAMPTZ,
      PRIMARY KEY (notification_id, user_id)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_comm_notifications_tenant_created ON communication_notifications(tenant_id,created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_comm_notification_receipts_user ON communication_notification_receipts(tenant_id,user_id)`);
  console.log('Communication notification tables ready');
}
ensureCommunicationNotificationsTables();

async function ensureTeamMessagingTables() {
  await pool.query(`CREATE TABLE IF NOT EXISTS team_conversations (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, title TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'company', guard_user_id INTEGER, created_by_user_id INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT team_conversation_kind CHECK (kind IN ('company','direct'))
  )`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_team_company_channel ON team_conversations(tenant_id) WHERE kind='company'`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_team_direct_channel ON team_conversations(tenant_id,guard_user_id) WHERE kind='direct'`);
  await pool.query(`CREATE TABLE IF NOT EXISTS team_messages (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
    conversation_id BIGINT NOT NULL REFERENCES team_conversations(id) ON DELETE CASCADE,
    sender_user_id INTEGER NOT NULL, sender_role TEXT NOT NULL, message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_team_messages_conversation ON team_messages(tenant_id,conversation_id,created_at)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS team_conversation_reads (
    tenant_id INTEGER NOT NULL, conversation_id BIGINT NOT NULL REFERENCES team_conversations(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL, last_read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(conversation_id,user_id)
  )`);
  console.log('Team messaging tables ready');
}
ensureTeamMessagingTables();

async function ensureLoneWorkerTables() {
  await pool.query(`CREATE TABLE IF NOT EXISTS lone_worker_settings (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, user_id INTEGER NOT NULL, site_id INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE, interval_minutes INTEGER NOT NULL DEFAULT 60,
    grace_minutes INTEGER NOT NULL DEFAULT 10, instructions TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(tenant_id,user_id,site_id),
    CONSTRAINT lone_worker_interval CHECK(interval_minutes BETWEEN 5 AND 720),
    CONSTRAINT lone_worker_grace CHECK(grace_minutes BETWEEN 0 AND 120)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS lone_worker_checkins (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, setting_id BIGINT NOT NULL REFERENCES lone_worker_settings(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL, site_id INTEGER NOT NULL, latitude DOUBLE PRECISION, longitude DOUBLE PRECISION,
    accuracy DOUBLE PRECISION, note TEXT, checked_in_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS lone_worker_alerts (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, setting_id BIGINT NOT NULL REFERENCES lone_worker_settings(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL, site_id INTEGER NOT NULL, due_at TIMESTAMPTZ NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), resolved_at TIMESTAMPTZ
  )`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_lone_worker_open_alert ON lone_worker_alerts(setting_id) WHERE resolved=FALSE`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_lone_worker_checkins_latest ON lone_worker_checkins(tenant_id,setting_id,checked_in_at DESC)`);
  console.log('Lone-worker safety tables ready');
}
ensureLoneWorkerTables();

async function ensureDispatchTables() {
  await pool.query(`CREATE TABLE IF NOT EXISTS dispatch_jobs (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, reference_code TEXT NOT NULL,
    title TEXT NOT NULL, description TEXT, priority TEXT NOT NULL DEFAULT 'normal', status TEXT NOT NULL DEFAULT 'assigned',
    site_id INTEGER, assigned_guard_id INTEGER NOT NULL, address TEXT, latitude DOUBLE PRECISION, longitude DOUBLE PRECISION,
    created_by_user_id INTEGER, assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), accepted_at TIMESTAMPTZ,
    en_route_at TIMESTAMPTZ, on_site_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, completion_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,reference_code), CONSTRAINT dispatch_priority CHECK(priority IN ('low','normal','high','critical')),
    CONSTRAINT dispatch_status CHECK(status IN ('assigned','accepted','en_route','on_site','completed','cancelled'))
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_dispatch_tenant_status ON dispatch_jobs(tenant_id,status,created_at DESC)`);
  console.log('Dispatch tables ready');
}
ensureDispatchTables();

async function ensureTrainingTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS training_materials(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,title TEXT NOT NULL,material_type TEXT NOT NULL,version TEXT NOT NULL DEFAULT '1.0',content TEXT NOT NULL,site_id INTEGER,questions JSONB NOT NULL DEFAULT '[]'::jsonb,passing_score INTEGER NOT NULL DEFAULT 80,active BOOLEAN NOT NULL DEFAULT TRUE,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),CONSTRAINT training_type CHECK(material_type IN ('training','policy','post_order')),CONSTRAINT training_score CHECK(passing_score BETWEEN 0 AND 100))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS training_assignments(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,material_id BIGINT NOT NULL REFERENCES training_materials(id) ON DELETE CASCADE,user_id INTEGER NOT NULL,due_at TIMESTAMPTZ,mandatory BOOLEAN NOT NULL DEFAULT TRUE,status TEXT NOT NULL DEFAULT 'assigned',score INTEGER,attempts INTEGER NOT NULL DEFAULT 0,acknowledged_at TIMESTAMPTZ,completed_at TIMESTAMPTZ,assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(material_id,user_id),CONSTRAINT training_assignment_status CHECK(status IN ('assigned','failed','completed')))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_training_assignments_user ON training_assignments(tenant_id,user_id,status)`);
  console.log('Training and compliance tables ready');
}
ensureTrainingTables();

async function ensureAssetTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS managed_assets(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,asset_type TEXT NOT NULL,name TEXT NOT NULL,asset_code TEXT NOT NULL,site_id INTEGER,status TEXT NOT NULL DEFAULT 'available',condition TEXT NOT NULL DEFAULT 'good',notes TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(tenant_id,asset_code),CONSTRAINT asset_type_check CHECK(asset_type IN ('equipment','key','vehicle','uniform','device','other')),CONSTRAINT asset_status_check CHECK(status IN ('available','issued','maintenance','lost','retired')))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS asset_custody(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,asset_id BIGINT NOT NULL REFERENCES managed_assets(id) ON DELETE CASCADE,user_id INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'issued',issued_by_user_id INTEGER,issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),acknowledged_at TIMESTAMPTZ,return_requested_at TIMESTAMPTZ,returned_at TIMESTAMPTZ,return_condition TEXT,guard_note TEXT,admin_note TEXT,CONSTRAINT custody_status_check CHECK(status IN ('issued','acknowledged','return_requested','returned','reported_lost','reported_damaged')))`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_open_custody ON asset_custody(asset_id) WHERE status<>'returned'`);
  console.log('Asset custody tables ready');
}ensureAssetTables();

async function ensureQualityTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS inspection_templates(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,title TEXT NOT NULL,description TEXT,site_id INTEGER,passing_score INTEGER NOT NULL DEFAULT 80,questions JSONB NOT NULL DEFAULT '[]'::jsonb,active BOOLEAN NOT NULL DEFAULT TRUE,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),CONSTRAINT inspection_passing_score CHECK(passing_score BETWEEN 0 AND 100))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS inspection_runs(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,template_id BIGINT NOT NULL REFERENCES inspection_templates(id) ON DELETE CASCADE,site_id INTEGER NOT NULL,assigned_user_id INTEGER NOT NULL,scheduled_for TIMESTAMPTZ NOT NULL,status TEXT NOT NULL DEFAULT 'scheduled',responses JSONB NOT NULL DEFAULT '[]'::jsonb,score INTEGER,overall_note TEXT,started_at TIMESTAMPTZ,submitted_at TIMESTAMPTZ,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),CONSTRAINT inspection_run_status CHECK(status IN ('scheduled','in_progress','submitted','cancelled')))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS corrective_actions(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,inspection_run_id BIGINT NOT NULL REFERENCES inspection_runs(id) ON DELETE CASCADE,question_index INTEGER,title TEXT NOT NULL,description TEXT,assigned_user_id INTEGER,due_at TIMESTAMPTZ,status TEXT NOT NULL DEFAULT 'open',resolution_note TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),resolved_at TIMESTAMPTZ,CONSTRAINT corrective_status CHECK(status IN ('open','in_progress','resolved','cancelled')))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_inspection_runs_assignee ON inspection_runs(tenant_id,assigned_user_id,status,scheduled_for)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_corrective_actions_status ON corrective_actions(tenant_id,status,due_at)`);
  console.log('Quality inspection tables ready');
}ensureQualityTables();

async function ensureStaffAccessColumns(){await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '[]'::jsonb`);await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS job_title TEXT`);await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS account_active BOOLEAN NOT NULL DEFAULT TRUE`);console.log('Staff access columns ready');}ensureStaffAccessColumns();

async function ensureIntegrationTables(){await pool.query(`CREATE TABLE IF NOT EXISTS integration_api_keys(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,name TEXT NOT NULL,key_prefix TEXT NOT NULL,key_hash TEXT NOT NULL,active BOOLEAN NOT NULL DEFAULT TRUE,last_used_at TIMESTAMPTZ,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE TABLE IF NOT EXISTS webhook_endpoints(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,name TEXT NOT NULL,url TEXT NOT NULL,secret TEXT NOT NULL,event_filter TEXT NOT NULL DEFAULT '*',active BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE TABLE IF NOT EXISTS webhook_deliveries(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,webhook_id BIGINT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,event_type TEXT NOT NULL,payload JSONB NOT NULL,status TEXT NOT NULL DEFAULT 'queued',attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),response_status INTEGER,last_error TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),delivered_at TIMESTAMPTZ)`);await pool.query(`CREATE INDEX IF NOT EXISTS idx_webhook_queue ON webhook_deliveries(status,next_attempt_at)`);console.log('Integration tables ready');}ensureIntegrationTables();

async function ensureOperationsTables(){await pool.query(`CREATE TABLE IF NOT EXISTS system_events(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER,event_type TEXT NOT NULL,severity TEXT NOT NULL DEFAULT 'info',message TEXT NOT NULL,details JSONB NOT NULL DEFAULT '{}'::jsonb,request_id TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE INDEX IF NOT EXISTS idx_system_events_tenant_created ON system_events(tenant_id,created_at DESC)`);console.log('Operations monitoring table ready');}ensureOperationsTables();

async function ensureSecurityRecoveryTables(){await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ`);await pool.query(`CREATE TABLE IF NOT EXISTS password_reset_tokens(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,user_id INTEGER NOT NULL,token_hash TEXT NOT NULL UNIQUE,expires_at TIMESTAMPTZ NOT NULL,used_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_reset_expiry ON password_reset_tokens(expires_at) WHERE used_at IS NULL`);console.log('Security and recovery tables ready');}ensureSecurityRecoveryTables();

async function ensureAuditLogsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER,
      user_email TEXT,
      user_role TEXT,
      action TEXT NOT NULL,
      resource TEXT NOT NULL,
      entity_id TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      ip_address TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs(tenant_id,created_at DESC)`);
  console.log('Audit logs table ready');
}
ensureAuditLogsTable();

async function ensurePatrolRoutesTables() {
  await pool.query(`CREATE TABLE IF NOT EXISTS patrol_routes (
    id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, site_id INTEGER NOT NULL,
    name TEXT NOT NULL, description TEXT, strict_order BOOLEAN NOT NULL DEFAULT TRUE,
    estimated_minutes INTEGER, active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,site_id,name)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS patrol_route_checkpoints (
    id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, route_id INTEGER NOT NULL REFERENCES patrol_routes(id) ON DELETE CASCADE,
    checkpoint_id INTEGER NOT NULL, position INTEGER NOT NULL,
    UNIQUE(route_id,checkpoint_id), UNIQUE(route_id,position)
  )`);
  await pool.query(`ALTER TABLE patrol_route_checkpoints ADD COLUMN IF NOT EXISTS instructions TEXT`);
  await pool.query(`ALTER TABLE patrol_route_checkpoints ADD COLUMN IF NOT EXISTS requires_confirmation BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE patrol_route_checkpoints ADD COLUMN IF NOT EXISTS requires_note BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_patrol_routes_tenant_site ON patrol_routes(tenant_id,site_id)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS patrol_runs (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, route_id INTEGER NOT NULL REFERENCES patrol_routes(id),
    site_id INTEGER NOT NULL, user_id INTEGER NOT NULL, scheduled_start TIMESTAMPTZ NOT NULL,
    scheduled_end TIMESTAMPTZ NOT NULL, grace_minutes INTEGER NOT NULL DEFAULT 15,
    status TEXT NOT NULL DEFAULT 'scheduled', notes TEXT, started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ, cancelled_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS patrol_run_scans (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, run_id BIGINT NOT NULL REFERENCES patrol_runs(id) ON DELETE CASCADE,
    checkpoint_id INTEGER NOT NULL, patrol_log_id INTEGER, position INTEGER NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(run_id,checkpoint_id)
  )`);
  await pool.query(`ALTER TABLE patrol_run_scans ADD COLUMN IF NOT EXISTS checkpoint_note TEXT`);
  await pool.query(`ALTER TABLE patrol_run_scans ADD COLUMN IF NOT EXISTS instruction_confirmed BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_patrol_runs_tenant_start ON patrol_runs(tenant_id,scheduled_start)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_patrol_runs_guard_start ON patrol_runs(tenant_id,user_id,scheduled_start)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS patrol_alerts (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, run_id BIGINT NOT NULL REFERENCES patrol_runs(id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', acknowledged_at TIMESTAMPTZ, acknowledged_by INTEGER,
    resolved_at TIMESTAMPTZ, resolved_by INTEGER, resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(run_id,alert_type)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_patrol_alerts_tenant_status ON patrol_alerts(tenant_id,status,created_at DESC)`);
  console.log('Patrol route tables ready');
}
ensurePatrolRoutesTables();

async function ensurePatrolEvidenceColumns() {
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS patrol_run_id BIGINT`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS accuracy_m DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS distance_m DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS location_status TEXT NOT NULL DEFAULT 'unavailable'`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS device_scanned_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_patrol_logs_evidence ON patrol_logs(tenant_id,location_status,scanned_at DESC)`);
  console.log('Patrol scan evidence columns ready');
}
ensurePatrolEvidenceColumns();

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
  console.log('Guard assignments table ready');
}
ensureGuardAssignmentsTable();

async function ensureRoundSizeColumn() {
  await pool.query(`ALTER TABLE guard_assignments ADD COLUMN IF NOT EXISTS round_size INTEGER`);
  console.log('Round size column ready');
}
ensureRoundSizeColumn();

async function ensureCheckpointMetaColumns() {
  await pool.query(`ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS building TEXT`);
  await pool.query(`ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS floor TEXT`);
  console.log('Checkpoint building/floor columns ready');
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
  console.log('SOS alerts table ready');
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
  console.log('Guard locations table ready');
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
  console.log('Guard location history table ready');
}
ensureGuardLocationHistoryTable();

async function cleanupLocationHistory() {
  try {
    const cutoff = new Date(Date.now() - LOCATION_HISTORY_RETENTION_HOURS * 3600000);
    const result = await pool.query('DELETE FROM guard_location_history WHERE recorded_at < $1', [cutoff]);
    if (result.rowCount > 0) {
      console.log('Pruned ' + result.rowCount + ' old guard_location_history row(s)');
    }
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
  console.log('Client users table ready');
}
ensureClientUsersTable();

// Guard certifications table + migration
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

  // Migration safety for databases created by the older name/issuer schema.
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS cert_name TEXT`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS cert_number TEXT`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS issue_date DATE`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS expiry_date DATE`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW()`);

  const legacyNameColumn = await pool.query(`
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'guard_certifications'
      AND column_name = 'name'
  `);
  if (legacyNameColumn.rows.length > 0) {
    await pool.query(`
      UPDATE guard_certifications
      SET cert_name = name
      WHERE cert_name IS NULL AND name IS NOT NULL
    `);
    // New writes use cert_name, so the legacy name column must no longer
    // reject inserts that intentionally omit it.
    await pool.query(`ALTER TABLE guard_certifications ALTER COLUMN name DROP NOT NULL`);
  }

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_guard_certifications_user ON guard_certifications (tenant_id, user_id)`);
  console.log('Guard certifications table ready');
}
ensureGuardCertificationsTable();

// Shift scheduling table
async function ensureShiftsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shifts (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      shift_date DATE NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      break_minutes INTEGER NOT NULL DEFAULT 0,
      employment_type TEXT NOT NULL DEFAULT 'full_time',
      recurrence_group_id TEXT,
      notes TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE shifts ADD COLUMN IF NOT EXISTS break_minutes INTEGER NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE shifts ADD COLUMN IF NOT EXISTS assignment_status TEXT NOT NULL DEFAULT 'assigned'`);
  await pool.query(`ALTER TABLE shifts ADD COLUMN IF NOT EXISTS confirmation_status TEXT NOT NULL DEFAULT 'pending'`);
  await pool.query(`ALTER TABLE shifts ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shifts_guard_lookup ON shifts (tenant_id, user_id, shift_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shifts_site_lookup ON shifts (tenant_id, site_id, shift_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shifts_series ON shifts (tenant_id, recurrence_group_id)`);
  console.log('Shifts table ready');
}
ensureShiftsTable();

async function ensureShiftSwapRequestsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shift_swap_requests (
      id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, shift_id INTEGER NOT NULL,
      requester_id INTEGER NOT NULL, target_user_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending_recipient', reason TEXT,
      recipient_responded_at TIMESTAMPTZ, admin_reviewed_at TIMESTAMPTZ,
      admin_reviewed_by INTEGER, admin_notes TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_swap_requests ON shift_swap_requests (tenant_id,status,created_at DESC)`);
  console.log('Shift swap requests table ready');
}
ensureShiftSwapRequestsTable();

async function ensureShiftTemplatesTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shift_templates (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER,
      name TEXT NOT NULL,
      color TEXT NOT NULL DEFAULT '#2563eb',
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      break_minutes INTEGER NOT NULL DEFAULT 0,
      employment_type TEXT NOT NULL DEFAULT 'full_time',
      notes TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shift_templates_tenant ON shift_templates (tenant_id, name)`);
  console.log('Shift templates table ready');
}
ensureShiftTemplatesTable();

async function ensureAttendanceTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance_sessions (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      shift_id INTEGER,
      clocked_in_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      clocked_out_at TIMESTAMPTZ,
      clock_in_latitude DOUBLE PRECISION,
      clock_in_longitude DOUBLE PRECISION,
      clock_in_accuracy DOUBLE PRECISION,
      clock_out_latitude DOUBLE PRECISION,
      clock_out_longitude DOUBLE PRECISION,
      clock_out_accuracy DOUBLE PRECISION,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance_breaks (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      attendance_session_id INTEGER NOT NULL,
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ended_at TIMESTAMPTZ,
      start_latitude DOUBLE PRECISION,
      start_longitude DOUBLE PRECISION,
      end_latitude DOUBLE PRECISION,
      end_longitude DOUBLE PRECISION
    )
  `);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_attendance_one_active_session ON attendance_sessions (tenant_id, user_id) WHERE clocked_out_at IS NULL`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_attendance_one_active_break ON attendance_breaks (attendance_session_id) WHERE ended_at IS NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_attendance_history ON attendance_sessions (tenant_id, clocked_in_at DESC)`);
  await pool.query(`ALTER TABLE attendance_sessions ADD COLUMN IF NOT EXISTS clock_in_distance_m DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE attendance_sessions ADD COLUMN IF NOT EXISTS clock_in_geofence_radius_m INTEGER`);
  await pool.query(`ALTER TABLE attendance_sessions ADD COLUMN IF NOT EXISTS clock_in_geofence_verified BOOLEAN`);
  console.log('Attendance tables ready');
}
ensureAttendanceTables();

async function ensureTimesheetsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS timesheets (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      period_start DATE NOT NULL,
      period_end DATE NOT NULL,
      status TEXT NOT NULL DEFAULT 'submitted',
      session_count INTEGER NOT NULL DEFAULT 0,
      worked_seconds BIGINT NOT NULL DEFAULT 0,
      break_seconds BIGINT NOT NULL DEFAULT 0,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      reviewed_by INTEGER,
      review_notes TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id, user_id, period_start, period_end)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_timesheets_review ON timesheets (tenant_id, status, period_start DESC)`);
  console.log('Timesheets table ready');
}
ensureTimesheetsTable();

async function ensureAvailabilityAndLeaveTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guard_availability (
      id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      weekday INTEGER NOT NULL, is_available BOOLEAN NOT NULL DEFAULT TRUE,
      available_from TEXT, available_until TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id,user_id,weekday), CHECK (weekday BETWEEN 0 AND 6)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS leave_requests (
      id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      start_date DATE NOT NULL, end_date DATE NOT NULL, leave_type TEXT NOT NULL,
      reason TEXT, status TEXT NOT NULL DEFAULT 'pending', requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ, reviewed_by INTEGER, review_notes TEXT,
      CHECK (end_date >= start_date)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_leave_review ON leave_requests (tenant_id,status,start_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_guard_availability_lookup ON guard_availability (tenant_id,user_id,weekday)`);
  console.log('Availability and leave tables ready');
}
ensureAvailabilityAndLeaveTables();

// ------------------------ COMPLIANCE SWEEP ------------------------

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
  const schedulesRes = await client.query(
    'SELECT * FROM patrol_schedules WHERE tenant_id = $1 AND site_id = $2',
    [tenantId, siteId]
  );
  const checkpointsRes = await client.query(
    'SELECT * FROM checkpoints WHERE tenant_id = $1 AND site_id = $2',
    [tenantId, siteId]
  );
  const checkpointIds = checkpointsRes.rows.map(c => c.id);
  const logsRes = checkpointIds.length
    ? await client.query(
        'SELECT * FROM patrol_logs WHERE tenant_id = $1 AND checkpoint_id = ANY($2) ORDER BY scanned_at DESC',
        [tenantId, checkpointIds]
      )
    : { rows: [] };

  const zone = (tenantRes.rows[0] && tenantRes.rows[0].timezone) || 'UTC';
  const now = new Date();
  const hourlySchedules = schedulesRes.rows.filter(s => s.schedule_type === 'hourly');
  const fixedSchedules = schedulesRes.rows.filter(s => s.schedule_type === 'fixed');
  const hasCustomOnly = hourlySchedules.length === 0 && fixedSchedules.length === 0 && schedulesRes.rows.some(s => s.schedule_type === 'custom');

  const shortestHourly = hourlySchedules.length
    ? Math.min(...hourlySchedules.map(s => Number(s.config.interval_hours) || Infinity))
    : null;

  const allFixedTimes = Array.from(new Set(
    fixedSchedules.flatMap(s => Array.isArray(s.config.times) ? s.config.times : [])
  ));

  return checkpointsRes.rows.map(cp => {
    const lastLog = logsRes.rows.find(l => l.checkpoint_id === cp.id);
    const lastScan = lastLog ? new Date(lastLog.scanned_at) : null;

    let status = 'no_schedule';
    let hoursOverdue = 0;
    let scheduleType = null;

    if (shortestHourly !== null && shortestHourly !== Infinity) {
      scheduleType = 'hourly';
      if (!lastScan) {
        status = 'overdue';
      } else {
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
      if (!targetOcc) {
        status = 'ok';
      } else {
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

    return {
      checkpoint_id: cp.id,
      checkpoint_name: cp.name,
      last_scan: lastScan,
      status,
      hours_overdue: hoursOverdue,
      schedule_type: scheduleType
    };
  });
}

async function runComplianceSweep() {
  try {
    const tenantsRes = await pool.query('SELECT id FROM tenants');
    for (const tenant of tenantsRes.rows) {
      await withTenant(tenant.id, async (client) => {
        const sitesRes = await client.query('SELECT id, name FROM sites WHERE tenant_id = $1', [tenant.id]);

        for (const site of sitesRes.rows) {
          const compliance = await computeSiteCompliance(client, tenant.id, site.id);

          for (const cp of compliance) {
            const openRes = await client.query(
              'SELECT id FROM notifications WHERE tenant_id = $1 AND checkpoint_id = $2 AND resolved = FALSE',
              [tenant.id, cp.checkpoint_id]
            );
            const hasOpen = openRes.rows.length > 0;

            if (cp.status === 'overdue' && !hasOpen) {
              const message = cp.hours_overdue
                ? `${cp.checkpoint_name} is ${cp.hours_overdue}h overdue`
                : `${cp.checkpoint_name} has never been scanned`;
              await client.query(
                `INSERT INTO notifications (tenant_id, site_id, site_name, checkpoint_id, checkpoint_name, message, hours_overdue)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [tenant.id, site.id, site.name, cp.checkpoint_id, cp.checkpoint_name, message, cp.hours_overdue]
              );
            } else if (cp.status !== 'overdue' && hasOpen) {
              await client.query(
                'UPDATE notifications SET resolved = TRUE, resolved_at = NOW() WHERE tenant_id = $1 AND checkpoint_id = $2 AND resolved = FALSE',
                [tenant.id, cp.checkpoint_id]
              );
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

// ------------------------ REPORT HELPERS ------------------------

async function fetchReportData(client, tenantId, siteId, startDt, endDt) {
  const tenantRes = await client.query('SELECT name, timezone FROM tenants WHERE id = $1', [tenantId]);
  const siteRes = await client.query('SELECT name FROM sites WHERE id = $1 AND tenant_id = $2', [siteId, tenantId]);
  if (siteRes.rows.length === 0) {
    const err = new Error('Site not found');
    err.statusCode = 404;
    throw err;
  }

  const checkpointsRes = await client.query(
    'SELECT id, name, building, floor FROM checkpoints WHERE tenant_id = $1 AND site_id = $2 ORDER BY name',
    [tenantId, siteId]
  );
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
    return {
      id: cp.id,
      name: cp.name,
      location: [cp.building, cp.floor].filter(Boolean).join(' / ') || '-',
      scanCount: scansForCp.length,
      lastScan: lastScanInRange
    };
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
  if (/[",\n]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function buildCsv(headers, rows) {
  const lines = [headers.map(csvEscape).join(',')];
  rows.forEach(row => {
    lines.push(row.map(csvEscape).join(','));
  });
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

// ------------------------ REPORT ROUTES ------------------------

app.get('/api/reports/compliance-pdf', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, start_date, end_date } = req.query;
  if (!tenant_id || !site_id || !start_date || !end_date) {
    return res.status(400).json({ error: 'tenant_id, site_id, start_date, and end_date are required' });
  }

  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, (client) => fetchReportData(client, tenant_id, site_id, startDt, endDt));

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
        doc.fillColor('#6b7280').text(
          cp.lastScan ? DateTime.fromJSDate(new Date(cp.lastScan)).setZone(reportData.timezone).toFormat('dd LLL, HH:mm') : 'Not scanned',
          colX.lastScan, rowY, { width: 110 }
        );
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
        doc.fontSize(9).fillColor(severityColor(inc.severity)).text('[' + inc.severity.toUpperCase() + ']  ' + dateLabel, { continued: false });
        doc.fontSize(10).fillColor('#111827').text(inc.description, { width: 495 });
        if (inc.guard_email) {
          doc.fontSize(8).fillColor('#9ca3af').text('Reported by: ' + inc.guard_email);
        }
        doc.moveDown(0.6);
      });
    }

    doc.end();
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/reports/compliance-csv', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, start_date, end_date } = req.query;
  if (!tenant_id || !site_id || !start_date || !end_date) {
    return res.status(400).json({ error: 'tenant_id, site_id, start_date, and end_date are required' });
  }

  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, (client) => fetchReportData(client, tenant_id, site_id, startDt, endDt));

    const rows = reportData.logs.map(log => {
      const cp = reportData.checkpointLookup[log.checkpoint_id] || {};
      const scannedLocal = DateTime.fromJSDate(new Date(log.scanned_at)).setZone(reportData.timezone);
      return [
        reportData.siteName,
        cp.name || ('Checkpoint #' + log.checkpoint_id),
        [cp.building, cp.floor].filter(Boolean).join(' / ') || '',
        log.guard_email || '',
        scannedLocal.toFormat('yyyy-MM-dd'),
        scannedLocal.toFormat('HH:mm:ss'),
        log.latitude ?? '',
        log.longitude ?? ''
      ];
    });

    const csv = buildCsv(
      ['Site', 'Checkpoint', 'Location', 'Guard Email', 'Date', 'Time', 'Latitude', 'Longitude'],
      rows
    );

    const filename = 'scan-log-' + safeFilenamePart(reportData.siteName) + '-' + startDt.toFormat('yyyy-MM-dd') + '.csv';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send('\uFEFF' + csv);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/reports/incidents-csv', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, start_date, end_date } = req.query;
  if (!tenant_id || !site_id || !start_date || !end_date) {
    return res.status(400).json({ error: 'tenant_id, site_id, start_date, and end_date are required' });
  }

  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, (client) => fetchReportData(client, tenant_id, site_id, startDt, endDt));

    const rows = reportData.incidents.map(inc => {
      const reportedLocal = DateTime.fromJSDate(new Date(inc.reported_at)).setZone(reportData.timezone);
      return [
        reportData.siteName,
        reportedLocal.toFormat('yyyy-MM-dd'),
        reportedLocal.toFormat('HH:mm:ss'),
        inc.severity,
        inc.guard_email || '',
        inc.description,
        inc.photo_count
      ];
    });

    const csv = buildCsv(
      ['Site', 'Date', 'Time', 'Severity', 'Guard Email', 'Description', 'Photo Count'],
      rows
    );

    const filename = 'incidents-' + safeFilenamePart(reportData.siteName) + '-' + startDt.toFormat('yyyy-MM-dd') + '.csv';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send('\uFEFF' + csv);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// ------------------------ HEALTH & BASIC ROUTES ------------------------

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'PatrolSync Backend', timestamp: new Date().toISOString() });
});

app.get('/health', async (req, res) => {
  try {
    const started=Date.now();await pool.query('SELECT 1');
    res.json({status:'healthy',service:'PatrolSync Backend',database:'connected',database_latency_ms:Date.now()-started,uptime_seconds:Math.floor(process.uptime()),timestamp:new Date().toISOString(),request_id:req.requestId});
  } catch (err) {
    res.status(503).json({status:'unhealthy',database:'disconnected',error:err.message,request_id:req.requestId});
  }
});

app.get('/ready',async(req,res)=>{try{await pool.query('SELECT 1');res.json({ready:true,request_id:req.requestId})}catch(err){res.status(503).json({ready:false,error:'Database unavailable',request_id:req.requestId})}});

app.get('/api/timezones', (req, res) => {
  res.json(getAllTimezones());
});

app.get('/api/plans', (req, res) => {
  res.json(PLAN_LIMITS);
});

app.get('/api/usage', requireAuth, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const data = await withTenant(tenant_id, async (client) => {
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

app.get('/api/notifications', requireAuth, async (req, res) => {
  const { tenant_id, status } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) => {
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
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'UPDATE notifications SET resolved = TRUE, resolved_at = NOW() WHERE id = $1 AND tenant_id = $2 RETURNING *',
        [id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Notification not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/audit-logs', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const { action, user_id, from_date, to_date, search } = req.query;
  try {
    const result = await withTenant(tenantId, client => {
      const params = [tenantId];
      let query = 'SELECT * FROM audit_logs WHERE tenant_id=$1';
      if (action) { params.push(action); query += ` AND action=$${params.length}`; }
      if (user_id) { params.push(user_id); query += ` AND user_id=$${params.length}`; }
      if (from_date) { params.push(from_date); query += ` AND created_at >= $${params.length}::date`; }
      if (to_date) { params.push(to_date); query += ` AND created_at < ($${params.length}::date + INTERVAL '1 day')`; }
      if (search) { params.push(`%${search}%`); query += ` AND (resource ILIKE $${params.length} OR user_email ILIKE $${params.length} OR details::text ILIKE $${params.length})`; }
      query += ' ORDER BY created_at DESC LIMIT 500';
      return client.query(query, params);
    });
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ------------------------ SOS ROUTES ------------------------

app.post('/api/sos', requireAuth, async (req, res) => {
  const { tenant_id, site_id, latitude, longitude, message } = req.body;
  const user_id = req.auth.user_id;
  if (!tenant_id || !site_id) {
    return res.status(400).json({ error: 'tenant_id and site_id are required' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const existing = await client.query(
        "SELECT * FROM sos_alerts WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'",
        [tenant_id, user_id]
      );
      if (existing.rows.length > 0) {
        return { row: existing.rows[0], alreadyActive: true };
      }
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
    const result = await withTenant(tenant_id, (client) => {
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
    const result = await withTenant(tenant_id, async (client) => {
      const existing = await client.query(
        "SELECT * FROM sos_alerts WHERE id = $1 AND tenant_id = $2 AND status = 'active'",
        [id, tenant_id]
      );
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
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Active SOS alert not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// ------------------------ GUARD LOCATION ROUTES ------------------------

app.post('/api/guard-locations', requireAuth, async (req, res) => {
  const { tenant_id, site_id, latitude, longitude } = req.body;
  const user_id = req.auth.user_id;
  if (!tenant_id || latitude === undefined || longitude === undefined) {
    return res.status(400).json({ error: 'tenant_id, latitude, and longitude are required' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
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
    const result = await withTenant(tenant_id, (client) =>
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
    const result = await withTenant(tenant_id, (client) =>
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

// ------------------------ CLIENT PORTAL ROUTES ------------------------

app.post('/api/client-users', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, email, password } = req.body;
  if (!tenant_id || !site_id || !email || !password) {
    return res.status(400).json({ error: 'tenant_id, site_id, email, and password are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'password must be at least 6 characters' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
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
    if (err.code === '23505') {
      return res.status(409).json({ error: 'A client account with this email already exists for this tenant' });
    }
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/client-users', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
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
    const result = await withTenant(tenant_id, (client) =>
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
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'UPDATE client_users SET password_hash = $1 WHERE id = $2 AND tenant_id = $3 RETURNING id, email',
        [hash, id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Client account not found' });
    res.json({ reset: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/client-auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
  const normalizedEmail = email.toLowerCase().trim();

  try {
    const tenantsRes = await pool.query('SELECT id FROM tenants');
    let matched = null;
    let matchedTenantId = null;

    for (const t of tenantsRes.rows) {
      const result = await withTenant(t.id, (client) =>
        client.query('SELECT * FROM client_users WHERE tenant_id = $1 AND LOWER(email) = $2', [t.id, normalizedEmail])
      );
      if (result.rows.length > 0) {
        const candidate = result.rows[0];
        const valid = await bcrypt.compare(password, candidate.password_hash);
        if (valid) {
          matched = candidate;
          matchedTenantId = t.id;
          break;
        }
      }
    }

    if (!matched) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const siteRes = await withTenant(matchedTenantId, (client) =>
      client.query('SELECT name FROM sites WHERE id = $1 AND tenant_id = $2', [matched.site_id, matchedTenantId])
    );

    const token = jwt.sign(
      { client_user_id: matched.id, tenant_id: matchedTenantId, site_id: matched.site_id, role: 'client' },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      token,
      client: { id: matched.id, email: matched.email },
      tenant_id: matchedTenantId,
      site_id: matched.site_id,
      site_name: siteRes.rows[0] ? siteRes.rows[0].name : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/client-portal/compliance', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  try {
    const compliance = await withTenant(tenant_id, (client) => computeSiteCompliance(client, tenant_id, site_id));
    res.json(compliance);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/client-portal/incidents', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  const { date } = req.query;
  try {
    const result = await withTenant(tenant_id, (client) =>
      date
        ? client.query(
            `SELECT i.description, i.severity, i.reported_at, COALESCE(p.photo_count, 0) as photo_count
             FROM incidents i
             LEFT JOIN (SELECT incident_id, COUNT(*) AS photo_count FROM incident_photos WHERE tenant_id = $1 GROUP BY incident_id) p ON p.incident_id = i.id
             WHERE i.tenant_id = $1 AND i.site_id = $2 AND i.reported_at::date = $3
             ORDER BY i.reported_at DESC`,
            [tenant_id, site_id, date]
          )
        : client.query(
            `SELECT i.description, i.severity, i.reported_at, COALESCE(p.photo_count, 0) as photo_count
             FROM incidents i
             LEFT JOIN (SELECT incident_id, COUNT(*) AS photo_count FROM incident_photos WHERE tenant_id = $1 GROUP BY incident_id) p ON p.incident_id = i.id
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
    const result = await withTenant(tenant_id, (client) =>
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
  if (!start_date || !end_date) {
    return res.status(400).json({ error: 'start_date and end_date are required' });
  }

  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, (client) => fetchReportData(client, tenant_id, site_id, startDt, endDt));

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
        doc.fillColor('#6b7280').text(
          cp.lastScan ? DateTime.fromJSDate(new Date(cp.lastScan)).setZone(reportData.timezone).toFormat('dd LLL, HH:mm') : 'Not scanned',
          colX.lastScan, rowY, { width: 110 }
        );
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
        doc.fontSize(9).fillColor(severityColor(inc.severity)).text('[' + inc.severity.toUpperCase() + ']  ' + dateLabel, { continued: false });
        doc.fontSize(10).fillColor('#111827').text(inc.description, { width: 495 });
        doc.moveDown(0.6);
      });
    }

    doc.end();
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// ------------------------ TENANT ROUTES ------------------------

app.post('/api/tenants', async (req, res) => {
  const { name, slug, plan } = req.body;
  if (!name || !slug) return res.status(400).json({ error: 'name and slug are required' });
  const chosenPlan = VALID_PLANS.includes(plan) ? plan : 'starter';
  try {
    const result = await pool.query(
      'INSERT INTO tenants (name, slug, plan) VALUES ($1, $2, $3) RETURNING *',
      [name, slug, chosenPlan]
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

app.patch('/api/tenants/:id/plan', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { plan } = req.body;
  if (!plan || !VALID_PLANS.includes(plan)) {
    return res.status(400).json({ error: 'plan must be one of: ' + VALID_PLANS.join(', ') });
  }
  if (Number(id) !== req.auth.tenant_id) {
    return res.status(403).json({ error: 'Cannot modify a different tenant' });
  }
  try {
    const result = await withTenant(id, (client) =>
      client.query('UPDATE tenants SET plan = $1 WHERE id = $2 RETURNING *', [plan, id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tenant not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/tenants/:id/timezone', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { timezone } = req.body;
  if (!timezone) return res.status(400).json({ error: 'timezone is required' });
  if (Number(id) !== req.auth.tenant_id) {
    return res.status(403).json({ error: 'Cannot modify a different tenant' });
  }
  const validZones = getAllTimezones();
  if (!validZones.includes(timezone)) {
    return res.status(400).json({ error: 'Unrecognized timezone' });
  }
  try {
    const result = await withTenant(id, (client) =>
      client.query('UPDATE tenants SET timezone = $1 WHERE id = $2 RETURNING *', [timezone, id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tenant not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function isValidPhoneFormat(value) {
  return /^[0-9+ ()-]{6,20}$/.test(value);
}

app.patch('/api/tenants/:id/emergency-contacts', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { emergency_phone, emergency_whatsapp } = req.body;
  if (Number(id) !== req.auth.tenant_id) {
    return res.status(403).json({ error: 'Cannot modify a different tenant' });
  }

  const phoneTrimmed = (emergency_phone || '').trim();
  const waTrimmed = (emergency_whatsapp || '').trim();

  if (phoneTrimmed && !isValidPhoneFormat(phoneTrimmed)) {
    return res.status(400).json({ error: 'Emergency phone: enter a valid number (digits, spaces, +, -, () only)' });
  }
  if (waTrimmed && !isValidPhoneFormat(waTrimmed)) {
    return res.status(400).json({ error: 'WhatsApp number: enter a valid number (digits, spaces, +, -, () only)' });
  }

  try {
    const result = await withTenant(id, (client) =>
      client.query(
        'UPDATE tenants SET emergency_phone = $1, emergency_whatsapp = $2 WHERE id = $3 RETURNING *',
        [phoneTrimmed || null, waTrimmed || null, id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tenant not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ SIGNUP & AUTH ROUTES ------------------------

app.post('/api/signup', async (req, res) => {
  const { company_name, plan, admin_email, admin_password, timezone } = req.body;
  if (!company_name || !admin_email || !admin_password) {
    return res.status(400).json({ error: 'company_name, admin_email, and admin_password are required' });
  }
  const chosenPlan = VALID_PLANS.includes(plan) ? plan : 'starter';
  const validZones = getAllTimezones();
  const chosenTimezone = timezone && validZones.includes(timezone) ? timezone : 'UTC';
  const slug = company_name.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const tenantResult = await client.query(
      'INSERT INTO tenants (name, slug, plan, timezone) VALUES ($1, $2, $3, $4) RETURNING *',
      [company_name, slug, chosenPlan, chosenTimezone]
    );
    const tenant = tenantResult.rows[0];

    const hash = await bcrypt.hash(admin_password, 10);
    await client.query(`SET app.current_tenant = '${tenant.id}'`);
    const userResult = await client.query(
      'INSERT INTO users (tenant_id, email, role, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, tenant_id, email, role',
      [tenant.id, admin_email.toLowerCase().trim(), 'admin', hash]
    );
    const adminUser = userResult.rows[0];

    await client.query('COMMIT');

    const token = jwt.sign(
      { user_id: adminUser.id, tenant_id: tenant.id, role: adminUser.role },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.status(201).json({ tenant, admin: adminUser, token });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') {
      return res.status(409).json({ error: 'A company with a similar name or this email already exists' });
    }
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { tenant_id, email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  const normalizedEmail = email.toLowerCase().trim();

  try {
    let candidates = [];

    if (tenant_id) {
      const result = await withTenant(tenant_id, (client) =>
        client.query('SELECT * FROM users WHERE tenant_id = $1 AND LOWER(email) = $2', [tenant_id, normalizedEmail])
      );
      candidates = result.rows;
    } else {
      const tenantsRes = await pool.query('SELECT id FROM tenants');
      for (const t of tenantsRes.rows) {
        const result = await withTenant(t.id, (client) =>
          client.query('SELECT * FROM users WHERE tenant_id = $1 AND LOWER(email) = $2', [t.id, normalizedEmail])
        );
        candidates.push(...result.rows);
      }
    }

    if (candidates.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    let matchedUser = null;
    for (const candidate of candidates) {
      if (!candidate.password_hash) continue;
      const valid = await bcrypt.compare(password, candidate.password_hash);
      if (valid) {
        matchedUser = candidate;
        break;
      }
    }

    if (!matchedUser) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      {
        user_id: matchedUser.id,
        tenant_id: matchedUser.tenant_id,
        role: matchedUser.role,
        email: matchedUser.email
      },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      token,
      tenant_id: matchedUser.tenant_id,
      user: {
        id: matchedUser.id,
        email: matchedUser.email,
        role: matchedUser.role
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ SITES & CHECKPOINTS ------------------------

app.post('/api/sites', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, name, address } = req.body;
  if (!tenant_id || !name) return res.status(400).json({ error: 'tenant_id and name are required' });
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const limitCheck = await checkPlanLimit(client, tenant_id, 'locations');
      if (!limitCheck.allowed) {
        const err = new Error(`Your ${limitCheck.plan} plan allows up to ${limitCheck.max} location(s). Upgrade your plan to add more.`);
        err.statusCode = 403;
        throw err;
      }
      return client.query(
        'INSERT INTO sites (tenant_id, name, address) VALUES ($1, $2, $3) RETURNING *',
        [tenant_id, name, address || null]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/sites', requireAuth, async (req, res) => {
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

app.patch('/api/sites/:id/geofence', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = Number(req.body.tenant_id || req.auth.tenant_id);
  if (tenantId !== Number(req.auth.tenant_id)) return res.status(403).json({ error: 'Tenant access denied' });
  const enabled = Boolean(req.body.geofence_enabled);
  const latitude = req.body.latitude === null || req.body.latitude === '' ? null : Number(req.body.latitude);
  const longitude = req.body.longitude === null || req.body.longitude === '' ? null : Number(req.body.longitude);
  const radius = Number(req.body.geofence_radius_m);
  if (enabled && (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 || !Number.isFinite(longitude) || longitude < -180 || longitude > 180)) {
    return res.status(400).json({ error: 'Valid latitude and longitude are required when the geofence is enabled' });
  }
  if (!Number.isInteger(radius) || radius < 25 || radius > 5000) {
    return res.status(400).json({ error: 'Geofence radius must be between 25 and 5000 metres' });
  }
  try {
    const result = await withTenant(tenantId, client => client.query(
      `UPDATE sites SET latitude=$1, longitude=$2, geofence_radius_m=$3, geofence_enabled=$4
       WHERE id=$5 AND tenant_id=$6 RETURNING *`,
      [latitude, longitude, radius, enabled, req.params.id, tenantId]
    ));
    if (result.rows.length === 0) return res.status(404).json({ error: 'Site not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/checkpoints', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, name, qr_code, latitude, longitude, building, floor } = req.body;
  if (!tenant_id || !site_id || !name || !qr_code) {
    return res.status(400).json({ error: 'tenant_id, site_id, name, and qr_code are required' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const limitCheck = await checkPlanLimit(client, tenant_id, 'checkpoints');
      if (!limitCheck.allowed) {
        const err = new Error(`Your ${limitCheck.plan} plan allows up to ${limitCheck.max} checkpoint(s). Upgrade your plan to add more.`);
        err.statusCode = 403;
        throw err;
      }
      return client.query(
        'INSERT INTO checkpoints (tenant_id, site_id, name, qr_code, latitude, longitude, building, floor) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
        [tenant_id, site_id, name, qr_code, latitude || null, longitude || null, building || null, floor || null]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'A checkpoint with this QR code already exists' });
    }
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/checkpoints', requireAuth, async (req, res) => {
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

app.get('/api/checkpoints/lookup', requireAuth, async (req, res) => {
  const { tenant_id, qr_code } = req.query;
  if (!tenant_id || !qr_code) return res.status(400).json({ error: 'tenant_id and qr_code query params are required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `SELECT c.*, s.name as site_name FROM checkpoints c
         JOIN sites s ON s.id = c.site_id
         WHERE c.tenant_id = $1 AND c.qr_code = $2`,
        [tenant_id, qr_code]
      )
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No checkpoint matches this QR code' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/qr-image', (req, res) => {
  const { text, token } = req.query;
  if (!text) return res.status(400).send('text query param is required');
  if (!token) return res.status(401).send('token query param is required');

  try {
    jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).send('Invalid or expired token');
  }

  QRCode.toBuffer(String(text), { width: 220, margin: 1 }, (err, buffer) => {
    if (err) return res.status(500).send('Failed to generate QR image');
    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(buffer);
  });
});

app.delete('/api/checkpoints/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, async (client) => {
      await client.query('DELETE FROM patrol_logs WHERE checkpoint_id = $1 AND tenant_id = $2', [id, tenant_id]);
      await client.query('DELETE FROM notifications WHERE checkpoint_id = $1 AND tenant_id = $2', [id, tenant_id]);
      return client.query('DELETE FROM checkpoints WHERE id = $1 AND tenant_id = $2 RETURNING *', [id, tenant_id]);
    });
    if (result.rows.length === 0) return res.status(404).json({ error: 'Checkpoint not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ USERS & GUARDS ------------------------

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, firebase_uid, email, role, password } = req.body;
  if (!tenant_id || !email) {
    return res.status(400).json({ error: 'tenant_id and email are required' });
  }
  if (role && !['admin', 'guard'].includes(role)) {
    return res.status(400).json({ error: 'role must be admin or guard' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      if ((role || 'guard') === 'guard') {
        const limitCheck = await checkPlanLimit(client, tenant_id, 'guards');
        if (!limitCheck.allowed) {
          const err = new Error(`Your ${limitCheck.plan} plan allows up to ${limitCheck.max} guard(s). Upgrade your plan to add more.`);
          err.statusCode = 403;
          throw err;
        }
      }
      const hash = password ? await bcrypt.hash(password, 10) : null;
      return client.query(
        'INSERT INTO users (tenant_id, firebase_uid, email, role, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id, tenant_id, email, role',
        [tenant_id, firebase_uid || null, email.toLowerCase().trim(), role || 'guard', hash]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, role } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const includeInactive=req.query.include_inactive==='true';
    const result = await withTenant(tenant_id, (client) =>
      role
        ? client.query(`SELECT * FROM users WHERE tenant_id=$1 AND role=$2 AND ($3::boolean OR COALESCE(account_active,TRUE)=TRUE) ORDER BY created_at DESC`,[tenant_id,role,includeInactive])
        : client.query(`SELECT * FROM users WHERE tenant_id=$1 AND ($2::boolean OR COALESCE(account_active,TRUE)=TRUE) ORDER BY created_at DESC`,[tenant_id,includeInactive])
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  if (Number(id) === req.auth.user_id) {
    return res.status(400).json({ error: 'You cannot remove your own account' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      await client.query('BEGIN');
      try {
        const archived=await client.query("UPDATE users SET account_active=FALSE,password_changed_at=NOW() WHERE id=$1 AND tenant_id=$2 AND role='guard' AND COALESCE(account_active,TRUE)=TRUE RETURNING id,email",[id,tenant_id]);
        if(archived.rowCount)await client.query('DELETE FROM guard_assignments WHERE tenant_id=$1 AND user_id=$2',[tenant_id,id]);
        await client.query('COMMIT');return archived;
      } catch(e) { await client.query('ROLLBACK');throw e; }
    });
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Active guard not found, or guard is already archived' });
    }
    res.json({ archived: result.rows[0],message:'Guard archived. Historical operational records were preserved.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/users/:id/reset-password', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, new_password } = req.body;
  if (!tenant_id || !new_password) {
    return res.status(400).json({ error: 'tenant_id and new_password are required' });
  }
  if (new_password.length < 6) {
    return res.status(400).json({ error: 'new_password must be at least 6 characters' });
  }
  try {
    const hash = await bcrypt.hash(new_password, 10);
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        "UPDATE users SET password_hash = $1 WHERE id = $2 AND tenant_id = $3 AND role = 'guard' RETURNING id, email",
        [hash, id, tenant_id]
      )
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Guard not found, or user is not a guard' });
    }
    res.json({ reset: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ GUARD ASSIGNMENTS & PROGRESS ------------------------

app.post('/api/guard-assignments', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, user_id, round_size } = req.body;
  if (!tenant_id || !site_id || !user_id) {
    return res.status(400).json({ error: 'tenant_id, site_id, and user_id are required' });
  }
  const roundSizeVal = (round_size !== undefined && round_size !== null && round_size !== '') ? Number(round_size) : null;
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `INSERT INTO guard_assignments (tenant_id, site_id, user_id, round_size) VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, site_id, user_id) DO NOTHING RETURNING *`,
        [tenant_id, site_id, user_id, roundSizeVal]
      )
    );
    if (result.rows.length === 0) {
      return res.status(409).json({ error: 'This guard is already assigned to this site' });
    }
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/guard-assignments', requireAuth, async (req, res) => {
  const { tenant_id, user_id, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });

  if (req.auth.role !== 'admin' && Number(user_id) !== req.auth.user_id) {
    return res.status(403).json({ error: 'Guards can only view their own assignments' });
  }

  try {
    const result = await withTenant(tenant_id, (client) => {
      let query = `SELECT ga.*, s.name as site_name, s.geofence_enabled, s.geofence_radius_m, u.email as guard_email
                   FROM guard_assignments ga
                   JOIN sites s ON s.id = ga.site_id
                   JOIN users u ON u.id = ga.user_id
                   WHERE ga.tenant_id = $1`;
      const params = [tenant_id];
      if (user_id) { params.push(user_id); query += ` AND ga.user_id = $${params.length}`; }
      if (site_id) { params.push(site_id); query += ` AND ga.site_id = $${params.length}`; }
      query += ' ORDER BY ga.created_at DESC';
      return client.query(query, params);
    });
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/guard-assignments/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, round_size } = req.body;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id is required' });
  const roundSizeVal = (round_size !== undefined && round_size !== null && round_size !== '') ? Number(round_size) : null;
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'UPDATE guard_assignments SET round_size = $1 WHERE id = $2 AND tenant_id = $3 RETURNING *',
        [roundSizeVal, id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Assignment not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/guard-assignments/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query('DELETE FROM guard_assignments WHERE id = $1 AND tenant_id = $2 RETURNING *', [id, tenant_id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Assignment not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/guard-progress', requireAuth, async (req, res) => {
  const { tenant_id, site_id, user_id } = req.query;
  if (!tenant_id || !site_id || !user_id) {
    return res.status(400).json({ error: 'tenant_id, site_id, and user_id are required' });
  }
  if (req.auth.role !== 'admin' && Number(user_id) !== req.auth.user_id) {
    return res.status(403).json({ error: 'Guards can only view their own progress' });
  }
  try {
    const data = await withTenant(tenant_id, async (client) => {
      const tenantRes = await client.query('SELECT timezone FROM tenants WHERE id = $1', [tenant_id]);
      const zone = (tenantRes.rows[0] && tenantRes.rows[0].timezone) || 'UTC';

      const assignmentRes = await client.query(
        'SELECT * FROM guard_assignments WHERE tenant_id = $1 AND site_id = $2 AND user_id = $3',
        [tenant_id, site_id, user_id]
      );
      if (assignmentRes.rows.length === 0) {
        const err = new Error('Guard is not assigned to this site');
        err.statusCode = 404;
        throw err;
      }
      const assignment = assignmentRes.rows[0];

      const checkpointsRes = await client.query(
        'SELECT id, name FROM checkpoints WHERE tenant_id = $1 AND site_id = $2 ORDER BY name',
        [tenant_id, site_id]
      );
      const checkpoints = checkpointsRes.rows;
      const target = assignment.round_size !== null ? assignment.round_size : checkpoints.length;

      const roundStart = todayStartUTC(zone);
      const checkpointIds = checkpoints.map(c => c.id);
      const scannedRes = checkpointIds.length
        ? await client.query(
            'SELECT DISTINCT checkpoint_id FROM patrol_logs WHERE tenant_id = $1 AND user_id = $2 AND checkpoint_id = ANY($3) AND scanned_at >= $4',
            [tenant_id, user_id, checkpointIds, roundStart]
          )
        : { rows: [] };
      const scannedIds = new Set(scannedRes.rows.map(r => r.checkpoint_id));

      const remaining = checkpoints.filter(c => !scannedIds.has(c.id));

      return {
        scanned_count: scannedIds.size,
        target,
        round_complete: scannedIds.size >= target,
        remaining: remaining.map(c => ({ checkpoint_id: c.id, name: c.name })),
        round_started_at: roundStart
      };
    });
    res.json(data);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// ------------------------ PATROL SCHEDULES & LOGS ------------------------

app.get('/api/patrol-routes', requireAuth, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const siteId = req.query.site_id ? Number(req.query.site_id) : null;
  try {
    const result = await withTenant(tenantId, client => {
      const params = [tenantId];
      let where = 'r.tenant_id=$1';
      if (siteId) { params.push(siteId); where += ` AND r.site_id=$${params.length}`; }
      return client.query(`SELECT r.*,s.name AS site_name,
        COALESCE(json_agg(json_build_object('checkpoint_id',c.id,'name',c.name,'position',rc.position,'instructions',rc.instructions,'requires_confirmation',rc.requires_confirmation,'requires_note',rc.requires_note)
          ORDER BY rc.position) FILTER (WHERE c.id IS NOT NULL),'[]') AS checkpoints
        FROM patrol_routes r JOIN sites s ON s.id=r.site_id
        LEFT JOIN patrol_route_checkpoints rc ON rc.route_id=r.id
        LEFT JOIN checkpoints c ON c.id=rc.checkpoint_id
        WHERE ${where} GROUP BY r.id,s.name ORDER BY r.active DESC,r.name`, params);
    });
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/patrol-routes', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  const siteId = Number(req.body.site_id), checkpointIds = (req.body.checkpoint_ids || []).map(Number);
  const name = String(req.body.name || '').trim();
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!siteId || !name || !checkpointIds.length) return res.status(400).json({ error: 'Site, route name, and at least one checkpoint are required' });
  if (new Set(checkpointIds).size !== checkpointIds.length) return res.status(400).json({ error: 'A checkpoint can only appear once in a route' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);
    const valid = await client.query('SELECT id FROM checkpoints WHERE tenant_id=$1 AND site_id=$2 AND id=ANY($3::int[])',[tenantId,siteId,checkpointIds]);
    if (valid.rows.length !== checkpointIds.length) throw Object.assign(new Error('Every checkpoint must belong to the selected site'),{statusCode:400});
    const route = await client.query(`INSERT INTO patrol_routes (tenant_id,site_id,name,description,strict_order,estimated_minutes)
      VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,[tenantId,siteId,name,req.body.description||null,req.body.strict_order!==false,req.body.estimated_minutes||null]);
    for (let i=0;i<checkpointIds.length;i++) await client.query('INSERT INTO patrol_route_checkpoints (tenant_id,route_id,checkpoint_id,position) VALUES ($1,$2,$3,$4)',[tenantId,route.rows[0].id,checkpointIds[i],i+1]);
    await client.query('COMMIT'); res.status(201).json(route.rows[0]);
  } catch (err) { await client.query('ROLLBACK'); res.status(err.statusCode||500).json({ error: err.code==='23505'?'A route with this name already exists at the site':err.message }); }
  finally { client.release(); }
});

app.put('/api/patrol-routes/:id', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.body.tenant_id), routeId=Number(req.params.id);
  const siteId=Number(req.body.site_id), checkpointIds=(req.body.checkpoint_ids||[]).map(Number), name=String(req.body.name||'').trim();
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!siteId||!name||!checkpointIds.length||new Set(checkpointIds).size!==checkpointIds.length) return res.status(400).json({ error: 'Valid site, unique checkpoint order, and route name are required' });
  const client=await pool.connect(); try { await client.query('BEGIN'); await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);
    const valid=await client.query('SELECT id FROM checkpoints WHERE tenant_id=$1 AND site_id=$2 AND id=ANY($3::int[])',[tenantId,siteId,checkpointIds]);
    if(valid.rows.length!==checkpointIds.length) throw Object.assign(new Error('Every checkpoint must belong to the selected site'),{statusCode:400});
    const updated=await client.query(`UPDATE patrol_routes SET site_id=$1,name=$2,description=$3,strict_order=$4,estimated_minutes=$5,active=$6,updated_at=NOW() WHERE id=$7 AND tenant_id=$8 RETURNING *`,[siteId,name,req.body.description||null,req.body.strict_order!==false,req.body.estimated_minutes||null,req.body.active!==false,routeId,tenantId]);
    if(!updated.rows.length) throw Object.assign(new Error('Route not found'),{statusCode:404});
    const previous=await client.query('SELECT checkpoint_id,instructions,requires_confirmation,requires_note FROM patrol_route_checkpoints WHERE route_id=$1 AND tenant_id=$2',[routeId,tenantId]);
    const requirements=new Map(previous.rows.map(row=>[Number(row.checkpoint_id),row]));
    await client.query('DELETE FROM patrol_route_checkpoints WHERE route_id=$1 AND tenant_id=$2',[routeId,tenantId]);
    for(let i=0;i<checkpointIds.length;i++){const saved=requirements.get(checkpointIds[i])||{};await client.query('INSERT INTO patrol_route_checkpoints (tenant_id,route_id,checkpoint_id,position,instructions,requires_confirmation,requires_note) VALUES ($1,$2,$3,$4,$5,$6,$7)',[tenantId,routeId,checkpointIds[i],i+1,saved.instructions||null,Boolean(saved.requires_confirmation),Boolean(saved.requires_note)]);}
    await client.query('COMMIT'); res.json(updated.rows[0]);
  } catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.code==='23505'?'A route with this name already exists at the site':err.message});} finally{client.release();}
});

app.patch('/api/patrol-routes/:routeId/checkpoints/:checkpointId',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`UPDATE patrol_route_checkpoints SET instructions=$1,requires_confirmation=$2,requires_note=$3 WHERE route_id=$4 AND checkpoint_id=$5 AND tenant_id=$6 RETURNING *`,[String(req.body.instructions||'').trim()||null,Boolean(req.body.requires_confirmation),Boolean(req.body.requires_note),req.params.routeId,req.params.checkpointId,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Route checkpoint not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}
});

app.delete('/api/patrol-routes/:id', requireAuth, requireAdmin, async (req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query('DELETE FROM patrol_routes WHERE id=$1 AND tenant_id=$2 RETURNING id',[req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Route not found'});res.json({deleted:true});}catch(err){res.status(500).json({error:err.message});}
});

async function refreshPatrolRunStatuses(client, tenantId) {
  await client.query(`UPDATE patrol_runs SET status='missed'
    WHERE tenant_id=$1 AND status='scheduled' AND NOW()>scheduled_end+(grace_minutes*INTERVAL '1 minute')`,[tenantId]);
}

async function runPatrolAlertSweep() {
  try {
    await pool.query(`UPDATE patrol_runs SET status='missed' WHERE status='scheduled' AND NOW()>scheduled_end+(grace_minutes*INTERVAL '1 minute')`);
    await pool.query(`INSERT INTO patrol_alerts (tenant_id,run_id,alert_type,severity,message)
      SELECT pr.tenant_id,pr.id,'late_start','warning','Patrol has not started within its grace period'
      FROM patrol_runs pr WHERE pr.status='scheduled' AND NOW()>pr.scheduled_start+(pr.grace_minutes*INTERVAL '1 minute')
      ON CONFLICT (run_id,alert_type) DO NOTHING`);
    await pool.query(`INSERT INTO patrol_alerts (tenant_id,run_id,alert_type,severity,message)
      SELECT pr.tenant_id,pr.id,'overdue','critical','Patrol is still incomplete after its scheduled end time'
      FROM patrol_runs pr WHERE pr.status='in_progress' AND NOW()>pr.scheduled_end+(pr.grace_minutes*INTERVAL '1 minute')
      ON CONFLICT (run_id,alert_type) DO NOTHING`);
    await pool.query(`INSERT INTO patrol_alerts (tenant_id,run_id,alert_type,severity,message)
      SELECT pr.tenant_id,pr.id,'missed','critical','Patrol was not started before its scheduled window expired'
      FROM patrol_runs pr WHERE pr.status='missed'
      ON CONFLICT (run_id,alert_type) DO NOTHING`);
    await pool.query(`UPDATE patrol_alerts pa SET status='resolved',resolved_at=NOW(),resolution_notes='Automatically resolved when patrol activity resumed'
      FROM patrol_runs pr WHERE pa.run_id=pr.id AND pa.status<>'resolved' AND (pr.status='cancelled' OR (pa.alert_type='late_start' AND pr.status IN ('in_progress','completed')) OR (pa.alert_type='overdue' AND pr.status='completed'))`);
  } catch(err) { console.error('Patrol alert sweep failed:',err.message); }
}
setInterval(runPatrolAlertSweep,60000);
setTimeout(runPatrolAlertSweep,20000);

app.post('/api/patrol-runs', requireAuth, requireAdmin, async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id),routeId=Number(req.body.route_id),userId=Number(req.body.user_id);
  const start=new Date(req.body.scheduled_start),end=new Date(req.body.scheduled_end),grace=Math.max(0,Math.min(120,Number(req.body.grace_minutes??15)));
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!routeId||!userId||isNaN(start)||isNaN(end)||end<=start)return res.status(400).json({error:'Route, guard, and a valid start/end period are required'});
  try{const result=await withTenant(tenantId,async client=>{const eligible=await client.query(`SELECT r.site_id FROM patrol_routes r JOIN guard_assignments ga ON ga.site_id=r.site_id AND ga.tenant_id=r.tenant_id AND ga.user_id=$3 WHERE r.id=$1 AND r.tenant_id=$2 AND r.active=TRUE`,[routeId,tenantId,userId]);if(!eligible.rows.length)throw Object.assign(new Error('Guard must be assigned to the route site'),{statusCode:400});return client.query(`INSERT INTO patrol_runs (tenant_id,route_id,site_id,user_id,scheduled_start,scheduled_end,grace_minutes,notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[tenantId,routeId,eligible.rows[0].site_id,userId,start.toISOString(),end.toISOString(),grace,req.body.notes||null]);});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.get('/api/patrol-runs',requireAuth,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const requestedUser=req.query.user_id?Number(req.query.user_id):null,userId=req.auth.role==='admin'?requestedUser:req.auth.user_id;
  try{const result=await withTenant(tenantId,async client=>{await refreshPatrolRunStatuses(client,tenantId);const params=[tenantId];let where='pr.tenant_id=$1';if(userId){params.push(userId);where+=` AND pr.user_id=$${params.length}`;}if(req.query.from_date){params.push(req.query.from_date);where+=` AND pr.scheduled_start >= $${params.length}::date`;}if(req.query.to_date){params.push(req.query.to_date);where+=` AND pr.scheduled_start < ($${params.length}::date+INTERVAL '1 day')`;}return client.query(`SELECT pr.*,CASE WHEN pr.status='scheduled' AND NOW()>pr.scheduled_start+(pr.grace_minutes*INTERVAL '1 minute') THEN 'late' WHEN pr.status='in_progress' AND NOW()>pr.scheduled_end+(pr.grace_minutes*INTERVAL '1 minute') THEN 'incomplete' ELSE pr.status END AS display_status,r.name AS route_name,r.strict_order,r.estimated_minutes,s.name AS site_name,u.email AS guard_email,
      COUNT(rs.id)::int AS scanned_count,(SELECT COUNT(*)::int FROM patrol_route_checkpoints rc WHERE rc.route_id=pr.route_id) AS checkpoint_count,
      COALESCE(json_agg(json_build_object('checkpoint_id',c.id,'name',c.name,'position',rc.position,'instructions',rc.instructions,'requires_confirmation',rc.requires_confirmation,'requires_note',rc.requires_note,'scanned_at',rs.scanned_at,'checkpoint_note',rs.checkpoint_note,'instruction_confirmed',rs.instruction_confirmed) ORDER BY rc.position) FILTER(WHERE c.id IS NOT NULL),'[]') AS checkpoints
      FROM patrol_runs pr JOIN patrol_routes r ON r.id=pr.route_id JOIN sites s ON s.id=pr.site_id JOIN users u ON u.id=pr.user_id
      LEFT JOIN patrol_route_checkpoints rc ON rc.route_id=pr.route_id LEFT JOIN checkpoints c ON c.id=rc.checkpoint_id
      LEFT JOIN patrol_run_scans rs ON rs.run_id=pr.id AND rs.checkpoint_id=rc.checkpoint_id WHERE ${where}
      GROUP BY pr.id,r.name,r.strict_order,r.estimated_minutes,s.name,u.email ORDER BY pr.scheduled_start DESC LIMIT 500`,params);});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}
});

app.patch('/api/patrol-runs/:id/start',requireAuth,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,async client=>{await refreshPatrolRunStatuses(client,tenantId);const params=[req.params.id,tenantId];let query=`UPDATE patrol_runs SET status='in_progress',started_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status='scheduled' AND NOW()>=scheduled_start-INTERVAL '60 minutes' AND NOW()<=scheduled_end+(grace_minutes*INTERVAL '1 minute')`;if(req.auth.role!=='admin'){params.push(req.auth.user_id);query+=` AND user_id=$3`;}query+=' RETURNING *';return client.query(query,params)});if(!result.rows.length)return res.status(409).json({error:'Patrol cannot be started yet, is overdue, or is already started'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}
});

app.patch('/api/patrol-runs/:id/cancel',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query("UPDATE patrol_runs SET status='cancelled',cancelled_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status IN ('scheduled','in_progress') RETURNING *",[req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Patrol cannot be cancelled'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/patrol-alerts',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{await runPatrolAlertSweep();const result=await withTenant(tenantId,client=>{const params=[tenantId];let where='pa.tenant_id=$1';if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND pa.status=$${params.length}`;}if(req.query.severity){params.push(req.query.severity);where+=` AND pa.severity=$${params.length}`;}return client.query(`SELECT pa.*,pr.scheduled_start,pr.scheduled_end,pr.status AS run_status,r.name AS route_name,s.name AS site_name,u.email AS guard_email,
      (SELECT COUNT(*)::int FROM patrol_run_scans rs WHERE rs.run_id=pr.id) AS scanned_count,
      (SELECT COUNT(*)::int FROM patrol_route_checkpoints rc WHERE rc.route_id=pr.route_id) AS checkpoint_count
      FROM patrol_alerts pa JOIN patrol_runs pr ON pr.id=pa.run_id JOIN patrol_routes r ON r.id=pr.route_id JOIN sites s ON s.id=pr.site_id JOIN users u ON u.id=pr.user_id WHERE ${where} ORDER BY CASE pa.severity WHEN 'critical' THEN 1 ELSE 2 END,pa.created_at DESC LIMIT 500`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}
});

app.patch('/api/patrol-alerts/:id/acknowledge',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query("UPDATE patrol_alerts SET status='acknowledged',acknowledged_at=NOW(),acknowledged_by=$1 WHERE id=$2 AND tenant_id=$3 AND status='open' RETURNING *",[req.auth.user_id,req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Alert is no longer open'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/patrol-alerts/:id/resolve',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),notes=String(req.body.resolution_notes||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!notes)return res.status(400).json({error:'Resolution notes are required'});try{const result=await withTenant(tenantId,client=>client.query("UPDATE patrol_alerts SET status='resolved',resolved_at=NOW(),resolved_by=$1,resolution_notes=$2 WHERE id=$3 AND tenant_id=$4 AND status<>'resolved' RETURNING *",[req.auth.user_id,notes,req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Alert is already resolved or unavailable'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/patrol-schedules', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, schedule_type, config } = req.body;
  if (!tenant_id || !site_id || !schedule_type || !config) {
    return res.status(400).json({ error: 'tenant_id, site_id, schedule_type, and config are required' });
  }
  if (!['fixed', 'hourly', 'custom'].includes(schedule_type)) {
    return res.status(400).json({ error: 'schedule_type must be fixed, hourly, or custom' });
  }
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'INSERT INTO patrol_schedules (tenant_id, site_id, schedule_type, config) VALUES ($1, $2, $3, $4) RETURNING *',
        [tenant_id, site_id, schedule_type, JSON.stringify(config)]
      )
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/patrol-schedules', requireAuth, async (req, res) => {
  const { tenant_id, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      site_id
        ? client.query('SELECT * FROM patrol_schedules WHERE tenant_id = $1 AND site_id = $2', [tenant_id, site_id])
        : client.query('SELECT * FROM patrol_schedules WHERE tenant_id = $1', [tenant_id])
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/patrol-schedules/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'DELETE FROM patrol_schedules WHERE id = $1 AND tenant_id = $2 RETURNING *',
        [id, tenant_id]
      )
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Schedule not found' });
    }
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/patrol-logs', requireAuth, async (req, res) => {
  const { tenant_id, checkpoint_id, user_id, latitude, longitude, accuracy, scanned_at, device_scanned_at, patrol_run_id, checkpoint_note, instruction_confirmed } = req.body;
  if (!tenant_id || !checkpoint_id || !user_id) {
    return res.status(400).json({ error: 'tenant_id, checkpoint_id, and user_id are required' });
  }
  const tenantId=attendanceTenant(req,tenant_id);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(req.auth.role!=='admin'&&Number(user_id)!==req.auth.user_id)return res.status(403).json({error:'Guards can only submit their own scans'});

  let scannedAtValue = null;
  if (scanned_at) {
    const parsed = new Date(scanned_at);
    if (isNaN(parsed.getTime())) {
      return res.status(400).json({ error: 'scanned_at must be a valid date' });
    }
    if (parsed.getTime() > Date.now() + 5 * 60000) {
      return res.status(400).json({ error: 'scanned_at cannot be in the future' });
    }
    scannedAtValue = parsed.toISOString();
  }

  if(patrol_run_id){
    const client=await pool.connect();
    try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);
      const runResult=await client.query(`SELECT pr.*,r.strict_order FROM patrol_runs pr JOIN patrol_routes r ON r.id=pr.route_id WHERE pr.id=$1 AND pr.tenant_id=$2 FOR UPDATE`,[patrol_run_id,tenantId]);
      if(!runResult.rows.length)throw Object.assign(new Error('Scheduled patrol not found'),{statusCode:404});const run=runResult.rows[0];
      if(req.auth.role!=='admin'&&Number(run.user_id)!==req.auth.user_id)throw Object.assign(new Error('This patrol is assigned to another guard'),{statusCode:403});
      if(run.status!=='in_progress')throw Object.assign(new Error('Start this patrol before scanning checkpoints'),{statusCode:409});
      const routeCheckpoint=await client.query(`SELECT rc.position,rc.instructions,rc.requires_confirmation,rc.requires_note,s.latitude,s.longitude,s.geofence_enabled,s.geofence_radius_m FROM patrol_route_checkpoints rc JOIN checkpoints c ON c.id=rc.checkpoint_id JOIN sites s ON s.id=c.site_id WHERE rc.route_id=$1 AND rc.checkpoint_id=$2`,[run.route_id,checkpoint_id]);
      if(!routeCheckpoint.rows.length)throw Object.assign(new Error('This checkpoint is not part of the active patrol route'),{statusCode:400});
      const position=routeCheckpoint.rows[0].position;
      if(routeCheckpoint.rows[0].requires_confirmation&&!instruction_confirmed)throw Object.assign(new Error('You must acknowledge the checkpoint instructions before scanning'),{statusCode:400});
      if(routeCheckpoint.rows[0].requires_note&&!String(checkpoint_note||'').trim())throw Object.assign(new Error('A written checkpoint observation is required'),{statusCode:400});
      const evidence=patrolScanEvidence(routeCheckpoint.rows[0],latitude,longitude,accuracy);
      if(routeCheckpoint.rows[0].geofence_enabled&&evidence.status==='unavailable')throw Object.assign(new Error('GPS location is required for this patrol checkpoint'),{statusCode:400});
      if(routeCheckpoint.rows[0].geofence_enabled&&evidence.status==='outside')throw Object.assign(new Error('Scan rejected: you are '+Math.round(evidence.distance)+'m from the site geofence'),{statusCode:403});
      const already=await client.query('SELECT 1 FROM patrol_run_scans WHERE run_id=$1 AND checkpoint_id=$2',[patrol_run_id,checkpoint_id]);
      if(already.rows.length)throw Object.assign(new Error('This checkpoint has already been scanned for this patrol'),{statusCode:409});
      if(run.strict_order){const next=await client.query(`SELECT rc.position,c.name FROM patrol_route_checkpoints rc JOIN checkpoints c ON c.id=rc.checkpoint_id WHERE rc.route_id=$1 AND NOT EXISTS(SELECT 1 FROM patrol_run_scans rs WHERE rs.run_id=$2 AND rs.checkpoint_id=rc.checkpoint_id) ORDER BY rc.position LIMIT 1`,[run.route_id,patrol_run_id]);if(next.rows.length&&Number(next.rows[0].position)!==Number(position))throw Object.assign(new Error('Wrong checkpoint order. Scan next: '+next.rows[0].name),{statusCode:409});}
      const log=await client.query(`INSERT INTO patrol_logs (tenant_id,checkpoint_id,user_id,latitude,longitude,scanned_at,patrol_run_id,accuracy_m,distance_m,location_status,device_scanned_at) VALUES ($1,$2,$3,$4,$5,COALESCE($6::timestamptz,NOW()),$7,$8,$9,$10,$11) RETURNING *`,[tenantId,checkpoint_id,user_id,latitude||null,longitude||null,scannedAtValue,patrol_run_id,evidence.accuracy,evidence.distance,evidence.status,device_scanned_at||scannedAtValue]);
      await client.query('INSERT INTO patrol_run_scans (tenant_id,run_id,checkpoint_id,patrol_log_id,position,scanned_at,checkpoint_note,instruction_confirmed) VALUES ($1,$2,$3,$4,$5,COALESCE($6::timestamptz,NOW()),$7,$8)',[tenantId,patrol_run_id,checkpoint_id,log.rows[0].id,position,scannedAtValue,String(checkpoint_note||'').trim()||null,Boolean(instruction_confirmed)]);
      const counts=await client.query(`SELECT (SELECT COUNT(*) FROM patrol_route_checkpoints WHERE route_id=$1)::int total,(SELECT COUNT(*) FROM patrol_run_scans WHERE run_id=$2)::int scanned`,[run.route_id,patrol_run_id]);const complete=counts.rows[0].scanned>=counts.rows[0].total;
      if(complete)await client.query("UPDATE patrol_runs SET status='completed',completed_at=NOW() WHERE id=$1",[patrol_run_id]);
      await client.query('COMMIT');return res.status(201).json({...log.rows[0],patrol_run_id:Number(patrol_run_id),patrol_complete:complete,scanned_count:counts.rows[0].scanned,checkpoint_count:counts.rows[0].total});
    }catch(err){await client.query('ROLLBACK');return res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}
  }

  try {
    const result = await withTenant(tenant_id, async client => {
      const siteResult=await client.query(`SELECT s.latitude,s.longitude,s.geofence_enabled,s.geofence_radius_m FROM checkpoints c JOIN sites s ON s.id=c.site_id WHERE c.id=$1 AND c.tenant_id=$2`,[checkpoint_id,tenantId]);
      if(!siteResult.rows.length)throw Object.assign(new Error('Checkpoint not found'),{statusCode:404});
      const evidence=patrolScanEvidence(siteResult.rows[0],latitude,longitude,accuracy);
      return client.query(`INSERT INTO patrol_logs (tenant_id,checkpoint_id,user_id,latitude,longitude,scanned_at,accuracy_m,distance_m,location_status,device_scanned_at) VALUES ($1,$2,$3,$4,$5,COALESCE($6::timestamptz,NOW()),$7,$8,$9,$10) RETURNING *`,[tenantId,checkpoint_id,user_id,latitude||null,longitude||null,scannedAtValue,evidence.accuracy,evidence.distance,evidence.status,device_scanned_at||scannedAtValue]);
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(err.statusCode||500).json({ error: err.message });
  }
});

app.get('/api/patrol-logs', requireAuth, async (req, res) => {
  const { tenant_id, checkpoint_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      checkpoint_id
        ? client.query('SELECT * FROM patrol_logs WHERE tenant_id = $1 AND checkpoint_id = $2 ORDER BY scanned_at DESC', [tenant_id, checkpoint_id])
        : client.query('SELECT * FROM patrol_logs WHERE tenant_id = $1 ORDER BY scanned_at DESC', [tenant_id])
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/patrol-evidence',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>{const params=[tenantId];let where='pl.tenant_id=$1';if(req.query.site_id){params.push(req.query.site_id);where+=` AND c.site_id=$${params.length}`;}if(req.query.location_status){params.push(req.query.location_status);where+=` AND pl.location_status=$${params.length}`;}if(req.query.from_date){params.push(req.query.from_date);where+=` AND pl.scanned_at >= $${params.length}::date`;}if(req.query.to_date){params.push(req.query.to_date);where+=` AND pl.scanned_at < ($${params.length}::date+INTERVAL '1 day')`;}return client.query(`SELECT pl.id,pl.scanned_at,pl.received_at,pl.device_scanned_at,pl.latitude,pl.longitude,pl.accuracy_m,pl.distance_m,pl.location_status,pl.patrol_run_id,c.name AS checkpoint_name,s.name AS site_name,u.email AS guard_email,r.name AS route_name,rs.checkpoint_note,rs.instruction_confirmed FROM patrol_logs pl JOIN checkpoints c ON c.id=pl.checkpoint_id JOIN sites s ON s.id=c.site_id JOIN users u ON u.id=pl.user_id LEFT JOIN patrol_runs pr ON pr.id=pl.patrol_run_id LEFT JOIN patrol_routes r ON r.id=pr.route_id LEFT JOIN patrol_run_scans rs ON rs.patrol_log_id=pl.id WHERE ${where} ORDER BY pl.scanned_at DESC LIMIT 1000`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/patrol-compliance', requireAuth, async (req, res) => {
  const { tenant_id, site_id } = req.query;
  if (!tenant_id || !site_id) {
    return res.status(400).json({ error: 'tenant_id and site_id are required' });
  }
  try {
    const compliance = await withTenant(tenant_id, (client) => computeSiteCompliance(client, tenant_id, site_id));
    res.json(compliance);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ CLIENT SERVICE CONTRACTS & SLAS ------------------------

function validPercent(value){const n=Number(value);return Number.isFinite(n)&&n>=0&&n<=100;}

function reportPeriod(runDate,frequency){const d=DateTime.fromISO(String(runDate).slice(0,10),{zone:'UTC'});if(frequency==='weekly')return{start:d.minus({days:7}),end:d.minus({days:1}),next:d.plus({weeks:1})};if(frequency==='quarterly')return{start:d.startOf('month').minus({months:3}),end:d.startOf('month').minus({days:1}),next:d.plus({months:3})};return{start:d.startOf('month').minus({months:1}),end:d.startOf('month').minus({days:1}),next:d.plus({months:1})};}

async function runClientReportSweep(){const client=await pool.connect();try{await client.query('BEGIN');const due=await client.query(`SELECT * FROM client_report_schedules WHERE active=TRUE AND next_run_date<=CURRENT_DATE ORDER BY next_run_date FOR UPDATE SKIP LOCKED`);for(const schedule of due.rows){const period=reportPeriod(schedule.next_run_date,schedule.frequency);await client.query(`INSERT INTO client_report_runs (tenant_id,schedule_id,contract_id,period_start,period_end,recipient_email) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (schedule_id,period_start,period_end) DO NOTHING`,[schedule.tenant_id,schedule.id,schedule.contract_id,period.start.toISODate(),period.end.toISODate(),schedule.recipient_email]);await client.query('UPDATE client_report_schedules SET next_run_date=$1,updated_at=NOW() WHERE id=$2',[period.next.toISODate(),schedule.id]);}await client.query('COMMIT');}catch(err){await client.query('ROLLBACK');console.error('Client report sweep failed:',err.message);}finally{client.release();}}
setInterval(runClientReportSweep,60*60*1000);setTimeout(runClientReportSweep,25000);

app.get('/api/service-contracts',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,async client=>{await client.query("UPDATE service_contracts SET status='expired',updated_at=NOW() WHERE tenant_id=$1 AND status='active' AND end_date<CURRENT_DATE",[tenantId]);const params=[tenantId];let where='sc.tenant_id=$1';if(req.query.site_id){params.push(req.query.site_id);where+=` AND sc.site_id=$${params.length}`;}if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND sc.status=$${params.length}`;}return client.query(`SELECT sc.*,s.name AS site_name,u.email AS created_by_email FROM service_contracts sc JOIN sites s ON s.id=sc.site_id LEFT JOIN users u ON u.id=sc.created_by WHERE ${where} ORDER BY sc.start_date DESC,sc.id DESC`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/service-contracts',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),clientName=String(req.body.client_name||'').trim(),start=req.body.start_date,end=req.body.end_date||null,billing=['monthly','hourly','per_patrol','fixed'].includes(req.body.billing_model)?req.body.billing_model:'monthly',status=['draft','active','suspended'].includes(req.body.status)?req.body.status:'draft';if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!clientName||!start)return res.status(400).json({error:'Site, client name, and start date are required'});if(end&&new Date(end)<new Date(start))return res.status(400).json({error:'End date cannot be before start date'});if(!validPercent(req.body.sla_patrol_completion_pct)||!validPercent(req.body.sla_shift_coverage_pct))return res.status(400).json({error:'SLA percentages must be between 0 and 100'});try{const result=await withTenant(tenantId,async client=>{const site=await client.query('SELECT 1 FROM sites WHERE id=$1 AND tenant_id=$2',[siteId,tenantId]);if(!site.rows.length)throw Object.assign(new Error('Site not found'),{statusCode:404});let reference=String(req.body.reference_code||'').trim();if(!reference){const sequence=await client.query('SELECT COALESCE(MAX(id),0)+1 AS next FROM service_contracts WHERE tenant_id=$1',[tenantId]);reference='CTR-'+new Date().getUTCFullYear()+'-'+String(sequence.rows[0].next).padStart(5,'0');}return client.query(`INSERT INTO service_contracts (tenant_id,site_id,reference_code,client_name,start_date,end_date,status,billing_model,rate,currency,sla_patrol_completion_pct,sla_incident_ack_minutes,sla_shift_coverage_pct,report_frequency,notes,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,[tenantId,siteId,reference,clientName,start,end,status,billing,req.body.rate||null,String(req.body.currency||'EUR').toUpperCase().slice(0,3),Number(req.body.sla_patrol_completion_pct),Math.max(1,Number(req.body.sla_incident_ack_minutes||15)),Number(req.body.sla_shift_coverage_pct),['weekly','monthly','quarterly'].includes(req.body.report_frequency)?req.body.report_frequency:'monthly',req.body.notes||null,req.auth.user_id])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.code==='23505'?'Contract reference already exists':err.message});}});

app.put('/api/service-contracts/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),start=req.body.start_date,end=req.body.end_date||null;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!String(req.body.client_name||'').trim()||!start)return res.status(400).json({error:'Site, client name, and start date are required'});if(end&&new Date(end)<new Date(start))return res.status(400).json({error:'End date cannot be before start date'});if(!validPercent(req.body.sla_patrol_completion_pct)||!validPercent(req.body.sla_shift_coverage_pct))return res.status(400).json({error:'SLA percentages must be between 0 and 100'});try{const result=await withTenant(tenantId,client=>client.query(`UPDATE service_contracts SET site_id=$1,reference_code=$2,client_name=$3,start_date=$4,end_date=$5,status=$6,billing_model=$7,rate=$8,currency=$9,sla_patrol_completion_pct=$10,sla_incident_ack_minutes=$11,sla_shift_coverage_pct=$12,report_frequency=$13,notes=$14,updated_at=NOW() WHERE id=$15 AND tenant_id=$16 RETURNING *`,[siteId,String(req.body.reference_code||'').trim(),String(req.body.client_name).trim(),start,end,['draft','active','suspended','expired'].includes(req.body.status)?req.body.status:'draft',['monthly','hourly','per_patrol','fixed'].includes(req.body.billing_model)?req.body.billing_model:'monthly',req.body.rate||null,String(req.body.currency||'EUR').toUpperCase().slice(0,3),Number(req.body.sla_patrol_completion_pct),Math.max(1,Number(req.body.sla_incident_ack_minutes||15)),Number(req.body.sla_shift_coverage_pct),['weekly','monthly','quarterly'].includes(req.body.report_frequency)?req.body.report_frequency:'monthly',req.body.notes||null,req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Contract not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.code==='23505'?'Contract reference already exists':err.message});}});

app.patch('/api/service-contracts/:id/status',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),status=req.body.status;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['draft','active','suspended','expired'].includes(status))return res.status(400).json({error:'Invalid contract status'});try{const result=await withTenant(tenantId,client=>client.query('UPDATE service_contracts SET status=$1,updated_at=NOW() WHERE id=$2 AND tenant_id=$3 RETURNING *',[status,req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Contract not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/sla-performance',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id),from=req.query.from_date,to=req.query.to_date;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!from||!to||isNaN(new Date(from))||isNaN(new Date(to))||new Date(to)<new Date(from))return res.status(400).json({error:'Valid from_date and to_date are required'});try{const contracts=await withTenant(tenantId,client=>{const params=[tenantId,from,to];let siteFilter='';if(req.query.site_id){params.push(req.query.site_id);siteFilter=` AND sc.site_id=$${params.length}`;}return client.query(`SELECT sc.*,s.name AS site_name,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=sc.tenant_id AND pr.site_id=sc.site_id AND pr.status<>'cancelled' AND pr.scheduled_start::date BETWEEN $2::date AND $3::date AND pr.scheduled_end<=NOW()) AS patrol_total,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=sc.tenant_id AND pr.site_id=sc.site_id AND pr.status='completed' AND pr.scheduled_start::date BETWEEN $2::date AND $3::date AND pr.scheduled_end<=NOW()) AS patrol_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $2::date AND $3::date) AS incident_total,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $2::date AND $3::date AND i.acknowledged_at IS NOT NULL AND i.acknowledged_at<=i.reported_at+(sc.sla_incident_ack_minutes*INTERVAL '1 minute')) AS incident_ack_met,
      (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (i.acknowledged_at-i.reported_at))/60)::numeric,1) FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $2::date AND $3::date AND i.acknowledged_at IS NOT NULL) AS incident_avg_ack_minutes,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=sc.tenant_id AND sh.site_id=sc.site_id AND sh.shift_date BETWEEN $2::date AND $3::date) AS shift_total,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=sc.tenant_id AND sh.site_id=sc.site_id AND sh.shift_date BETWEEN $2::date AND $3::date AND sh.assignment_status='assigned') AS shift_covered
      FROM service_contracts sc JOIN sites s ON s.id=sc.site_id WHERE sc.tenant_id=$1 AND sc.status='active' AND sc.start_date<=$3::date AND (sc.end_date IS NULL OR sc.end_date>=$2::date)${siteFilter} ORDER BY s.name,sc.id`,params)});const rows=contracts.rows.map(c=>{const pct=(n,d)=>d?Math.round(n/d*10000)/100:null,patrol=pct(c.patrol_completed,c.patrol_total),incident=pct(c.incident_ack_met,c.incident_total),coverage=pct(c.shift_covered,c.shift_total);const metric=(actual,target)=>({actual,target:Number(target),status:actual===null?'no_data':actual>=Number(target)?'met':'missed'});const metrics={patrol:metric(patrol,c.sla_patrol_completion_pct),incident:metric(incident,100),coverage:metric(coverage,c.sla_shift_coverage_pct)};return{contract_id:c.id,reference_code:c.reference_code,client_name:c.client_name,site_id:c.site_id,site_name:c.site_name,from_date:from,to_date:to,patrol:{...metrics.patrol,completed:c.patrol_completed,total:c.patrol_total},incident:{...metrics.incident,within_sla:c.incident_ack_met,total:c.incident_total,target_minutes:c.sla_incident_ack_minutes,average_minutes:c.incident_avg_ack_minutes===null?null:Number(c.incident_avg_ack_minutes)},coverage:{...metrics.coverage,covered:c.shift_covered,total:c.shift_total},overall_status:Object.values(metrics).some(m=>m.status==='missed')?'missed':Object.values(metrics).every(m=>m.status==='no_data')?'no_data':'met'};});res.json(rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/client-report-schedules',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{await runClientReportSweep();const result=await withTenant(tenantId,client=>client.query(`SELECT crs.*,sc.reference_code,sc.client_name,sc.site_id,s.name AS site_name FROM client_report_schedules crs JOIN service_contracts sc ON sc.id=crs.contract_id JOIN sites s ON s.id=sc.site_id WHERE crs.tenant_id=$1 ORDER BY crs.active DESC,crs.next_run_date`,[tenantId]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/client-report-schedules',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),contractId=Number(req.body.contract_id),email=String(req.body.recipient_email||'').trim().toLowerCase(),frequency=['weekly','monthly','quarterly'].includes(req.body.frequency)?req.body.frequency:'monthly',next=req.body.next_run_date;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!contractId||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!next||isNaN(new Date(next)))return res.status(400).json({error:'Contract, valid recipient email, and next run date are required'});try{const result=await withTenant(tenantId,async client=>{const contract=await client.query('SELECT 1 FROM service_contracts WHERE id=$1 AND tenant_id=$2',[contractId,tenantId]);if(!contract.rows.length)throw Object.assign(new Error('Contract not found'),{statusCode:404});return client.query(`INSERT INTO client_report_schedules (tenant_id,contract_id,recipient_email,frequency,next_run_date,created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,[tenantId,contractId,email,frequency,next,req.auth.user_id])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.code==='23505'?'A report schedule already exists for this contract and recipient':err.message});}});

app.patch('/api/client-report-schedules/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`UPDATE client_report_schedules SET active=COALESCE($1,active),frequency=COALESCE($2,frequency),next_run_date=COALESCE($3,next_run_date),updated_at=NOW() WHERE id=$4 AND tenant_id=$5 RETURNING *`,[typeof req.body.active==='boolean'?req.body.active:null,['weekly','monthly','quarterly'].includes(req.body.frequency)?req.body.frequency:null,req.body.next_run_date||null,req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Report schedule not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/client-report-runs',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{await runClientReportSweep();const result=await withTenant(tenantId,client=>client.query(`SELECT crr.*,sc.reference_code,sc.client_name,s.name AS site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.tenant_id=$1 ORDER BY crr.generated_at DESC LIMIT 500`,[tenantId]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/client-report-runs',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),contractId=Number(req.body.contract_id),start=req.body.period_start,end=req.body.period_end;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!contractId||!start||!end||isNaN(new Date(start))||isNaN(new Date(end))||new Date(end)<new Date(start))return res.status(400).json({error:'Contract and valid report period are required'});try{const result=await withTenant(tenantId,async client=>{const contract=await client.query('SELECT 1 FROM service_contracts WHERE id=$1 AND tenant_id=$2',[contractId,tenantId]);if(!contract.rows.length)throw Object.assign(new Error('Contract not found'),{statusCode:404});return client.query(`INSERT INTO client_report_runs (tenant_id,contract_id,period_start,period_end,status) VALUES ($1,$2,$3,$4,'generated') RETURNING *`,[tenantId,contractId,start,end])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});

app.patch('/api/client-report-runs/:id/delivered',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`UPDATE client_report_runs SET status='delivered',delivered_at=NOW(),delivered_by=$1,delivery_notes=$2 WHERE id=$3 AND tenant_id=$4 RETURNING *`,[req.auth.user_id,req.body.delivery_notes||null,req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Report run not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/client-report-runs/:id/pdf',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const data=await withTenant(tenantId,async client=>{const run=(await client.query(`SELECT crr.*,sc.reference_code,sc.client_name,sc.site_id,sc.sla_patrol_completion_pct,sc.sla_incident_ack_minutes,sc.sla_shift_coverage_pct,s.name AS site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.id=$1 AND crr.tenant_id=$2`,[req.params.id,tenantId])).rows[0];if(!run)throw Object.assign(new Error('Report run not found'),{statusCode:404});const counts=(await client.query(`SELECT (SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status<>'cancelled')::int patrol_total,(SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status='completed')::int patrol_completed,(SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND site_id=$2 AND reported_at::date BETWEEN $3 AND $4)::int incidents,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4)::int shifts,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4 AND assignment_status='assigned')::int covered`,[tenantId,run.site_id,run.period_start,run.period_end])).rows[0];return{run,counts}});const {run,counts}=data,pct=(a,b)=>b?Math.round(a/b*10000)/100:null;res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`attachment; filename="${run.reference_code}-${run.period_start}-${run.period_end}.pdf"`);const doc=new PDFDocument({margin:50});doc.pipe(res);doc.fontSize(20).text('PatrolSync Client Service Report');doc.moveDown().fontSize(12).text(`Client: ${run.client_name}`).text(`Site: ${run.site_name}`).text(`Contract: ${run.reference_code}`).text(`Period: ${String(run.period_start).slice(0,10)} to ${String(run.period_end).slice(0,10)}`);doc.moveDown().fontSize(16).text('Service Performance');doc.moveDown(.5).fontSize(12).text(`Patrol completion: ${counts.patrol_completed}/${counts.patrol_total} (${pct(counts.patrol_completed,counts.patrol_total)??'No data'}%) — Target ${run.sla_patrol_completion_pct}%`).text(`Incidents reported: ${counts.incidents}`).text(`Shift coverage: ${counts.covered}/${counts.shifts} (${pct(counts.covered,counts.shifts)??'No data'}%) — Target ${run.sla_shift_coverage_pct}%`).text(`Incident acknowledgement target: ${run.sla_incident_ack_minutes} minutes`);doc.moveDown().fontSize(9).fillColor('#666').text(`Generated ${new Date().toISOString()} · Report run #${run.id}`);doc.end();}catch(err){if(!res.headersSent)res.status(err.statusCode||500).json({error:err.message});}});

// Client-facing contract, SLA and delivered report access. Site scope comes only from the signed client JWT.
app.get('/api/client-portal/service-overview',requireAuth,requireClient,async(req,res)=>{
  const {tenant_id,site_id}=req.auth,from=req.query.from_date,to=req.query.to_date;
  if(!from||!to||isNaN(new Date(from))||isNaN(new Date(to))||new Date(to)<new Date(from))return res.status(400).json({error:'Valid from_date and to_date are required'});
  try{
    const result=await withTenant(tenant_id,client=>client.query(`SELECT sc.id,sc.reference_code,sc.client_name,sc.start_date,sc.end_date,sc.status,sc.billing_model,sc.rate,sc.currency,sc.sla_patrol_completion_pct,sc.sla_incident_ack_minutes,sc.sla_shift_coverage_pct,sc.report_frequency,s.name AS site_name,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=sc.tenant_id AND pr.site_id=sc.site_id AND pr.status<>'cancelled' AND pr.scheduled_start::date BETWEEN $3::date AND $4::date AND pr.scheduled_end<=NOW()) AS patrol_total,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=sc.tenant_id AND pr.site_id=sc.site_id AND pr.status='completed' AND pr.scheduled_start::date BETWEEN $3::date AND $4::date AND pr.scheduled_end<=NOW()) AS patrol_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $3::date AND $4::date) AS incident_total,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $3::date AND $4::date AND i.acknowledged_at IS NOT NULL AND i.acknowledged_at<=i.reported_at+(sc.sla_incident_ack_minutes*INTERVAL '1 minute')) AS incident_ack_met,
      (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (i.acknowledged_at-i.reported_at))/60)::numeric,1) FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $3::date AND $4::date AND i.acknowledged_at IS NOT NULL) AS incident_avg_ack_minutes,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=sc.tenant_id AND sh.site_id=sc.site_id AND sh.shift_date BETWEEN $3::date AND $4::date) AS shift_total,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=sc.tenant_id AND sh.site_id=sc.site_id AND sh.shift_date BETWEEN $3::date AND $4::date AND sh.assignment_status='assigned') AS shift_covered
      FROM service_contracts sc JOIN sites s ON s.id=sc.site_id WHERE sc.tenant_id=$1 AND sc.site_id=$2 AND sc.status='active' AND sc.start_date<=$4::date AND (sc.end_date IS NULL OR sc.end_date>=$3::date) ORDER BY sc.start_date DESC`,[tenant_id,site_id,from,to]));
    const pct=(n,d)=>d?Math.round(Number(n)/Number(d)*10000)/100:null;
    res.json(result.rows.map(c=>{const patrol=pct(c.patrol_completed,c.patrol_total),incident=pct(c.incident_ack_met,c.incident_total),coverage=pct(c.shift_covered,c.shift_total),status=(actual,target)=>actual===null?'no_data':actual>=Number(target)?'met':'missed',statuses=[status(patrol,c.sla_patrol_completion_pct),status(incident,100),status(coverage,c.sla_shift_coverage_pct)];return{...c,from_date:from,to_date:to,patrol:{actual:patrol,target:Number(c.sla_patrol_completion_pct),status:statuses[0],completed:c.patrol_completed,total:c.patrol_total},incident:{actual:incident,target:100,status:statuses[1],within_sla:c.incident_ack_met,total:c.incident_total,target_minutes:c.sla_incident_ack_minutes,average_minutes:c.incident_avg_ack_minutes===null?null:Number(c.incident_avg_ack_minutes)},coverage:{actual:coverage,target:Number(c.sla_shift_coverage_pct),status:statuses[2],covered:c.shift_covered,total:c.shift_total},overall_status:statuses.includes('missed')?'missed':statuses.every(x=>x==='no_data')?'no_data':'met'};}));
  }catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/client-portal/service-reports',requireAuth,requireClient,async(req,res)=>{
  const {tenant_id,site_id}=req.auth;
  try{const result=await withTenant(tenant_id,client=>client.query(`SELECT crr.id,crr.period_start,crr.period_end,crr.generated_at,crr.delivered_at,crr.delivery_notes,sc.reference_code,sc.client_name,s.name AS site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.tenant_id=$1 AND sc.site_id=$2 AND crr.status='delivered' ORDER BY crr.period_end DESC,crr.id DESC LIMIT 100`,[tenant_id,site_id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/client-portal/service-reports/:id/pdf',requireAuth,requireClient,async(req,res)=>{
  const {tenant_id,site_id}=req.auth;
  try{const data=await withTenant(tenant_id,async client=>{const run=(await client.query(`SELECT crr.*,sc.reference_code,sc.client_name,sc.site_id,sc.sla_patrol_completion_pct,sc.sla_incident_ack_minutes,sc.sla_shift_coverage_pct,s.name AS site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.id=$1 AND crr.tenant_id=$2 AND sc.site_id=$3 AND crr.status='delivered'`,[req.params.id,tenant_id,site_id])).rows[0];if(!run)throw Object.assign(new Error('Delivered report not found'),{statusCode:404});const counts=(await client.query(`SELECT (SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status<>'cancelled')::int patrol_total,(SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status='completed')::int patrol_completed,(SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND site_id=$2 AND reported_at::date BETWEEN $3 AND $4)::int incidents,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4)::int shifts,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4 AND assignment_status='assigned')::int covered`,[tenant_id,site_id,run.period_start,run.period_end])).rows[0];return{run,counts};});const {run,counts}=data,pct=(a,b)=>b?Math.round(a/b*10000)/100:'No data';res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`attachment; filename="${run.reference_code}-${String(run.period_start).slice(0,10)}-${String(run.period_end).slice(0,10)}.pdf"`);const doc=new PDFDocument({margin:50});doc.pipe(res);doc.fontSize(20).text('PatrolSync Client Service Report');doc.moveDown().fontSize(12).text(`Client: ${run.client_name}`).text(`Site: ${run.site_name}`).text(`Contract: ${run.reference_code}`).text(`Period: ${String(run.period_start).slice(0,10)} to ${String(run.period_end).slice(0,10)}`);doc.moveDown().fontSize(16).text('Service Performance');doc.moveDown(.5).fontSize(12).text(`Patrol completion: ${counts.patrol_completed}/${counts.patrol_total} (${pct(counts.patrol_completed,counts.patrol_total)}%) - Target ${run.sla_patrol_completion_pct}%`).text(`Incidents reported: ${counts.incidents}`).text(`Shift coverage: ${counts.covered}/${counts.shifts} (${pct(counts.covered,counts.shifts)}%) - Target ${run.sla_shift_coverage_pct}%`).text(`Incident acknowledgement target: ${run.sla_incident_ack_minutes} minutes`);doc.moveDown().fontSize(9).fillColor('#666').text(`Delivered report #${run.id}`);doc.end();}catch(err){if(!res.headersSent)res.status(err.statusCode||500).json({error:err.message});}
});

// ------------------------ TRANSACTIONAL EMAIL AUTOMATION ------------------------

const EMAIL_PROVIDER=String(process.env.EMAIL_PROVIDER||'brevo').toLowerCase();
const EMAIL_FROM_ADDRESS=process.env.EMAIL_FROM_ADDRESS||'';
const EMAIL_FROM_NAME=process.env.EMAIL_FROM_NAME||'PatrolSync';
const FRONTEND_URL=String(process.env.FRONTEND_URL||'').replace(/\/$/,'');

function emailHtml(title,body,buttonLabel,buttonUrl){return`<!doctype html><html><body style="font-family:Arial;color:#172033;line-height:1.5"><div style="max-width:620px;margin:auto;border:1px solid #dbe2ea;border-radius:10px;padding:24px"><h2>${title}</h2>${body}${buttonUrl?`<p><a href="${buttonUrl}" style="display:inline-block;background:#2563eb;color:white;text-decoration:none;padding:11px 18px;border-radius:6px">${buttonLabel}</a></p>`:''}<p style="color:#64748b;font-size:12px">Sent automatically by PatrolSync.</p></div></body></html>`;}

async function sendProviderEmail({to,subject,html,attachments=[]}){
  if(EMAIL_PROVIDER!=='brevo')throw new Error(`Unsupported EMAIL_PROVIDER: ${EMAIL_PROVIDER}`);
  if(!process.env.BREVO_API_KEY||!EMAIL_FROM_ADDRESS)throw new Error('Brevo is not configured: set BREVO_API_KEY and EMAIL_FROM_ADDRESS');
  const payload={sender:{name:EMAIL_FROM_NAME,email:EMAIL_FROM_ADDRESS},to:[{email:to}],subject,htmlContent:html};
  if(attachments.length)payload.attachment=attachments.map(a=>({name:a.name,content:a.content}));
  const response=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'Content-Type':'application/json','api-key':process.env.BREVO_API_KEY,'accept':'application/json'},body:JSON.stringify(payload)});
  const text=await response.text();let data={};try{data=text?JSON.parse(text):{};}catch{data={message:text};}if(!response.ok)throw new Error(data.message||`Brevo HTTP ${response.status}`);return{provider:'brevo',message_id:data.messageId||null};
}

async function pdfBuffer(build){return new Promise((resolve,reject)=>{const doc=new PDFDocument({margin:50}),parts=[];doc.on('data',d=>parts.push(d));doc.on('end',()=>resolve(Buffer.concat(parts)));doc.on('error',reject);build(doc);doc.end();});}

async function reportEmailAttachment(tenantId,id){return withTenant(tenantId,async client=>{const run=(await client.query(`SELECT crr.*,sc.reference_code,sc.client_name,sc.site_id,sc.sla_patrol_completion_pct,sc.sla_incident_ack_minutes,sc.sla_shift_coverage_pct,s.name AS site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.id=$1 AND crr.tenant_id=$2`,[id,tenantId])).rows[0];if(!run)throw new Error('Report not found');const c=(await client.query(`SELECT (SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status<>'cancelled')::int patrol_total,(SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status='completed')::int patrol_completed,(SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND site_id=$2 AND reported_at::date BETWEEN $3 AND $4)::int incidents,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4)::int shifts,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4 AND assignment_status='assigned')::int covered`,[tenantId,run.site_id,run.period_start,run.period_end])).rows[0],pct=(a,b)=>b?Math.round(a/b*10000)/100:'No data',buffer=await pdfBuffer(doc=>{doc.fontSize(20).text('PatrolSync Client Service Report');doc.moveDown().fontSize(12).text(`Client: ${run.client_name}`).text(`Site: ${run.site_name}`).text(`Contract: ${run.reference_code}`).text(`Period: ${String(run.period_start).slice(0,10)} to ${String(run.period_end).slice(0,10)}`);doc.moveDown().fontSize(16).text('Service Performance');doc.moveDown(.5).fontSize(12).text(`Patrol completion: ${c.patrol_completed}/${c.patrol_total} (${pct(c.patrol_completed,c.patrol_total)}%)`).text(`Incidents reported: ${c.incidents}`).text(`Shift coverage: ${c.covered}/${c.shifts} (${pct(c.covered,c.shifts)}%)`);});return{name:`${run.reference_code}-${String(run.period_start).slice(0,10)}.pdf`,content:buffer.toString('base64')};});}

async function invoiceEmailAttachment(tenantId,id){return withTenant(tenantId,async client=>{const result=await invoiceDetails(client,tenantId,id);if(!result.rows.length)throw new Error('Invoice not found');const i=result.rows[0],money=n=>`${i.currency} ${Number(n).toFixed(2)}`,buffer=await pdfBuffer(doc=>{doc.fontSize(22).text('PatrolSync Invoice').moveDown(.5);doc.fontSize(11).text(`Invoice: ${i.invoice_number}`).text(`Client: ${i.client_name}`).text(`Site: ${i.site_name}`).text(`Period: ${String(i.period_start).slice(0,10)} to ${String(i.period_end).slice(0,10)}`).text(`Due: ${String(i.due_date).slice(0,10)}`).moveDown();i.lines.forEach(line=>doc.text(`${line.description}: ${Number(line.quantity).toFixed(2)} x ${money(line.unit_rate)} = ${money(line.line_total)}`));doc.moveDown().fontSize(14).text(`Total: ${money(i.total)}`,{align:'right'}).fontSize(11).text(`Balance: ${money(Number(i.total)-Number(i.amount_paid))}`,{align:'right'});});return{name:`${i.invoice_number}.pdf`,content:buffer.toString('base64')};});}

async function queueEmail({tenantId,eventType,entityType,entityId,key,to,subject,html}){if(!to)return;await pool.query(`INSERT INTO email_deliveries(tenant_id,event_type,entity_type,entity_id,idempotency_key,recipient_email,subject,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT(idempotency_key,recipient_email) DO NOTHING`,[tenantId,eventType,entityType,entityId,key,String(to).trim().toLowerCase(),subject,JSON.stringify({html})]);}

async function processEmailQueue(limit=20){if(!process.env.BREVO_API_KEY||!EMAIL_FROM_ADDRESS)return;const client=await pool.connect();try{const rows=(await client.query(`UPDATE email_deliveries SET status='sending',attempt_count=attempt_count+1,updated_at=NOW() WHERE id IN (SELECT id FROM email_deliveries WHERE status IN ('queued','failed') AND next_attempt_at<=NOW() AND attempt_count<5 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1) RETURNING *`,[limit])).rows;for(const row of rows){try{const attachments=[];if(row.entity_type==='client_report')attachments.push(await reportEmailAttachment(row.tenant_id,row.entity_id));if(row.entity_type==='invoice')attachments.push(await invoiceEmailAttachment(row.tenant_id,row.entity_id));const sent=await sendProviderEmail({to:row.recipient_email,subject:row.subject,html:row.payload.html,attachments});await client.query(`UPDATE email_deliveries SET status='sent',provider=$1,provider_message_id=$2,sent_at=NOW(),last_error=NULL,updated_at=NOW() WHERE id=$3`,[sent.provider,sent.message_id,row.id]);if(row.entity_type==='client_report')await client.query(`UPDATE client_report_runs SET status='delivered',delivered_at=COALESCE(delivered_at,NOW()),delivery_notes=COALESCE(delivery_notes,'Delivered automatically by email') WHERE id=$1 AND tenant_id=$2`,[row.entity_id,row.tenant_id]);}catch(err){const delay=Math.min(1440,Math.pow(2,row.attempt_count)*5);await client.query(`UPDATE email_deliveries SET status='failed',last_error=$1,next_attempt_at=NOW()+($2*INTERVAL '1 minute'),updated_at=NOW() WHERE id=$3`,[String(err.message).slice(0,1000),delay,row.id]);}}}finally{client.release();}}

async function queueTicketNotifications(){const rows=await pool.query(`SELECT c.id,c.tenant_id,c.author_type,c.comment,st.reference_code,st.subject,cu.email client_email,COALESCE(assignee.email,admin.email) admin_email FROM service_ticket_comments c JOIN service_tickets st ON st.id=c.ticket_id LEFT JOIN client_users cu ON cu.id=st.client_user_id LEFT JOIN users assignee ON assignee.id=st.assigned_to LEFT JOIN LATERAL(SELECT email FROM users WHERE tenant_id=c.tenant_id AND role='admin' ORDER BY id LIMIT 1) admin ON TRUE WHERE c.internal=FALSE AND NOT EXISTS(SELECT 1 FROM email_deliveries e WHERE e.idempotency_key='ticket-comment-'||c.id)`);for(const c of rows.rows){const to=c.author_type==='client'?c.admin_email:c.client_email;if(!to)continue;await queueEmail({tenantId:c.tenant_id,eventType:'ticket_comment',entityType:'service_ticket',entityId:c.id,key:`ticket-comment-${c.id}`,to,subject:`${c.reference_code}: ${c.subject}`,html:emailHtml('Service ticket update',`<p><b>${c.reference_code}: ${c.subject}</b></p><p>${String(c.comment).replace(/[&<>]/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[x]))}</p>`,c.author_type==='client'?'Open Ticket Queue':'Open Client Portal',FRONTEND_URL&&`${FRONTEND_URL}/${c.author_type==='client'?'service_tickets.html':'client_portal.html'}`)});}}

async function runEmailAutomationSweep(){try{await runClientReportSweep();await queueTicketNotifications();const reports=await pool.query(`SELECT crr.id,crr.tenant_id,crr.recipient_email,crr.period_start,crr.period_end,sc.client_name,s.name site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.status='generated' AND crr.recipient_email IS NOT NULL AND NOT EXISTS(SELECT 1 FROM email_deliveries e WHERE e.idempotency_key='report-'||crr.id)`);for(const r of reports.rows)await queueEmail({tenantId:r.tenant_id,eventType:'client_report',entityType:'client_report',entityId:r.id,key:`report-${r.id}`,to:r.recipient_email,subject:`PatrolSync service report - ${r.site_name}`,html:emailHtml('Your service report is ready',`<p>Please find attached the service report for ${r.site_name}, covering ${String(r.period_start).slice(0,10)} to ${String(r.period_end).slice(0,10)}.</p>`,'Open Client Portal',FRONTEND_URL&&`${FRONTEND_URL}/client_portal.html`)});const invoices=await pool.query(`SELECT i.id,i.tenant_id,i.invoice_number,i.total,i.currency,i.due_date,sc.client_name,sc.site_id,cu.email FROM invoices i JOIN service_contracts sc ON sc.id=i.contract_id JOIN client_users cu ON cu.tenant_id=i.tenant_id AND cu.site_id=sc.site_id WHERE i.status IN ('issued','overdue') AND NOT EXISTS(SELECT 1 FROM email_deliveries e WHERE e.idempotency_key='invoice-'||i.id AND e.recipient_email=LOWER(cu.email))`);for(const i of invoices.rows)await queueEmail({tenantId:i.tenant_id,eventType:'invoice_issued',entityType:'invoice',entityId:i.id,key:`invoice-${i.id}`,to:i.email,subject:`Invoice ${i.invoice_number} from PatrolSync`,html:emailHtml(`Invoice ${i.invoice_number}`,`<p>Your invoice for ${i.currency} ${Number(i.total).toFixed(2)} is attached. Payment is due ${String(i.due_date).slice(0,10)}.</p>`,'View Client Portal',FRONTEND_URL&&`${FRONTEND_URL}/client_portal.html`)});const renewals=await pool.query(`SELECT cr.id,cr.tenant_id,sc.reference_code,sc.client_name,sc.end_date,(sc.end_date-CURRENT_DATE)::int days_remaining,COALESCE(owner.email,admin.email) email FROM contract_renewals cr JOIN service_contracts sc ON sc.id=cr.contract_id LEFT JOIN users owner ON owner.id=cr.owner_user_id LEFT JOIN LATERAL(SELECT email FROM users WHERE tenant_id=cr.tenant_id AND role='admin' ORDER BY id LIMIT 1) admin ON TRUE WHERE cr.status NOT IN ('renewed','lost') AND (sc.end_date-CURRENT_DATE)::int IN (90,60,30,14,7,1,0)`);for(const r of renewals.rows)await queueEmail({tenantId:r.tenant_id,eventType:'renewal_reminder',entityType:'contract_renewal',entityId:r.id,key:`renewal-${r.id}-${r.days_remaining}`,to:r.email,subject:`Contract renewal reminder: ${r.reference_code}`,html:emailHtml('Contract renewal reminder',`<p>${r.client_name} contract ${r.reference_code} expires in ${r.days_remaining} day(s), on ${String(r.end_date).slice(0,10)}.</p>`,'Open Renewals',FRONTEND_URL&&`${FRONTEND_URL}/contract_renewals.html`)});await processEmailQueue();}catch(err){console.error('Email automation sweep failed:',err.message);}}

setInterval(runEmailAutomationSweep,15*60*1000);setTimeout(runEmailAutomationSweep,45000);

app.get('/api/email-deliveries',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const params=[tenantId];let where='tenant_id=$1';if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND status=$${params.length}`;}const result=await withTenant(tenantId,client=>client.query(`SELECT * FROM email_deliveries WHERE ${where} ORDER BY created_at DESC LIMIT 500`,params));res.json({configured:Boolean(process.env.BREVO_API_KEY&&EMAIL_FROM_ADDRESS),provider:EMAIL_PROVIDER,from_address:EMAIL_FROM_ADDRESS||null,deliveries:result.rows});}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/email-deliveries/:id/retry',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`UPDATE email_deliveries SET status='queued',attempt_count=0,last_error=NULL,next_attempt_at=NOW(),updated_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status='failed' RETURNING *`,[req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Only failed deliveries can be retried'});setTimeout(()=>processEmailQueue(),100);res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/email-deliveries/test',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),to=String(req.body.recipient_email||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to))return res.status(400).json({error:'Valid recipient email is required'});try{const key=`test-${tenantId}-${Date.now()}`;await queueEmail({tenantId,eventType:'test',entityType:'test',entityId:null,key,to,subject:'PatrolSync email test',html:emailHtml('PatrolSync email is connected','<p>Your Brevo transactional email integration is working.</p>')});await processEmailQueue(1);const result=await pool.query('SELECT * FROM email_deliveries WHERE idempotency_key=$1 AND recipient_email=$2',[key,to.toLowerCase()]);res.status(result.rows[0]?.status==='sent'?200:502).json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

// ------------------------ CONTRACT RENEWAL MANAGEMENT ------------------------

const renewalStatuses=['not_started','contacted','negotiating','awaiting_client','approved','renewed','lost'];

app.get('/api/contract-renewals',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,async client=>{await client.query(`INSERT INTO contract_renewals(tenant_id,contract_id,proposed_start_date,proposed_rate,proposed_currency) SELECT sc.tenant_id,sc.id,sc.end_date+1,sc.rate,sc.currency FROM service_contracts sc WHERE sc.tenant_id=$1 AND sc.end_date IS NOT NULL AND sc.status IN ('active','expired') AND sc.end_date<=CURRENT_DATE+INTERVAL '180 days' ON CONFLICT(contract_id) DO NOTHING`,[tenantId]);const params=[tenantId];let where='cr.tenant_id=$1';if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND cr.status=$${params.length}`;}return client.query(`SELECT cr.*,sc.reference_code,sc.client_name,sc.site_id,sc.start_date,sc.end_date,sc.status AS contract_status,sc.billing_model,sc.rate AS current_rate,sc.currency AS current_currency,s.name AS site_name,u.email AS owner_email,(sc.end_date-CURRENT_DATE)::int AS days_remaining,(SELECT COUNT(*)::int FROM contract_renewal_history h WHERE h.renewal_id=cr.id) history_count FROM contract_renewals cr JOIN service_contracts sc ON sc.id=cr.contract_id JOIN sites s ON s.id=sc.site_id LEFT JOIN users u ON u.id=cr.owner_user_id WHERE ${where} ORDER BY CASE WHEN sc.end_date<CURRENT_DATE THEN 0 ELSE 1 END,sc.end_date,cr.updated_at DESC`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/contract-renewals',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),contractId=Number(req.body.contract_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!contractId)return res.status(400).json({error:'Contract is required'});try{const result=await withTenant(tenantId,client=>client.query(`INSERT INTO contract_renewals(tenant_id,contract_id,proposed_start_date,proposed_rate,proposed_currency) SELECT tenant_id,id,COALESCE(end_date+1,CURRENT_DATE),rate,currency FROM service_contracts WHERE id=$1 AND tenant_id=$2 ON CONFLICT(contract_id) DO UPDATE SET updated_at=NOW() RETURNING *`,[contractId,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Contract not found'});res.status(201).json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/contract-renewals/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),status=renewalStatuses.includes(req.body.status)?req.body.status:null,owner=req.body.owner_user_id?Number(req.body.owner_user_id):null,start=req.body.proposed_start_date||null,end=req.body.proposed_end_date||null,rate=req.body.proposed_rate===''||req.body.proposed_rate===null?null:Number(req.body.proposed_rate),currency=req.body.proposed_currency?String(req.body.proposed_currency).toUpperCase().slice(0,3):null,note=String(req.body.history_note||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(start&&end&&new Date(end)<new Date(start))return res.status(400).json({error:'Proposed end date cannot be before start date'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);if(owner){const valid=await client.query("SELECT 1 FROM users WHERE id=$1 AND tenant_id=$2 AND role='admin'",[owner,tenantId]);if(!valid.rows.length)throw Object.assign(new Error('Renewal owner must be an administrator'),{statusCode:400});}const result=await client.query(`UPDATE contract_renewals SET status=COALESCE($1,status),owner_user_id=$2,proposed_start_date=COALESCE($3,proposed_start_date),proposed_end_date=$4,proposed_rate=COALESCE($5,proposed_rate),proposed_currency=COALESCE($6,proposed_currency),notes=COALESCE($7,notes),last_contact_at=CASE WHEN $8 THEN NOW() ELSE last_contact_at END,next_follow_up_date=$9,updated_at=NOW() WHERE id=$10 AND tenant_id=$11 RETURNING *`,[status,owner,start,end,Number.isFinite(rate)?rate:null,currency,req.body.notes===undefined?null:String(req.body.notes),req.body.mark_contacted===true,req.body.next_follow_up_date||null,req.params.id,tenantId]);if(!result.rows.length)throw Object.assign(new Error('Renewal not found'),{statusCode:404});if(note||status)await client.query(`INSERT INTO contract_renewal_history(tenant_id,renewal_id,action,note,user_id) VALUES($1,$2,$3,$4,$5)`,[tenantId,req.params.id,status?'status_'+status:'note',note||null,req.auth.user_id]);await client.query('COMMIT');res.json(result.rows[0]);}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}});

app.get('/api/contract-renewals/:id/history',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`SELECT h.*,u.email FROM contract_renewal_history h LEFT JOIN users u ON u.id=h.user_id WHERE h.tenant_id=$1 AND h.renewal_id=$2 ORDER BY h.created_at DESC`,[tenantId,req.params.id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/contract-renewals/:id/complete',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);const row=(await client.query(`SELECT cr.*,sc.* ,cr.id AS renewal_id,sc.id AS source_contract_id FROM contract_renewals cr JOIN service_contracts sc ON sc.id=cr.contract_id WHERE cr.id=$1 AND cr.tenant_id=$2 AND cr.status IN ('approved','negotiating','awaiting_client') FOR UPDATE`,[req.params.id,tenantId])).rows[0];if(!row)throw Object.assign(new Error('Renewal must be approved or active in the pipeline'),{statusCode:409});const start=row.proposed_start_date||DateTime.fromJSDate(new Date(row.end_date)).plus({days:1}).toISODate(),end=row.proposed_end_date||null;if(!start)throw Object.assign(new Error('Set the renewed contract start date'),{statusCode:400});const id=Number((await client.query("SELECT nextval(pg_get_serial_sequence('service_contracts','id')) AS id")).rows[0].id),reference=`${row.reference_code}-R${id}`,rate=row.proposed_rate??row.rate,currency=row.proposed_currency||row.currency;const renewed=(await client.query(`INSERT INTO service_contracts(id,tenant_id,site_id,reference_code,client_name,start_date,end_date,status,billing_model,rate,currency,sla_patrol_completion_pct,sla_incident_ack_minutes,sla_shift_coverage_pct,report_frequency,notes,created_by,previous_contract_id) VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *`,[id,tenantId,row.site_id,reference,row.client_name,start,end,row.billing_model,rate,currency,row.sla_patrol_completion_pct,row.sla_incident_ack_minutes,row.sla_shift_coverage_pct,row.report_frequency,row.notes,req.auth.user_id,row.source_contract_id])).rows[0];await client.query("UPDATE service_contracts SET status='expired',updated_at=NOW() WHERE id=$1",[row.source_contract_id]);await client.query("UPDATE contract_renewals SET status='renewed',completed_contract_id=$1,updated_at=NOW() WHERE id=$2",[id,row.renewal_id]);await client.query(`INSERT INTO contract_renewal_history(tenant_id,renewal_id,action,note,user_id) VALUES($1,$2,'renewed',$3,$4)`,[tenantId,row.renewal_id,`Created ${reference}`,req.auth.user_id]);await client.query('COMMIT');res.status(201).json(renewed);}catch(err){await client.query('ROLLBACK');res.status(err.code==='23505'?409:err.statusCode||500).json({error:err.code==='23505'?'Renewed contract reference already exists':err.message});}finally{client.release();}});

// ------------------------ CLIENT REQUESTS & SERVICE TICKETS ------------------------

const ticketTypes=['general','extra_guard','extra_patrol','incident_follow_up','schedule_change','access','billing'];
const ticketPriorities=['low','normal','high','urgent'];
const ticketStatuses=['open','in_progress','waiting_client','resolved','closed'];

async function canAccessTicket(client,auth,ticketId){
  const result=await client.query('SELECT * FROM service_tickets WHERE id=$1 AND tenant_id=$2',[ticketId,auth.tenant_id]);
  const ticket=result.rows[0];if(!ticket)return null;if(auth.role==='client'&&Number(ticket.site_id)!==Number(auth.site_id))return null;return ticket;
}

app.post('/api/client-portal/service-tickets',requireAuth,requireClient,async(req,res)=>{const {tenant_id,site_id,client_user_id}=req.auth,type=ticketTypes.includes(req.body.request_type)?req.body.request_type:'general',priority=ticketPriorities.includes(req.body.priority)?req.body.priority:'normal',subject=String(req.body.subject||'').trim(),description=String(req.body.description||'').trim();if(!subject||!description)return res.status(400).json({error:'Subject and description are required'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenant_id}'`);const id=Number((await client.query("SELECT nextval(pg_get_serial_sequence('service_tickets','id')) AS id")).rows[0].id),reference=`REQ-${new Date().getUTCFullYear()}-${String(id).padStart(6,'0')}`,ticket=(await client.query(`INSERT INTO service_tickets(id,tenant_id,site_id,client_user_id,reference_code,request_type,subject,description,priority) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,[id,tenant_id,site_id,client_user_id,reference,type,subject,description,priority])).rows[0];await client.query(`INSERT INTO service_ticket_comments(tenant_id,ticket_id,author_type,author_client_user_id,comment) VALUES($1,$2,'client',$3,$4)`,[tenant_id,id,client_user_id,description]);await client.query('COMMIT');res.status(201).json(ticket);}catch(err){await client.query('ROLLBACK');res.status(500).json({error:err.message});}finally{client.release();}});

app.get('/api/client-portal/service-tickets',requireAuth,requireClient,async(req,res)=>{const {tenant_id,site_id}=req.auth;try{const result=await withTenant(tenant_id,client=>client.query(`SELECT st.*,s.name AS site_name,u.email AS assigned_email,(SELECT COUNT(*)::int FROM service_ticket_comments c WHERE c.ticket_id=st.id AND c.internal=FALSE) comment_count FROM service_tickets st JOIN sites s ON s.id=st.site_id LEFT JOIN users u ON u.id=st.assigned_to WHERE st.tenant_id=$1 AND st.site_id=$2 ORDER BY CASE st.status WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'waiting_client' THEN 3 WHEN 'resolved' THEN 4 ELSE 5 END,st.updated_at DESC`,[tenant_id,site_id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/service-tickets',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>{const params=[tenantId];let where='st.tenant_id=$1';if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND st.status=$${params.length}`;}if(req.query.site_id){params.push(req.query.site_id);where+=` AND st.site_id=$${params.length}`;}if(req.query.priority&&req.query.priority!=='all'){params.push(req.query.priority);where+=` AND st.priority=$${params.length}`;}return client.query(`SELECT st.*,s.name AS site_name,cu.email AS client_email,u.email AS assigned_email,(SELECT COUNT(*)::int FROM service_ticket_comments c WHERE c.ticket_id=st.id) comment_count FROM service_tickets st JOIN sites s ON s.id=st.site_id LEFT JOIN client_users cu ON cu.id=st.client_user_id LEFT JOIN users u ON u.id=st.assigned_to WHERE ${where} ORDER BY CASE st.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END,CASE st.status WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'waiting_client' THEN 3 WHEN 'resolved' THEN 4 ELSE 5 END,st.updated_at DESC LIMIT 500`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/service-tickets/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),status=ticketStatuses.includes(req.body.status)?req.body.status:null,priority=ticketPriorities.includes(req.body.priority)?req.body.priority:null,assigned=req.body.assigned_to?Number(req.body.assigned_to):null,resolution=String(req.body.resolution||'').trim()||null;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,async client=>{if(assigned){const user=await client.query("SELECT 1 FROM users WHERE id=$1 AND tenant_id=$2 AND role='admin'",[assigned,tenantId]);if(!user.rows.length)throw Object.assign(new Error('Assigned administrator not found'),{statusCode:400});}return client.query(`UPDATE service_tickets SET status=COALESCE($1,status),priority=COALESCE($2,priority),assigned_to=$3,resolution=COALESCE($4,resolution),resolved_at=CASE WHEN $1='resolved' THEN NOW() WHEN $1 IS NOT NULL AND $1<>'resolved' THEN NULL ELSE resolved_at END,closed_at=CASE WHEN $1='closed' THEN NOW() WHEN $1 IS NOT NULL AND $1<>'closed' THEN NULL ELSE closed_at END,updated_at=NOW() WHERE id=$5 AND tenant_id=$6 RETURNING *`,[status,priority,assigned,resolution,req.params.id,tenantId]);});if(!result.rows.length)return res.status(404).json({error:'Ticket not found'});res.json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});

app.get('/api/service-tickets/:id/comments',requireAuth,async(req,res)=>{try{const ticket=await withTenant(req.auth.tenant_id,client=>canAccessTicket(client,req.auth,req.params.id));if(!ticket)return res.status(404).json({error:'Ticket not found'});const result=await withTenant(req.auth.tenant_id,client=>client.query(`SELECT c.*,u.email AS admin_email,cu.email AS client_email FROM service_ticket_comments c LEFT JOIN users u ON u.id=c.author_user_id LEFT JOIN client_users cu ON cu.id=c.author_client_user_id WHERE c.ticket_id=$1 AND c.tenant_id=$2 ${req.auth.role==='client'?'AND c.internal=FALSE':''} ORDER BY c.created_at`,[req.params.id,req.auth.tenant_id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/service-tickets/:id/comments',requireAuth,async(req,res)=>{const comment=String(req.body.comment||'').trim(),internal=req.auth.role==='admin'&&req.body.internal===true;if(!comment)return res.status(400).json({error:'Comment is required'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${req.auth.tenant_id}'`);const ticket=await canAccessTicket(client,req.auth,req.params.id);if(!ticket)throw Object.assign(new Error('Ticket not found'),{statusCode:404});if(req.auth.role==='client'&&ticket.status==='closed')throw Object.assign(new Error('Closed tickets cannot receive client comments'),{statusCode:409});const result=await client.query(`INSERT INTO service_ticket_comments(tenant_id,ticket_id,author_type,author_user_id,author_client_user_id,comment,internal) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[req.auth.tenant_id,ticket.id,req.auth.role,req.auth.role==='admin'?req.auth.user_id:null,req.auth.role==='client'?req.auth.client_user_id:null,comment,internal]);await client.query(`UPDATE service_tickets SET status=CASE WHEN $1='client' AND status='waiting_client' THEN 'in_progress' ELSE status END,updated_at=NOW() WHERE id=$2`,[req.auth.role,ticket.id]);await client.query('COMMIT');res.status(201).json(result.rows[0]);}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}});

// ------------------------ ADVANCED OPERATIONAL ANALYTICS ------------------------

app.get('/api/operational-analytics',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id),from=req.query.from_date,to=req.query.to_date,siteId=req.query.site_id?Number(req.query.site_id):null;
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const start=DateTime.fromISO(String(from||'')),end=DateTime.fromISO(String(to||''));
  if(!start.isValid||!end.isValid||end<start||end.diff(start,'days').days>366)return res.status(400).json({error:'Choose a valid analytics period of no more than 367 days'});
  try{const data=await withTenant(tenantId,async client=>{
    const p=[tenantId,from,to,siteId];
    const summary=(await client.query(`SELECT
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.shift_date BETWEEN $2 AND $3 AND ($4::int IS NULL OR sh.site_id=$4)) shifts_total,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.shift_date BETWEEN $2 AND $3 AND sh.assignment_status='assigned' AND ($4::int IS NULL OR sh.site_id=$4)) shifts_covered,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.scheduled_start::date BETWEEN $2 AND $3 AND pr.status<>'cancelled' AND ($4::int IS NULL OR pr.site_id=$4)) patrol_total,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.scheduled_start::date BETWEEN $2 AND $3 AND pr.status='completed' AND ($4::int IS NULL OR pr.site_id=$4)) patrol_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.reported_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR i.site_id=$4)) incidents_total,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.reported_at::date BETWEEN $2 AND $3 AND i.status='resolved' AND ($4::int IS NULL OR i.site_id=$4)) incidents_resolved,
      (SELECT ROUND(COALESCE(SUM(EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))-COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0)),0)/3600::numeric,2) FROM attendance_sessions a WHERE a.tenant_id=$1 AND a.clocked_out_at IS NOT NULL AND a.clocked_in_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR a.site_id=$4)) worked_hours,
      (SELECT COUNT(*)::int FROM attendance_sessions a JOIN shifts sh ON sh.id=a.shift_id AND sh.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.clocked_in_at::date BETWEEN $2 AND $3 AND a.clocked_in_at>(sh.shift_date+sh.start_time::time+INTERVAL '5 minutes') AND ($4::int IS NULL OR a.site_id=$4)) late_clockins,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.shift_date BETWEEN $2 AND LEAST($3::date,CURRENT_DATE-1) AND sh.assignment_status='assigned' AND ($4::int IS NULL OR sh.site_id=$4) AND NOT EXISTS(SELECT 1 FROM attendance_sessions a WHERE a.tenant_id=sh.tenant_id AND (a.shift_id=sh.id OR (a.user_id=sh.user_id AND a.site_id=sh.site_id AND a.clocked_in_at::date=sh.shift_date)))) no_shows`,p)).rows[0];
    const daily=(await client.query(`SELECT d::date AS date,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.shift_date=d::date AND ($4::int IS NULL OR sh.site_id=$4)) shifts,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.scheduled_start::date=d::date AND pr.status='completed' AND ($4::int IS NULL OR pr.site_id=$4)) patrols_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.reported_at::date=d::date AND ($4::int IS NULL OR i.site_id=$4)) incidents,
      (SELECT ROUND(COALESCE(SUM(EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))-COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0)),0)/3600::numeric,2) FROM attendance_sessions a WHERE a.tenant_id=$1 AND a.clocked_out_at IS NOT NULL AND a.clocked_in_at::date=d::date AND ($4::int IS NULL OR a.site_id=$4)) worked_hours
      FROM generate_series($2::date,$3::date,INTERVAL '1 day') d ORDER BY d`,p)).rows;
    const sites=(await client.query(`SELECT s.id,s.name,
      COUNT(DISTINCT sh.id)::int shifts,COUNT(DISTINCT sh.id) FILTER(WHERE sh.assignment_status='assigned')::int covered,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.site_id=s.id AND pr.scheduled_start::date BETWEEN $2 AND $3 AND pr.status<>'cancelled') patrol_total,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.site_id=s.id AND pr.scheduled_start::date BETWEEN $2 AND $3 AND pr.status='completed') patrol_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.site_id=s.id AND i.reported_at::date BETWEEN $2 AND $3) incidents
      FROM sites s LEFT JOIN shifts sh ON sh.site_id=s.id AND sh.tenant_id=s.tenant_id AND sh.shift_date BETWEEN $2 AND $3 WHERE s.tenant_id=$1 AND ($4::int IS NULL OR s.id=$4) GROUP BY s.id,s.name ORDER BY s.name`,p)).rows;
    const guards=(await client.query(`SELECT u.id,u.email,
      ROUND(COALESCE(SUM(EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))-COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0)),0)/3600::numeric,2) worked_hours,
      COUNT(DISTINCT a.id)::int sessions,
      COUNT(DISTINCT a.id) FILTER(WHERE sh.id IS NOT NULL AND a.clocked_in_at>(sh.shift_date+sh.start_time::time+INTERVAL '5 minutes'))::int late_clockins,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.user_id=u.id AND pr.scheduled_start::date BETWEEN $2 AND $3 AND pr.status='completed' AND ($4::int IS NULL OR pr.site_id=$4)) patrols_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.user_id=u.id AND i.reported_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR i.site_id=$4)) incidents
      FROM users u LEFT JOIN attendance_sessions a ON a.user_id=u.id AND a.tenant_id=u.tenant_id AND a.clocked_out_at IS NOT NULL AND a.clocked_in_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR a.site_id=$4) LEFT JOIN shifts sh ON sh.id=a.shift_id AND sh.tenant_id=a.tenant_id WHERE u.tenant_id=$1 AND u.role='guard' GROUP BY u.id,u.email ORDER BY worked_hours DESC,u.email`,p)).rows;
    const incidentBreakdown=(await client.query(`SELECT category,severity,COUNT(*)::int AS count FROM incidents WHERE tenant_id=$1 AND reported_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR site_id=$4) GROUP BY category,severity ORDER BY count DESC,category,severity`,p)).rows;
    const overtime=(await client.query(`SELECT COALESCE(SUM(GREATEST(0,weekly_hours-40)),0)::numeric(12,2) overtime_hours FROM (SELECT a.user_id,date_trunc('week',a.clocked_in_at)::date week,ROUND(SUM(EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))-COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0))/3600::numeric,2) weekly_hours FROM attendance_sessions a WHERE a.tenant_id=$1 AND a.clocked_out_at IS NOT NULL AND a.clocked_in_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR a.site_id=$4) GROUP BY a.user_id,date_trunc('week',a.clocked_in_at)) w`,p)).rows[0];
    return{summary:{...summary,overtime_hours:Number(overtime.overtime_hours||0)},daily,sites,guards,incident_breakdown:incidentBreakdown};
  });res.json({from_date:from,to_date:to,site_id:siteId,...data});}catch(err){res.status(500).json({error:err.message});}
});

// ------------------------ BILLING & INVOICING ------------------------

async function invoiceDetails(client,tenantId,whereValue,byId=true){
  const field=byId?'i.id':'i.invoice_number';
  return client.query(`SELECT i.*,sc.reference_code,sc.client_name,sc.site_id,sc.billing_model,s.name AS site_name,
    COALESCE((SELECT json_agg(il ORDER BY il.id) FROM invoice_lines il WHERE il.invoice_id=i.id),'[]') AS lines,
    COALESCE((SELECT json_agg(ip ORDER BY ip.payment_date,ip.id) FROM invoice_payments ip WHERE ip.invoice_id=i.id),'[]') AS payments
    FROM invoices i JOIN service_contracts sc ON sc.id=i.contract_id JOIN sites s ON s.id=sc.site_id
    WHERE i.tenant_id=$1 AND ${field}=$2`,[tenantId,whereValue]);
}

async function calculateInvoiceLine(client,contract,start,end){
  const rate=Number(contract.rate||0);
  if(contract.billing_model==='hourly'){
    const result=await client.query(`SELECT COALESCE(SUM(GREATEST(0,EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))-COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0))),0)/3600 AS quantity
      FROM attendance_sessions a WHERE a.tenant_id=$1 AND a.site_id=$2 AND a.clocked_out_at IS NOT NULL AND a.clocked_in_at::date BETWEEN $3 AND $4
      AND EXISTS(SELECT 1 FROM timesheets t WHERE t.tenant_id=a.tenant_id AND t.user_id=a.user_id AND t.status='approved' AND a.clocked_in_at::date BETWEEN t.period_start AND t.period_end)`,[contract.tenant_id,contract.site_id,start,end]);
    const quantity=Math.round(Number(result.rows[0].quantity||0)*100)/100;return{description:`Approved guard hours (${start} to ${end})`,quantity,unit_rate:rate,line_total:Math.round(quantity*rate*100)/100};
  }
  if(contract.billing_model==='per_patrol'){
    const result=await client.query(`SELECT COUNT(*)::int AS quantity FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND status='completed' AND scheduled_start::date BETWEEN $3 AND $4`,[contract.tenant_id,contract.site_id,start,end]);
    const quantity=Number(result.rows[0].quantity);return{description:`Completed patrols (${start} to ${end})`,quantity,unit_rate:rate,line_total:Math.round(quantity*rate*100)/100};
  }
  return{description:`${contract.billing_model==='monthly'?'Monthly service fee':'Fixed service fee'} (${start} to ${end})`,quantity:1,unit_rate:rate,line_total:rate};
}

app.get('/api/invoices',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,async client=>{await client.query("UPDATE invoices SET status='overdue',updated_at=NOW() WHERE tenant_id=$1 AND status='issued' AND due_date<CURRENT_DATE AND amount_paid<total",[tenantId]);const params=[tenantId];let where='i.tenant_id=$1';if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND i.status=$${params.length}`;}if(req.query.contract_id){params.push(req.query.contract_id);where+=` AND i.contract_id=$${params.length}`;}return client.query(`SELECT i.*,sc.reference_code,sc.client_name,s.name AS site_name FROM invoices i JOIN service_contracts sc ON sc.id=i.contract_id JOIN sites s ON s.id=sc.site_id WHERE ${where} ORDER BY i.created_at DESC LIMIT 500`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/invoices/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>invoiceDetails(client,tenantId,req.params.id));if(!result.rows.length)return res.status(404).json({error:'Invoice not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/invoices/generate',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),contractId=Number(req.body.contract_id),start=req.body.period_start,end=req.body.period_end,tax=Math.max(0,Math.min(100,Number(req.body.tax_rate||0))),dueDays=Math.max(0,Math.min(365,Number(req.body.due_days||30)));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!contractId||!start||!end||isNaN(new Date(start))||isNaN(new Date(end))||new Date(end)<new Date(start))return res.status(400).json({error:'Contract and valid billing period are required'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);const contract=(await client.query("SELECT * FROM service_contracts WHERE id=$1 AND tenant_id=$2 AND status='active'",[contractId,tenantId])).rows[0];if(!contract)throw Object.assign(new Error('Active contract not found'),{statusCode:404});if(contract.rate===null||contract.rate===undefined||!Number.isFinite(Number(contract.rate))||Number(contract.rate)<0)throw Object.assign(new Error('Set a valid contract rate before invoicing'),{statusCode:400});const line=await calculateInvoiceLine(client,contract,start,end);if(['hourly','per_patrol'].includes(contract.billing_model)&&line.quantity<=0)throw Object.assign(new Error(contract.billing_model==='hourly'?'No approved billable hours were found for this site and period':'No completed patrols were found for this site and period'),{statusCode:400});const subtotal=line.line_total,taxAmount=Math.round(subtotal*tax/100*100)/100,total=Math.round((subtotal+taxAmount)*100)/100,id=Number((await client.query("SELECT nextval(pg_get_serial_sequence('invoices','id')) AS id")).rows[0].id),number=`INV-${new Date().getUTCFullYear()}-${String(id).padStart(6,'0')}`,issue=DateTime.utc().toISODate(),due=DateTime.utc().plus({days:dueDays}).toISODate();const invoice=(await client.query(`INSERT INTO invoices(id,tenant_id,contract_id,invoice_number,period_start,period_end,issue_date,due_date,currency,subtotal,tax_rate,tax_amount,total,notes,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,[id,tenantId,contractId,number,start,end,issue,due,contract.currency||'EUR',subtotal,tax,taxAmount,total,req.body.notes||null,req.auth.user_id])).rows[0];await client.query(`INSERT INTO invoice_lines(invoice_id,description,quantity,unit_rate,line_total) VALUES($1,$2,$3,$4,$5)`,[id,line.description,line.quantity,line.unit_rate,line.line_total]);await client.query('COMMIT');res.status(201).json({...invoice,lines:[line]});}catch(err){await client.query('ROLLBACK');res.status(err.code==='23505'?409:err.statusCode||500).json({error:err.code==='23505'?'An invoice already exists for this contract and period':err.message});}finally{client.release();}});

app.patch('/api/invoices/:id/status',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),status=req.body.status;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['issued','cancelled'].includes(status))return res.status(400).json({error:'Status must be issued or cancelled'});try{const result=await withTenant(tenantId,client=>client.query(`UPDATE invoices SET status=$1,issue_date=CASE WHEN $1='issued' THEN COALESCE(issue_date,CURRENT_DATE) ELSE issue_date END,updated_at=NOW() WHERE id=$2 AND tenant_id=$3 AND status${status==='issued'?"='draft'":" NOT IN ('paid','cancelled')"} RETURNING *`,[status,req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Invoice status cannot be changed'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/invoices/:id/payments',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),amount=Number(req.body.amount),paymentDate=req.body.payment_date;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!Number.isFinite(amount)||amount<=0||!paymentDate||isNaN(new Date(paymentDate)))return res.status(400).json({error:'Positive amount and payment date are required'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);const invoice=(await client.query("SELECT * FROM invoices WHERE id=$1 AND tenant_id=$2 AND status IN ('issued','overdue','paid') FOR UPDATE",[req.params.id,tenantId])).rows[0];if(!invoice)throw Object.assign(new Error('Issued invoice not found'),{statusCode:404});const balance=Number(invoice.total)-Number(invoice.amount_paid);if(amount>balance+0.001)throw Object.assign(new Error(`Payment exceeds outstanding balance of ${invoice.currency} ${balance.toFixed(2)}`),{statusCode:400});const payment=(await client.query(`INSERT INTO invoice_payments(tenant_id,invoice_id,amount,payment_date,method,reference,notes,recorded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[tenantId,invoice.id,amount,paymentDate,req.body.method||null,req.body.reference||null,req.body.notes||null,req.auth.user_id])).rows[0],newPaid=Math.round((Number(invoice.amount_paid)+amount)*100)/100,newStatus=newPaid>=Number(invoice.total)?'paid':(new Date(invoice.due_date)<new Date()?'overdue':'issued');await client.query('UPDATE invoices SET amount_paid=$1,status=$2,updated_at=NOW() WHERE id=$3',[newPaid,newStatus,invoice.id]);await client.query('COMMIT');res.status(201).json(payment);}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}});

async function sendInvoicePdf(res,invoice){res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`attachment; filename="${invoice.invoice_number}.pdf"`);const money=n=>`${invoice.currency} ${Number(n).toFixed(2)}`,doc=new PDFDocument({margin:50});doc.pipe(res);doc.fontSize(22).text('PatrolSync Invoice').moveDown(.5);doc.fontSize(11).text(`Invoice: ${invoice.invoice_number}`).text(`Client: ${invoice.client_name}`).text(`Site: ${invoice.site_name}`).text(`Contract: ${invoice.reference_code}`).text(`Billing period: ${String(invoice.period_start).slice(0,10)} to ${String(invoice.period_end).slice(0,10)}`).text(`Issue date: ${String(invoice.issue_date||'Draft').slice(0,10)}`).text(`Due date: ${String(invoice.due_date).slice(0,10)}`).moveDown();doc.fontSize(14).text('Charges').moveDown(.4);invoice.lines.forEach(line=>doc.fontSize(10).text(`${line.description}   ${Number(line.quantity).toFixed(2)} x ${money(line.unit_rate)} = ${money(line.line_total)}`));doc.moveDown().fontSize(11).text(`Subtotal: ${money(invoice.subtotal)}`,{align:'right'}).text(`Tax (${Number(invoice.tax_rate).toFixed(2)}%): ${money(invoice.tax_amount)}`,{align:'right'}).fontSize(14).text(`Total: ${money(invoice.total)}`,{align:'right'}).fontSize(11).text(`Paid: ${money(invoice.amount_paid)}`,{align:'right'}).text(`Balance: ${money(Number(invoice.total)-Number(invoice.amount_paid))}`,{align:'right'});if(invoice.notes)doc.moveDown().text(`Notes: ${invoice.notes}`);doc.end();}

app.get('/api/invoices/:id/pdf',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>invoiceDetails(client,tenantId,req.params.id));if(!result.rows.length)return res.status(404).json({error:'Invoice not found'});sendInvoicePdf(res,result.rows[0]);}catch(err){if(!res.headersSent)res.status(500).json({error:err.message});}});

app.get('/api/client-portal/invoices',requireAuth,requireClient,async(req,res)=>{const {tenant_id,site_id}=req.auth;try{const result=await withTenant(tenant_id,client=>client.query(`SELECT i.id,i.invoice_number,i.period_start,i.period_end,i.issue_date,i.due_date,i.status,i.currency,i.total,i.amount_paid,sc.reference_code FROM invoices i JOIN service_contracts sc ON sc.id=i.contract_id WHERE i.tenant_id=$1 AND sc.site_id=$2 AND i.status IN ('issued','overdue','paid') ORDER BY i.issue_date DESC,i.id DESC`,[tenant_id,site_id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/client-portal/invoices/:id/pdf',requireAuth,requireClient,async(req,res)=>{const {tenant_id,site_id}=req.auth;try{const result=await withTenant(tenant_id,client=>client.query(`SELECT i.*,sc.reference_code,sc.client_name,sc.site_id,s.name AS site_name,COALESCE((SELECT json_agg(il ORDER BY il.id) FROM invoice_lines il WHERE il.invoice_id=i.id),'[]') AS lines,COALESCE((SELECT json_agg(ip ORDER BY ip.payment_date,ip.id) FROM invoice_payments ip WHERE ip.invoice_id=i.id),'[]') AS payments FROM invoices i JOIN service_contracts sc ON sc.id=i.contract_id JOIN sites s ON s.id=sc.site_id WHERE i.id=$1 AND i.tenant_id=$2 AND sc.site_id=$3 AND i.status IN ('issued','overdue','paid')`,[req.params.id,tenant_id,site_id]));if(!result.rows.length)return res.status(404).json({error:'Invoice not found'});sendInvoicePdf(res,result.rows[0]);}catch(err){if(!res.headersSent)res.status(500).json({error:err.message});}});

// ------------------------ SHIFT HANDOVERS ------------------------

app.post('/api/handovers',requireAuth,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),toUser=req.body.to_user_id?Number(req.body.to_user_id):null,summary=String(req.body.summary||'').trim(),actions=String(req.body.outstanding_actions||'').trim(),equipment=['ok','attention','fault'].includes(req.body.equipment_status)?req.body.equipment_status:'ok';if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!summary)return res.status(400).json({error:'Site and handover summary are required'});try{const result=await withTenant(tenantId,async client=>{if(req.auth.role!=='admin'){const assigned=await client.query('SELECT 1 FROM guard_assignments WHERE tenant_id=$1 AND site_id=$2 AND user_id=$3',[tenantId,siteId,req.auth.user_id]);if(!assigned.rows.length)throw Object.assign(new Error('You are not assigned to this site'),{statusCode:403});}if(toUser){const target=await client.query(`SELECT 1 FROM guard_assignments ga JOIN users u ON u.id=ga.user_id WHERE ga.tenant_id=$1 AND ga.site_id=$2 AND ga.user_id=$3 AND u.role='guard'`,[tenantId,siteId,toUser]);if(!target.rows.length)throw Object.assign(new Error('Receiving guard is not assigned to this site'),{statusCode:400});}return client.query(`INSERT INTO handover_logs (tenant_id,site_id,from_user_id,to_user_id,summary,outstanding_actions,equipment_status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[tenantId,siteId,req.auth.user_id,toUser,summary,actions||null,equipment])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});

app.get('/api/handovers',requireAuth,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>{const params=[tenantId];let where='h.tenant_id=$1';if(req.query.site_id){params.push(req.query.site_id);where+=` AND h.site_id=$${params.length}`;}if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND h.status=$${params.length}`;}if(req.auth.role!=='admin'){params.push(req.auth.user_id);where+=` AND EXISTS(SELECT 1 FROM guard_assignments ga WHERE ga.tenant_id=h.tenant_id AND ga.site_id=h.site_id AND ga.user_id=$${params.length})`;}return client.query(`SELECT h.*,s.name AS site_name,fu.email AS from_email,tu.email AS to_email,au.email AS acknowledged_email FROM handover_logs h JOIN sites s ON s.id=h.site_id JOIN users fu ON fu.id=h.from_user_id LEFT JOIN users tu ON tu.id=h.to_user_id LEFT JOIN users au ON au.id=h.acknowledged_by WHERE ${where} ORDER BY h.created_at DESC LIMIT 300`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/handovers/:id/acknowledge',requireAuth,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,async client=>{const handover=await client.query('SELECT * FROM handover_logs WHERE id=$1 AND tenant_id=$2 AND status=$3',[req.params.id,tenantId,'pending']);if(!handover.rows.length)throw Object.assign(new Error('Handover is no longer pending'),{statusCode:409});const h=handover.rows[0];if(req.auth.role!=='admin'){if(Number(h.from_user_id)===req.auth.user_id)throw Object.assign(new Error('The outgoing guard cannot acknowledge their own handover'),{statusCode:403});if(h.to_user_id&&Number(h.to_user_id)!==req.auth.user_id)throw Object.assign(new Error('This handover is assigned to another guard'),{statusCode:403});const assigned=await client.query('SELECT 1 FROM guard_assignments WHERE tenant_id=$1 AND site_id=$2 AND user_id=$3',[tenantId,h.site_id,req.auth.user_id]);if(!assigned.rows.length)throw Object.assign(new Error('You are not assigned to this site'),{statusCode:403});}return client.query("UPDATE handover_logs SET status='acknowledged',acknowledged_by=$1,acknowledged_at=NOW() WHERE id=$2 AND tenant_id=$3 AND status='pending' RETURNING *",[req.auth.user_id,req.params.id,tenantId])});if(!result.rows.length)return res.status(409).json({error:'Handover was already acknowledged'});res.json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});

app.patch('/api/handovers/:id/resolve',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),notes=String(req.body.resolution_notes||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!notes)return res.status(400).json({error:'Resolution notes are required'});try{const result=await withTenant(tenantId,client=>client.query("UPDATE handover_logs SET status='resolved',resolved_by=$1,resolved_at=NOW(),resolution_notes=$2 WHERE id=$3 AND tenant_id=$4 AND status<>'resolved' RETURNING *",[req.auth.user_id,notes,req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Handover is already resolved or unavailable'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

// ------------------------ INCIDENTS ------------------------

app.post('/api/incidents', requireAuth, async (req, res) => {
  const { tenant_id, site_id, checkpoint_id, description, severity, category, photos } = req.body;
  const user_id = req.auth.user_id;
  if (!tenant_id || !site_id || !description) {
    return res.status(400).json({ error: 'tenant_id, site_id, and description are required' });
  }
  const tenantId=attendanceTenant(req,tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const incidentCategory=['security','safety','medical','fire','property','access','conduct','general'].includes(category)?category:'general';

  const photoList = Array.isArray(photos) ? photos.slice(0, MAX_PHOTOS_PER_INCIDENT) : [];
  for (const p of photoList) {
    if (typeof p !== 'string' || p.length === 0) {
      return res.status(400).json({ error: 'Each photo must be a non-empty base64 data URL string' });
    }
    if (p.length > MAX_PHOTO_BASE64_LENGTH) {
      return res.status(400).json({ error: 'One or more photos are too large. Please retake at a lower quality.' });
    }
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET app.current_tenant = '${tenant_id}'`);

    const incidentResult = await client.query(
      'INSERT INTO incidents (tenant_id, site_id, checkpoint_id, user_id, description, severity,category) VALUES ($1, $2, $3, $4, $5, $6,$7) RETURNING *',
      [tenant_id, site_id, checkpoint_id || null, user_id, description, severity || 'low',incidentCategory]
    );
    let incident = incidentResult.rows[0];
    const reference='INC-'+new Date().getUTCFullYear()+'-'+String(incident.id).padStart(6,'0');
    incident=(await client.query('UPDATE incidents SET reference_code=$1 WHERE id=$2 RETURNING *',[reference,incident.id])).rows[0];
    await client.query(`INSERT INTO incident_activities (tenant_id,incident_id,user_id,activity_type,note) VALUES ($1,$2,$3,'reported',$4)`,[tenantId,incident.id,user_id,'Incident reported with '+photoList.length+' photo(s)']);

    for (const photoData of photoList) {
      await client.query(
        'INSERT INTO incident_photos (tenant_id, incident_id, photo_data) VALUES ($1, $2, $3)',
        [tenant_id, incident.id, photoData]
      );
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
  const { tenant_id, date, status, category, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) => {
      let baseQuery = `
        SELECT i.*, COALESCE(p.photo_count, 0) AS photo_count,s.name AS site_name,reporter.email AS reporter_email,assignee.email AS assigned_email
        FROM incidents i
        JOIN sites s ON s.id=i.site_id LEFT JOIN users reporter ON reporter.id=i.user_id LEFT JOIN users assignee ON assignee.id=i.assigned_to
        LEFT JOIN (
          SELECT incident_id, COUNT(*) AS photo_count
          FROM incident_photos
          WHERE tenant_id = $1
          GROUP BY incident_id
        ) p ON p.incident_id = i.id
        WHERE i.tenant_id = $1
      `;
      const params=[tenant_id];if(date){params.push(date);baseQuery+=` AND i.reported_at::date=$${params.length}`;}if(status){params.push(status);baseQuery+=` AND i.status=$${params.length}`;}if(category){params.push(category);baseQuery+=` AND i.category=$${params.length}`;}if(site_id){params.push(site_id);baseQuery+=` AND i.site_id=$${params.length}`;}return client.query(baseQuery+' ORDER BY i.reported_at DESC LIMIT 500',params);
    });
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/incidents/:id/case',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id),status=req.body.status,assignedTo=req.body.assigned_to?Number(req.body.assigned_to):null,resolution=String(req.body.resolution||'').trim();
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(status&&!['reported','acknowledged','investigating','resolved','closed'].includes(status))return res.status(400).json({error:'Invalid incident status'});if(['resolved','closed'].includes(status)&&!resolution)return res.status(400).json({error:'Resolution details are required'});
  const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);if(assignedTo){const owner=await client.query("SELECT 1 FROM users WHERE id=$1 AND tenant_id=$2 AND role='admin'",[assignedTo,tenantId]);if(!owner.rows.length)throw Object.assign(new Error('Assigned supervisor not found'),{statusCode:400});}const current=await client.query('SELECT * FROM incidents WHERE id=$1 AND tenant_id=$2 FOR UPDATE',[req.params.id,tenantId]);if(!current.rows.length)throw Object.assign(new Error('Incident not found'),{statusCode:404});const nextStatus=status||current.rows[0].status;const updated=await client.query(`UPDATE incidents SET status=$1,assigned_to=$2,resolution=CASE WHEN $3<>'' THEN $3 ELSE resolution END,acknowledged_at=CASE WHEN $1 IN ('acknowledged','investigating','resolved','closed') THEN COALESCE(acknowledged_at,NOW()) ELSE acknowledged_at END,resolved_at=CASE WHEN $1 IN ('resolved','closed') THEN COALESCE(resolved_at,NOW()) ELSE NULL END,updated_at=NOW() WHERE id=$4 AND tenant_id=$5 RETURNING *`,[nextStatus,assignedTo,resolution,req.params.id,tenantId]);const changes=[];if(nextStatus!==current.rows[0].status)changes.push('Status: '+current.rows[0].status+' → '+nextStatus);if(assignedTo!==current.rows[0].assigned_to)changes.push(assignedTo?'Case assigned to supervisor #'+assignedTo:'Case unassigned');if(resolution)changes.push('Resolution: '+resolution);await client.query(`INSERT INTO incident_activities (tenant_id,incident_id,user_id,activity_type,note) VALUES ($1,$2,$3,'case_updated',$4)`,[tenantId,req.params.id,req.auth.user_id,changes.join('; ')||'Case updated']);await client.query('COMMIT');res.json(updated.rows[0]);}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}
});

app.post('/api/incidents/:id/comments',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),note=String(req.body.note||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!note)return res.status(400).json({error:'Comment is required'});try{const result=await withTenant(tenantId,async client=>{const exists=await client.query('SELECT 1 FROM incidents WHERE id=$1 AND tenant_id=$2',[req.params.id,tenantId]);if(!exists.rows.length)throw Object.assign(new Error('Incident not found'),{statusCode:404});return client.query(`INSERT INTO incident_activities (tenant_id,incident_id,user_id,activity_type,note) VALUES ($1,$2,$3,'comment',$4) RETURNING *`,[tenantId,req.params.id,req.auth.user_id,note])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});

app.get('/api/incidents/:id/activities',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`SELECT ia.*,u.email AS user_email FROM incident_activities ia LEFT JOIN users u ON u.id=ia.user_id WHERE ia.incident_id=$1 AND ia.tenant_id=$2 ORDER BY ia.created_at`,[req.params.id,tenantId]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/incidents/:id/photos', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'SELECT id, photo_data, created_at FROM incident_photos WHERE incident_id = $1 AND tenant_id = $2 ORDER BY created_at ASC',
        [id, tenant_id]
      )
    );
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
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'DELETE FROM incident_photos WHERE incident_id = $1 AND tenant_id = $2 RETURNING id',
        [id, tenant_id]
      )
    );
    res.json({ deleted_count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ ATTENDANCE / TIME CLOCK ------------------------

function attendanceTenant(req, requestedTenant) {
  const tenantId = Number(requestedTenant || req.auth.tenant_id);
  return tenantId === Number(req.auth.tenant_id) ? tenantId : null;
}

function distanceMetres(lat1, lon1, lat2, lon2) {
  const toRadians = value => value * Math.PI / 180;
  const earthRadius = 6371000;
  const deltaLat = toRadians(lat2 - lat1);
  const deltaLon = toRadians(lon2 - lon1);
  const a = Math.sin(deltaLat / 2) ** 2 + Math.cos(toRadians(lat1)) * Math.cos(toRadians(lat2)) * Math.sin(deltaLon / 2) ** 2;
  return earthRadius * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function patrolScanEvidence(site, latitude, longitude, accuracy) {
  const lat=Number(latitude),lng=Number(longitude),acc=Number(accuracy);
  if(!Number.isFinite(lat)||!Number.isFinite(lng)) return {accuracy:null,distance:null,status:'unavailable'};
  if(site.latitude===null||site.longitude===null) return {accuracy:Number.isFinite(acc)?acc:null,distance:null,status:'recorded'};
  const distance=Math.round(distanceMetres(lat,lng,Number(site.latitude),Number(site.longitude))*10)/10;
  if(!site.geofence_enabled)return {accuracy:Number.isFinite(acc)?acc:null,distance,status:'recorded'};
  return {accuracy:Number.isFinite(acc)?acc:null,distance,status:distance<=Number(site.geofence_radius_m||150)?'inside':'outside'};
}

async function getActiveAttendance(client, tenantId, userId) {
  const result = await client.query(
    `SELECT a.*, s.name AS site_name,
       b.id AS active_break_id, b.started_at AS break_started_at,
       COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (COALESCE(ab.ended_at, NOW()) - ab.started_at)))
                 FROM attendance_breaks ab WHERE ab.attendance_session_id = a.id), 0) AS break_seconds
     FROM attendance_sessions a
     JOIN sites s ON s.id = a.site_id
     LEFT JOIN attendance_breaks b ON b.attendance_session_id = a.id AND b.ended_at IS NULL
     WHERE a.tenant_id = $1 AND a.user_id = $2 AND a.clocked_out_at IS NULL`,
    [tenantId, userId]
  );
  return result.rows[0] || null;
}

app.get('/api/attendance/current', requireAuth, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const userId = req.auth.role === 'admin' && req.query.user_id ? Number(req.query.user_id) : req.auth.user_id;
  try {
    const session = await withTenant(tenantId, client => getActiveAttendance(client, tenantId, userId));
    res.json({ active: Boolean(session), session });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/attendance/clock-in', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can clock in' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  const { site_id, latitude, longitude, accuracy } = req.body;
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!site_id) return res.status(400).json({ error: 'Select a site before clocking in' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL app.current_tenant = '${tenantId}'`);
    const assignment = await client.query(
      `SELECT s.latitude, s.longitude, s.geofence_radius_m, s.geofence_enabled
       FROM guard_assignments ga JOIN sites s ON s.id=ga.site_id
       WHERE ga.tenant_id=$1 AND ga.user_id=$2 AND ga.site_id=$3`,
      [tenantId, req.auth.user_id, site_id]
    );
    if (assignment.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'You are not assigned to this site' });
    }
    const site = assignment.rows[0];
    let clockInDistance = null;
    let geofenceVerified = null;
    if (site.geofence_enabled) {
      if (!Number.isFinite(Number(latitude)) || !Number.isFinite(Number(longitude))) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Location permission is required to clock in at this site', code: 'LOCATION_REQUIRED' });
      }
      if (Number.isFinite(Number(accuracy)) && Number(accuracy) > 200) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Your GPS accuracy is too low. Move outdoors or wait for a stronger location signal, then try again.', code: 'LOCATION_INACCURATE', accuracy_m: Math.round(Number(accuracy)) });
      }
      clockInDistance = distanceMetres(Number(latitude), Number(longitude), Number(site.latitude), Number(site.longitude));
      geofenceVerified = clockInDistance <= Number(site.geofence_radius_m);
      if (!geofenceVerified) {
        await client.query('ROLLBACK');
        return res.status(403).json({
          error: `You are ${Math.round(clockInDistance)}m from the site. Move within the ${site.geofence_radius_m}m clock-in area.`,
          code: 'OUTSIDE_GEOFENCE', distance_m: Math.round(clockInDistance), radius_m: site.geofence_radius_m
        });
      }
    }
    const active = await getActiveAttendance(client, tenantId, req.auth.user_id);
    if (active) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'You are already clocked in', session: active });
    }
    const scheduledShift = await client.query(
      `SELECT id FROM shifts WHERE tenant_id=$1 AND user_id=$2 AND site_id=$3
       AND shift_date = CURRENT_DATE ORDER BY start_time LIMIT 1`,
      [tenantId, req.auth.user_id, site_id]
    );
    await client.query(
      `INSERT INTO attendance_sessions
       (tenant_id,user_id,site_id,shift_id,clock_in_latitude,clock_in_longitude,clock_in_accuracy,
        clock_in_distance_m,clock_in_geofence_radius_m,clock_in_geofence_verified)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [tenantId, req.auth.user_id, site_id, scheduledShift.rows[0]?.id || null,
       latitude ?? null, longitude ?? null, accuracy ?? null, clockInDistance,
       site.geofence_enabled ? site.geofence_radius_m : null, geofenceVerified]
    );
    await client.query('COMMIT');
    const session = await withTenant(tenantId, c => getActiveAttendance(c, tenantId, req.auth.user_id));
    res.status(201).json({ active: true, session });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(err.code === '23505' ? 409 : 500).json({ error: err.code === '23505' ? 'You are already clocked in' : err.message });
  } finally { client.release(); }
});

app.post('/api/attendance/break/start', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can manage breaks' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  try {
    const result = await withTenant(tenantId, async client => {
      const active = await getActiveAttendance(client, tenantId, req.auth.user_id);
      if (!active) throw Object.assign(new Error('Clock in before starting a break'), { statusCode: 409 });
      if (active.active_break_id) throw Object.assign(new Error('A break is already active'), { statusCode: 409 });
      await client.query(
        `INSERT INTO attendance_breaks (tenant_id,attendance_session_id,start_latitude,start_longitude)
         VALUES ($1,$2,$3,$4)`,
        [tenantId, active.id, req.body.latitude ?? null, req.body.longitude ?? null]
      );
      return getActiveAttendance(client, tenantId, req.auth.user_id);
    });
    res.status(201).json({ active: true, session: result });
  } catch (err) { res.status(err.statusCode || (err.code === '23505' ? 409 : 500)).json({ error: err.message }); }
});

app.post('/api/attendance/break/end', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can manage breaks' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  try {
    const session = await withTenant(tenantId, async client => {
      const active = await getActiveAttendance(client, tenantId, req.auth.user_id);
      if (!active || !active.active_break_id) throw Object.assign(new Error('No active break found'), { statusCode: 409 });
      await client.query(
        `UPDATE attendance_breaks SET ended_at=NOW(), end_latitude=$1, end_longitude=$2
         WHERE id=$3 AND tenant_id=$4 AND ended_at IS NULL`,
        [req.body.latitude ?? null, req.body.longitude ?? null, active.active_break_id, tenantId]
      );
      return getActiveAttendance(client, tenantId, req.auth.user_id);
    });
    res.json({ active: true, session });
  } catch (err) { res.status(err.statusCode || 500).json({ error: err.message }); }
});

app.post('/api/attendance/clock-out', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can clock out' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  try {
    const completed = await withTenant(tenantId, async client => {
      const active = await getActiveAttendance(client, tenantId, req.auth.user_id);
      if (!active) throw Object.assign(new Error('No active attendance session found'), { statusCode: 409 });
      if (active.active_break_id) await client.query('UPDATE attendance_breaks SET ended_at=NOW() WHERE id=$1', [active.active_break_id]);
      const result = await client.query(
        `UPDATE attendance_sessions SET clocked_out_at=NOW(), clock_out_latitude=$1,
         clock_out_longitude=$2, clock_out_accuracy=$3 WHERE id=$4 AND tenant_id=$5 RETURNING *`,
        [req.body.latitude ?? null, req.body.longitude ?? null, req.body.accuracy ?? null, active.id, tenantId]
      );
      return result.rows[0];
    });
    res.json({ active: false, session: null, completed_session: completed });
  } catch (err) { res.status(err.statusCode || 500).json({ error: err.message }); }
});

app.get('/api/attendance', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  try {
    const result = await withTenant(tenantId, client => {
      let query = `SELECT a.*, u.email AS guard_email, s.name AS site_name,
        COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (COALESCE(b.ended_at,NOW())-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id),0) AS break_seconds,
        EXTRACT(EPOCH FROM (COALESCE(a.clocked_out_at,NOW())-a.clocked_in_at)) AS elapsed_seconds,
        EXISTS(SELECT 1 FROM attendance_breaks active_break WHERE active_break.attendance_session_id=a.id AND active_break.ended_at IS NULL) AS on_break
        FROM attendance_sessions a JOIN users u ON u.id=a.user_id JOIN sites s ON s.id=a.site_id
        WHERE a.tenant_id=$1`;
      const params = [tenantId];
      if (req.query.date) { params.push(req.query.date); query += ` AND a.clocked_in_at::date=$${params.length}`; }
      if (req.query.user_id) { params.push(req.query.user_id); query += ` AND a.user_id=$${params.length}`; }
      if (req.query.site_id) { params.push(req.query.site_id); query += ` AND a.site_id=$${params.length}`; }
      query += ' ORDER BY a.clocked_in_at DESC LIMIT 500';
      return client.query(query, params);
    });
    res.json(result.rows.map(row => ({ ...row, worked_seconds: Math.max(0, Number(row.elapsed_seconds)-Number(row.break_seconds)) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ------------------------ AVAILABILITY & LEAVE ------------------------

app.get('/api/availability', requireAuth, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const userId = req.auth.role === 'admin' && req.query.user_id ? Number(req.query.user_id) : req.auth.user_id;
  try {
    const result = await withTenant(tenantId, client => client.query(
      'SELECT * FROM guard_availability WHERE tenant_id=$1 AND user_id=$2 ORDER BY weekday', [tenantId,userId]
    ));
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/availability', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can update their availability' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  const days = req.body.days;
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!Array.isArray(days) || days.length !== 7) return res.status(400).json({ error: 'Availability must include all seven weekdays' });
  try {
    const rows = await withTenant(tenantId, async client => {
      const saved=[];
      for (const day of days) {
        const weekday=Number(day.weekday),available=Boolean(day.is_available);
        if (!Number.isInteger(weekday)||weekday<0||weekday>6) throw Object.assign(new Error('Invalid weekday'),{statusCode:400});
        if (available && (!TIME_FORMAT_REGEX.test(day.available_from||'')||!TIME_FORMAT_REGEX.test(day.available_until||''))) throw Object.assign(new Error('Available days require valid start and end times'),{statusCode:400});
        const result=await client.query(
          `INSERT INTO guard_availability (tenant_id,user_id,weekday,is_available,available_from,available_until)
           VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,user_id,weekday) DO UPDATE SET
           is_available=EXCLUDED.is_available,available_from=EXCLUDED.available_from,available_until=EXCLUDED.available_until,updated_at=NOW() RETURNING *`,
          [tenantId,req.auth.user_id,weekday,available,available?day.available_from:null,available?day.available_until:null]
        );saved.push(result.rows[0]);
      }return saved;
    });
    res.json(rows);
  } catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.post('/api/leave-requests', requireAuth, async (req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can request leave'});
  const tenantId=attendanceTenant(req,req.body.tenant_id);const {start_date,end_date,leave_type,reason}=req.body;
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!validTimesheetPeriod(start_date,end_date))return res.status(400).json({error:'Choose a valid leave period of no more than 32 days'});
  if(!['annual','sick','unpaid','other'].includes(leave_type))return res.status(400).json({error:'Invalid leave type'});
  try{const result=await withTenant(tenantId,client=>client.query(
    `INSERT INTO leave_requests (tenant_id,user_id,start_date,end_date,leave_type,reason) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [tenantId,req.auth.user_id,start_date,end_date,leave_type,reason||null]));res.status(201).json(result.rows[0]);}
  catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/leave-requests',requireAuth,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>{let query=`SELECT l.*,u.email AS guard_email,r.email AS reviewer_email FROM leave_requests l JOIN users u ON u.id=l.user_id LEFT JOIN users r ON r.id=l.reviewed_by WHERE l.tenant_id=$1`;const params=[tenantId];if(req.auth.role!=='admin'){params.push(req.auth.user_id);query+=` AND l.user_id=$${params.length}`}else if(req.query.user_id){params.push(req.query.user_id);query+=` AND l.user_id=$${params.length}`}if(req.query.status){params.push(req.query.status);query+=` AND l.status=$${params.length}`}query+=' ORDER BY l.requested_at DESC LIMIT 250';return client.query(query,params)});res.json(result.rows);}
  catch(err){res.status(500).json({error:err.message});}
});

app.patch('/api/leave-requests/:id/review',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id);const {status,review_notes}=req.body;
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['approved','rejected'].includes(status))return res.status(400).json({error:'Invalid review status'});
  if(status==='rejected'&&!String(review_notes||'').trim())return res.status(400).json({error:'A rejection reason is required'});
  try{const result=await withTenant(tenantId,client=>client.query(
    `UPDATE leave_requests SET status=$1,review_notes=$2,reviewed_at=NOW(),reviewed_by=$3 WHERE id=$4 AND tenant_id=$5 AND status='pending' RETURNING *`,
    [status,String(review_notes||'').trim()||null,req.auth.user_id,req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Request not found or already reviewed'});res.json(result.rows[0]);}
  catch(err){res.status(500).json({error:err.message});}
});

app.delete('/api/leave-requests/:id',requireAuth,async(req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can cancel requests'});const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query("DELETE FROM leave_requests WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND status='pending' RETURNING id",[req.params.id,tenantId,req.auth.user_id]));if(!result.rows.length)return res.status(409).json({error:'Only pending requests can be cancelled'});res.json({deleted:result.rows[0]});}catch(err){res.status(500).json({error:err.message});}
});

// ------------------------ TIMESHEETS & APPROVALS ------------------------

function validTimesheetPeriod(start, end) {
  const startDate = DateTime.fromISO(start).startOf('day');
  const endDate = DateTime.fromISO(end).startOf('day');
  return startDate.isValid && endDate.isValid && endDate >= startDate && endDate.diff(startDate, 'days').days <= 31;
}

async function calculateTimesheet(client, tenantId, userId, periodStart, periodEnd) {
  const result = await client.query(
    `SELECT COUNT(*)::int AS session_count,
       COALESCE(SUM(EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))),0)::bigint AS elapsed_seconds,
       COALESCE(SUM((SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))),0)
                     FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL)),0)::bigint AS break_seconds
     FROM attendance_sessions a
     WHERE a.tenant_id=$1 AND a.user_id=$2 AND a.clocked_out_at IS NOT NULL
       AND a.clocked_in_at::date BETWEEN $3 AND $4`,
    [tenantId, userId, periodStart, periodEnd]
  );
  const row = result.rows[0];
  return {
    session_count: Number(row.session_count),
    elapsed_seconds: Number(row.elapsed_seconds),
    break_seconds: Number(row.break_seconds),
    worked_seconds: Math.max(0, Number(row.elapsed_seconds) - Number(row.break_seconds))
  };
}

app.get('/api/timesheets/preview', requireAuth, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const userId = req.auth.role === 'admin' && req.query.user_id ? Number(req.query.user_id) : req.auth.user_id;
  if (!validTimesheetPeriod(req.query.period_start, req.query.period_end)) {
    return res.status(400).json({ error: 'Choose a valid period of no more than 32 days' });
  }
  try {
    const summary = await withTenant(tenantId, client => calculateTimesheet(client, tenantId, userId, req.query.period_start, req.query.period_end));
    const sessions = await withTenant(tenantId, client => client.query(
      `SELECT a.*, s.name AS site_name,
       COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0) AS break_seconds
       FROM attendance_sessions a JOIN sites s ON s.id=a.site_id
       WHERE a.tenant_id=$1 AND a.user_id=$2 AND a.clocked_out_at IS NOT NULL
       AND a.clocked_in_at::date BETWEEN $3 AND $4 ORDER BY a.clocked_in_at`,
      [tenantId, userId, req.query.period_start, req.query.period_end]
    ));
    res.json({ ...summary, sessions: sessions.rows.map(row => ({ ...row, worked_seconds: Math.max(0, (new Date(row.clocked_out_at)-new Date(row.clocked_in_at))/1000-Number(row.break_seconds)) })) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/timesheets/submit', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can submit their timesheets' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  const { period_start, period_end } = req.body;
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!validTimesheetPeriod(period_start, period_end)) return res.status(400).json({ error: 'Choose a valid period of no more than 32 days' });
  try {
    const timesheet = await withTenant(tenantId, async client => {
      const existing = await client.query(
        'SELECT * FROM timesheets WHERE tenant_id=$1 AND user_id=$2 AND period_start=$3 AND period_end=$4',
        [tenantId, req.auth.user_id, period_start, period_end]
      );
      if (existing.rows[0]?.status === 'approved') throw Object.assign(new Error('This timesheet is approved and locked'), { statusCode: 409 });
      const open = await client.query(
        `SELECT 1 FROM attendance_sessions WHERE tenant_id=$1 AND user_id=$2 AND clocked_out_at IS NULL
         AND clocked_in_at::date BETWEEN $3 AND $4`, [tenantId, req.auth.user_id, period_start, period_end]
      );
      if (open.rows.length) throw Object.assign(new Error('Clock out before submitting this timesheet'), { statusCode: 409 });
      const summary = await calculateTimesheet(client, tenantId, req.auth.user_id, period_start, period_end);
      if (summary.session_count === 0) throw Object.assign(new Error('There are no completed attendance sessions in this period'), { statusCode: 400 });
      const result = await client.query(
        `INSERT INTO timesheets (tenant_id,user_id,period_start,period_end,status,session_count,worked_seconds,break_seconds,submitted_at,reviewed_at,reviewed_by,review_notes)
         VALUES ($1,$2,$3,$4,'submitted',$5,$6,$7,NOW(),NULL,NULL,NULL)
         ON CONFLICT (tenant_id,user_id,period_start,period_end) DO UPDATE SET
           status='submitted',session_count=EXCLUDED.session_count,worked_seconds=EXCLUDED.worked_seconds,
           break_seconds=EXCLUDED.break_seconds,submitted_at=NOW(),reviewed_at=NULL,reviewed_by=NULL,review_notes=NULL,updated_at=NOW()
         RETURNING *`,
        [tenantId, req.auth.user_id, period_start, period_end, summary.session_count, summary.worked_seconds, summary.break_seconds]
      );
      return result.rows[0];
    });
    res.status(201).json(timesheet);
  } catch (err) { res.status(err.statusCode || 500).json({ error: err.message }); }
});

app.get('/api/timesheets', requireAuth, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  try {
    const result = await withTenant(tenantId, client => {
      let query = `SELECT t.*, u.email AS guard_email, reviewer.email AS reviewer_email
                   FROM timesheets t JOIN users u ON u.id=t.user_id LEFT JOIN users reviewer ON reviewer.id=t.reviewed_by
                   WHERE t.tenant_id=$1`;
      const params = [tenantId];
      if (req.auth.role !== 'admin') { params.push(req.auth.user_id); query += ` AND t.user_id=$${params.length}`; }
      else if (req.query.user_id) { params.push(req.query.user_id); query += ` AND t.user_id=$${params.length}`; }
      if (req.query.status) { params.push(req.query.status); query += ` AND t.status=$${params.length}`; }
      query += ' ORDER BY t.period_start DESC, t.submitted_at DESC LIMIT 250';
      return client.query(query, params);
    });
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/timesheets/:id/review', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  const { status, review_notes } = req.body;
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!['approved','rejected'].includes(status)) return res.status(400).json({ error: 'Status must be approved or rejected' });
  if (status === 'rejected' && !String(review_notes || '').trim()) return res.status(400).json({ error: 'Add a reason when rejecting a timesheet' });
  try {
    const result = await withTenant(tenantId, client => client.query(
      `UPDATE timesheets SET status=$1,review_notes=$2,reviewed_at=NOW(),reviewed_by=$3,updated_at=NOW()
       WHERE id=$4 AND tenant_id=$5 AND status='submitted' RETURNING *`,
      [status, String(review_notes || '').trim() || null, req.auth.user_id, req.params.id, tenantId]
    ));
    if (!result.rows.length) return res.status(409).json({ error: 'Timesheet not found or already reviewed' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ------------------------ SHIFT SCHEDULING ------------------------

const TIME_FORMAT_REGEX = /^([01]\d|2[0-3]):([0-5]\d)$/;
const MAX_WEEKLY_REPEAT_DAYS = 182;
const MAX_MONTHLY_REPEAT_DAYS = 366;
const MAX_GENERATED_SHIFTS = 250;

function computeShiftDurationHours(startTime, endTime) {
  const [startHour, startMinute] = startTime.split(':').map(Number);
  const [endHour, endMinute] = endTime.split(':').map(Number);
  let difference = (endHour * 60 + endMinute) - (startHour * 60 + startMinute);
  if (difference <= 0) difference += 24 * 60;
  return Math.round((difference / 60) * 100) / 100;
}

function generateShiftDates({ recurrence, start_date, repeat_until, days_of_week, days_of_month }) {
  const start = DateTime.fromISO(start_date).startOf('day');
  if (!start.isValid) throw Object.assign(new Error('start_date is invalid'), { statusCode: 400 });
  if (recurrence === 'none') return [start];

  if (!repeat_until) {
    throw Object.assign(new Error('repeat_until is required for recurring shifts'), { statusCode: 400 });
  }
  const until = DateTime.fromISO(repeat_until).startOf('day');
  if (!until.isValid || until < start) {
    throw Object.assign(new Error('repeat_until must be on or after start_date'), { statusCode: 400 });
  }

  const span = until.diff(start, 'days').days;
  const dates = [];
  if (recurrence === 'weekly') {
    if (span > MAX_WEEKLY_REPEAT_DAYS) {
      throw Object.assign(new Error(`Weekly recurrence cannot span more than ${MAX_WEEKLY_REPEAT_DAYS} days`), { statusCode: 400 });
    }
    if (!Array.isArray(days_of_week) || days_of_week.length === 0) {
      throw Object.assign(new Error('Select at least one day for weekly recurrence'), { statusCode: 400 });
    }
    const weekdays = new Set(days_of_week.map(day => Number(day) === 0 ? 7 : Number(day)));
    for (let date = start; date <= until && dates.length < MAX_GENERATED_SHIFTS; date = date.plus({ days: 1 })) {
      if (weekdays.has(date.weekday)) dates.push(date);
    }
    return dates;
  }

  if (recurrence === 'monthly') {
    if (span > MAX_MONTHLY_REPEAT_DAYS) {
      throw Object.assign(new Error(`Monthly recurrence cannot span more than ${MAX_MONTHLY_REPEAT_DAYS} days`), { statusCode: 400 });
    }
    if (!Array.isArray(days_of_month) || days_of_month.length === 0) {
      throw Object.assign(new Error('Select at least one day of the month'), { statusCode: 400 });
    }
    const monthDays = [...new Set(days_of_month.map(Number))].filter(day => Number.isInteger(day) && day >= 1 && day <= 31).sort((a, b) => a - b);
    if (monthDays.length === 0) {
      throw Object.assign(new Error('days_of_month must contain numbers from 1 to 31'), { statusCode: 400 });
    }
    for (let month = start.startOf('month'); month <= until && dates.length < MAX_GENERATED_SHIFTS; month = month.plus({ months: 1 })) {
      for (const day of monthDays) {
        if (day > month.daysInMonth) continue;
        const occurrence = month.set({ day });
        if (occurrence >= start && occurrence <= until && dates.length < MAX_GENERATED_SHIFTS) dates.push(occurrence);
      }
    }
    return dates;
  }
  throw Object.assign(new Error('recurrence must be none, weekly, or monthly'), { statusCode: 400 });
}

function validTemplateColor(color) {
  return /^#[0-9a-f]{6}$/i.test(color || '');
}

const WEEKLY_OVERTIME_WARNING_HOURS = 40;

function shiftInterval(date, startTime, endTime) {
  const day = typeof date === 'string' ? date.slice(0, 10) : DateTime.fromJSDate(date).toISODate();
  const start = DateTime.fromISO(day + 'T' + startTime);
  let end = DateTime.fromISO(day + 'T' + endTime);
  if (end <= start) end = end.plus({ days: 1 });
  return { start, end };
}

function paidShiftHours(startTime, endTime, breakMinutes) {
  return Math.max(0, computeShiftDurationHours(startTime, endTime) - Number(breakMinutes || 0) / 60);
}

async function analyseProposedShifts(client, tenantId, userId, dates, startTime, endTime, breakMinutes, excludeShiftId = null) {
  const proposed = dates.map(date => ({ date: date.toISODate(), ...shiftInterval(date.toISODate(), startTime, endTime) }));
  const firstDate = proposed[0].start.startOf('week').minus({ days: 1 }).toISODate();
  const lastDate = proposed[proposed.length - 1].end.endOf('week').plus({ days: 1 }).toISODate();
  const existingResult = await client.query(
    `SELECT sh.*, s.name AS site_name FROM shifts sh JOIN sites s ON s.id=sh.site_id
     WHERE sh.tenant_id=$1 AND sh.user_id=$2 AND sh.shift_date BETWEEN $3 AND $4
       AND ($5::int IS NULL OR sh.id <> $5)
     ORDER BY sh.shift_date, sh.start_time`, [tenantId, userId, firstDate, lastDate, excludeShiftId]
  );
  const existing = existingResult.rows.map(shift => ({ ...shift, ...shiftInterval(shift.shift_date, shift.start_time, shift.end_time) }));
  const conflicts = [];
  for (const candidate of proposed) {
    for (const shift of existing) {
      if (candidate.start < shift.end && candidate.end > shift.start) {
        conflicts.push({ proposed_date: candidate.date, existing_shift_id: shift.id, existing_date: String(shift.shift_date).slice(0,10), existing_time: shift.start_time + '–' + shift.end_time, site_name: shift.site_name });
      }
    }
  }

  const availabilityResult = await client.query(
    'SELECT * FROM guard_availability WHERE tenant_id=$1 AND user_id=$2', [tenantId,userId]
  );
  const availabilityByDay = new Map(availabilityResult.rows.map(row => [Number(row.weekday),row]));
  const leaveResult = await client.query(
    `SELECT id,start_date,end_date,leave_type FROM leave_requests
     WHERE tenant_id=$1 AND user_id=$2 AND status='approved' AND start_date <= $3 AND end_date >= $4`,
    [tenantId,userId,lastDate,firstDate]
  );
  const availability_conflicts=[];
  const timeMinutes=value=>{const [h,m]=String(value).split(':').map(Number);return h*60+m};
  for(const candidate of proposed){
    const leave=leaveResult.rows.find(item=>candidate.date>=String(item.start_date).slice(0,10)&&candidate.date<=String(item.end_date).slice(0,10));
    if(leave){availability_conflicts.push({date:candidate.date,type:'approved_leave',message:`${candidate.date}: guard is on approved ${leave.leave_type} leave.`});continue;}
    if(availabilityResult.rows.length){
      const rule=availabilityByDay.get(candidate.start.weekday%7);
      if(!rule||!rule.is_available){availability_conflicts.push({date:candidate.date,type:'unavailable_day',message:`${candidate.date}: guard marked this weekday unavailable.`});continue;}
      let shiftStart=timeMinutes(startTime),shiftEnd=timeMinutes(endTime),availableStart=timeMinutes(rule.available_from),availableEnd=timeMinutes(rule.available_until);
      if(shiftEnd<=shiftStart)shiftEnd+=1440;if(availableEnd<=availableStart)availableEnd+=1440;
      if(shiftStart<availableStart||shiftEnd>availableEnd)availability_conflicts.push({date:candidate.date,type:'outside_availability',message:`${candidate.date}: ${startTime}–${endTime} is outside availability ${rule.available_from}–${rule.available_until}.`});
    }
  }

  const weeklyHours = new Map();
  for (const shift of existing) {
    const week = shift.start.startOf('week').toISODate();
    weeklyHours.set(week, (weeklyHours.get(week) || 0) + paidShiftHours(shift.start_time, shift.end_time, shift.break_minutes));
  }
  const candidateHours = paidShiftHours(startTime, endTime, breakMinutes);
  for (const candidate of proposed) {
    const week = candidate.start.startOf('week').toISODate();
    weeklyHours.set(week, (weeklyHours.get(week) || 0) + candidateHours);
  }
  const warnings = [...weeklyHours.entries()]
    .filter(([, hours]) => hours > WEEKLY_OVERTIME_WARNING_HOURS)
    .map(([week_start, hours]) => ({ type: 'overtime', week_start, scheduled_hours: Math.round(hours * 100) / 100, threshold_hours: WEEKLY_OVERTIME_WARNING_HOURS,
      message: `Week of ${week_start}: ${Math.round(hours * 100) / 100} scheduled hours exceeds the ${WEEKLY_OVERTIME_WARNING_HOURS}-hour threshold.` }));
  return { conflicts, availability_conflicts, warnings, proposed_count: proposed.length };
}

app.get('/api/shift-templates', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = req.query.tenant_id || req.auth.tenant_id;
  if (!tenantId) return res.status(400).json({ error: 'tenant_id is required' });
  try {
    const result = await withTenant(tenantId, (client) => client.query(
      `SELECT st.*, s.name AS site_name
       FROM shift_templates st LEFT JOIN sites s ON s.id = st.site_id
       WHERE st.tenant_id = $1 ORDER BY st.name ASC`, [tenantId]
    ));
    res.json(result.rows.map(template => ({
      ...template,
      paid_hours: Math.max(0, Math.round((computeShiftDurationHours(template.start_time, template.end_time) - template.break_minutes / 60) * 100) / 100)
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/shift-templates', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, name, color, start_time, end_time, break_minutes, employment_type, notes } = req.body;
  if (!tenant_id || !name || !start_time || !end_time) {
    return res.status(400).json({ error: 'tenant_id, name, start_time, and end_time are required' });
  }
  if (!TIME_FORMAT_REGEX.test(start_time) || !TIME_FORMAT_REGEX.test(end_time)) {
    return res.status(400).json({ error: 'Start and end time must use HH:MM format' });
  }
  const breakMinutes = Number(break_minutes || 0);
  if (!Number.isInteger(breakMinutes) || breakMinutes < 0 || breakMinutes > 720) {
    return res.status(400).json({ error: 'Break must be between 0 and 720 minutes' });
  }
  const templateColor = validTemplateColor(color) ? color : '#2563eb';
  const employmentType = ['full_time', 'part_time'].includes(employment_type) ? employment_type : 'full_time';
  try {
    const result = await withTenant(tenant_id, async (client) => {
      if (site_id) {
        const site = await client.query('SELECT id FROM sites WHERE id = $1 AND tenant_id = $2', [site_id, tenant_id]);
        if (site.rows.length === 0) throw Object.assign(new Error('Site not found for this tenant'), { statusCode: 404 });
      }
      return client.query(
        `INSERT INTO shift_templates (tenant_id, site_id, name, color, start_time, end_time, break_minutes, employment_type, notes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [tenant_id, site_id || null, name.trim(), templateColor, start_time, end_time, breakMinutes, employmentType, notes || null]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(err.statusCode || 500).json({ error: err.message }); }
});

app.patch('/api/shift-templates/:id', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, name, color, start_time, end_time, break_minutes, employment_type, notes } = req.body;
  if (!tenant_id || !name || !start_time || !end_time) return res.status(400).json({ error: 'All required template fields must be supplied' });
  if (!TIME_FORMAT_REGEX.test(start_time) || !TIME_FORMAT_REGEX.test(end_time)) return res.status(400).json({ error: 'Start and end time must use HH:MM format' });
  const breakMinutes = Number(break_minutes || 0);
  if (!Number.isInteger(breakMinutes) || breakMinutes < 0 || breakMinutes > 720) return res.status(400).json({ error: 'Break must be between 0 and 720 minutes' });
  try {
    const result = await withTenant(tenant_id, (client) => client.query(
      `UPDATE shift_templates SET site_id=$1, name=$2, color=$3, start_time=$4, end_time=$5,
       break_minutes=$6, employment_type=$7, notes=$8, updated_at=NOW()
       WHERE id=$9 AND tenant_id=$10 RETURNING *`,
      [site_id || null, name.trim(), validTemplateColor(color) ? color : '#2563eb', start_time, end_time,
       breakMinutes, ['full_time','part_time'].includes(employment_type) ? employment_type : 'full_time', notes || null, req.params.id, tenant_id]
    ));
    if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/shift-templates/:id', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = req.query.tenant_id;
  if (!tenantId) return res.status(400).json({ error: 'tenant_id is required' });
  try {
    const result = await withTenant(tenantId, (client) => client.query(
      'DELETE FROM shift_templates WHERE id=$1 AND tenant_id=$2 RETURNING id', [req.params.id, tenantId]
    ));
    if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/shifts', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, user_id, start_date, start_time, end_time, break_minutes,
    employment_type, recurrence, days_of_week, days_of_month, repeat_until, notes, dry_run } = req.body;
  if (!tenant_id || !site_id || !user_id || !start_date || !start_time || !end_time) {
    return res.status(400).json({ error: 'tenant_id, site_id, user_id, start_date, start_time, and end_time are required' });
  }
  if (!TIME_FORMAT_REGEX.test(start_time) || !TIME_FORMAT_REGEX.test(end_time)) {
    return res.status(400).json({ error: 'Start and end time must use HH:MM format' });
  }
  const employmentType = ['full_time', 'part_time'].includes(employment_type) ? employment_type : 'full_time';
  const recurrenceType = ['none', 'weekly', 'monthly'].includes(recurrence) ? recurrence : 'none';
  const breakMinutes = Number(break_minutes || 0);
  if (!Number.isInteger(breakMinutes) || breakMinutes < 0 || breakMinutes > 720) return res.status(400).json({ error: 'Break must be between 0 and 720 minutes' });

  try {
    const dates = generateShiftDates({ recurrence: recurrenceType, start_date, repeat_until, days_of_week, days_of_month });
    if (dates.length === 0) return res.status(400).json({ error: 'No shift dates match the recurrence settings' });

    const shifts = await withTenant(tenant_id, async (client) => {
      const guard = await client.query("SELECT id FROM users WHERE id = $1 AND tenant_id = $2 AND role = 'guard'", [user_id, tenant_id]);
      if (guard.rows.length === 0) throw Object.assign(new Error('Guard not found for this tenant'), { statusCode: 404 });
      const site = await client.query('SELECT id FROM sites WHERE id = $1 AND tenant_id = $2', [site_id, tenant_id]);
      if (site.rows.length === 0) throw Object.assign(new Error('Site not found for this tenant'), { statusCode: 404 });

      const analysis = await analyseProposedShifts(client, tenant_id, user_id, dates, start_time, end_time, breakMinutes);
      if (analysis.conflicts.length > 0) {
        const err = new Error(`Cannot create shifts: ${analysis.conflicts.length} overlap with the guard's existing schedule.`);
        err.statusCode = 409;
        err.code = 'SHIFT_CONFLICT';
        err.conflicts = analysis.conflicts;
        throw err;
      }
      if(analysis.availability_conflicts.length){const err=new Error(`Cannot create shifts: guard is unavailable on ${analysis.availability_conflicts.length} proposed date(s).`);err.statusCode=409;err.code='GUARD_UNAVAILABLE';err.availability_conflicts=analysis.availability_conflicts;throw err;}
      if (dry_run) return { dryRun: true, analysis };

      const seriesId = recurrenceType === 'none' ? null : crypto.randomUUID();
      const inserted = [];
      for (const date of dates) {
        const result = await client.query(
          `INSERT INTO shifts (tenant_id, site_id, user_id, shift_date, start_time, end_time, break_minutes, employment_type, recurrence_group_id, notes)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
          [tenant_id, site_id, user_id, date.toISODate(), start_time, end_time, breakMinutes, employmentType, seriesId, notes || null]
        );
        inserted.push(result.rows[0]);
      }
      return { inserted, analysis };
    });
    if (shifts.dryRun) return res.json({ valid: true, ...shifts.analysis });
    res.status(201).json({ created_count: shifts.inserted.length, recurrence_group_id: shifts.inserted[0].recurrence_group_id, shifts: shifts.inserted, warnings: shifts.analysis.warnings });
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message, code: err.code, conflicts: err.conflicts, availability_conflicts:err.availability_conflicts });
  }
});

app.patch('/api/shifts/:id/confirmation', requireAuth, async (req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can confirm shifts'});
  const tenantId=attendanceTenant(req,req.body.tenant_id),status=req.body.status;
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!['confirmed','declined'].includes(status))return res.status(400).json({error:'Status must be confirmed or declined'});
  try{const result=await withTenant(tenantId,client=>client.query(
    `UPDATE shifts SET confirmation_status=$1,confirmed_at=NOW() WHERE id=$2 AND tenant_id=$3 AND user_id=$4 AND assignment_status='assigned' RETURNING *`,
    [status,req.params.id,tenantId,req.auth.user_id]));if(!result.rows.length)return res.status(404).json({error:'Shift not found'});res.json(result.rows[0]);}
  catch(err){res.status(500).json({error:err.message});}
});

app.patch('/api/shifts/:id/make-open',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(
    `UPDATE shifts SET assignment_status='open',confirmation_status='pending',confirmed_at=NULL WHERE id=$1 AND tenant_id=$2 AND shift_date>=CURRENT_DATE RETURNING *`,
    [req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Future shift not found'});res.json(result.rows[0]);}
  catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/open-shifts',requireAuth,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(
    `SELECT sh.*,s.name AS site_name FROM shifts sh JOIN sites s ON s.id=sh.site_id
     WHERE sh.tenant_id=$1 AND sh.assignment_status='open' AND sh.shift_date>=CURRENT_DATE ORDER BY sh.shift_date,sh.start_time`,[tenantId]));res.json(result.rows.map(s=>({...s,duration_hours:paidShiftHours(s.start_time,s.end_time,s.break_minutes)})));}
  catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/open-shifts/:id/claim',requireAuth,async(req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can claim shifts'});const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);const locked=await client.query("SELECT * FROM shifts WHERE id=$1 AND tenant_id=$2 AND assignment_status='open' FOR UPDATE",[req.params.id,tenantId]);if(!locked.rows.length){await client.query('ROLLBACK');return res.status(409).json({error:'This open shift is no longer available'})}const shift=locked.rows[0];const assigned=await client.query('SELECT 1 FROM guard_assignments WHERE tenant_id=$1 AND site_id=$2 AND user_id=$3',[tenantId,shift.site_id,req.auth.user_id]);if(!assigned.rows.length)throw Object.assign(new Error('You must be assigned to this site to claim the shift'),{statusCode:403});const analysis=await analyseProposedShifts(client,tenantId,req.auth.user_id,[DateTime.fromISO(String(shift.shift_date).slice(0,10))],shift.start_time,shift.end_time,shift.break_minutes,shift.id);if(analysis.conflicts.length||analysis.availability_conflicts.length)throw Object.assign(new Error(analysis.availability_conflicts[0]?.message||'This shift conflicts with your schedule'),{statusCode:409});const result=await client.query("UPDATE shifts SET user_id=$1,assignment_status='assigned',confirmation_status='confirmed',confirmed_at=NOW() WHERE id=$2 RETURNING *",[req.auth.user_id,shift.id]);await client.query('COMMIT');res.json({shift:result.rows[0],warnings:analysis.warnings});}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}
});

app.post('/api/shift-swaps',requireAuth,async(req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can request swaps'});const tenantId=attendanceTenant(req,req.body.tenant_id);const {shift_id,target_user_id,reason}=req.body;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(Number(target_user_id)===Number(req.auth.user_id))return res.status(400).json({error:'Choose another guard'});
  try{const result=await withTenant(tenantId,async client=>{const shift=await client.query("SELECT * FROM shifts WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND assignment_status='assigned' AND shift_date>=CURRENT_DATE",[shift_id,tenantId,req.auth.user_id]);if(!shift.rows.length)throw Object.assign(new Error('Eligible shift not found'),{statusCode:404});const target=await client.query("SELECT 1 FROM users u JOIN guard_assignments ga ON ga.user_id=u.id AND ga.site_id=$1 AND ga.tenant_id=$2 WHERE u.id=$3 AND u.tenant_id=$2 AND u.role='guard'",[shift.rows[0].site_id,tenantId,target_user_id]);if(!target.rows.length)throw Object.assign(new Error('Target guard is not assigned to this site'),{statusCode:400});return client.query("INSERT INTO shift_swap_requests (tenant_id,shift_id,requester_id,target_user_id,reason) VALUES ($1,$2,$3,$4,$5) RETURNING *",[tenantId,shift_id,req.auth.user_id,target_user_id,reason||null])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.get('/api/shifts/:id/swap-targets',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can request swaps'});const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`SELECT DISTINCT u.id,u.email FROM shifts sh JOIN guard_assignments ga ON ga.site_id=sh.site_id AND ga.tenant_id=sh.tenant_id JOIN users u ON u.id=ga.user_id WHERE sh.id=$1 AND sh.tenant_id=$2 AND sh.user_id=$3 AND u.id<>$3 AND u.role='guard' ORDER BY u.email`,[req.params.id,tenantId,req.auth.user_id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/shift-swaps',requireAuth,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>{let query=`SELECT sw.*,sh.shift_date,sh.start_time,sh.end_time,s.name AS site_name,r.email AS requester_email,t.email AS target_email FROM shift_swap_requests sw JOIN shifts sh ON sh.id=sw.shift_id JOIN sites s ON s.id=sh.site_id JOIN users r ON r.id=sw.requester_id JOIN users t ON t.id=sw.target_user_id WHERE sw.tenant_id=$1`;const params=[tenantId];if(req.auth.role!=='admin'){params.push(req.auth.user_id);query+=` AND (sw.requester_id=$${params.length} OR sw.target_user_id=$${params.length})`}query+=' ORDER BY sw.created_at DESC LIMIT 250';return client.query(query,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/shift-swaps/:id/respond',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can respond'});const tenantId=attendanceTenant(req,req.body.tenant_id),accepted=Boolean(req.body.accepted);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query("UPDATE shift_swap_requests SET status=$1,recipient_responded_at=NOW() WHERE id=$2 AND tenant_id=$3 AND target_user_id=$4 AND status='pending_recipient' RETURNING *",[accepted?'pending_admin':'declined',req.params.id,tenantId,req.auth.user_id]));if(!result.rows.length)return res.status(409).json({error:'Request not found or already answered'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/shift-swaps/:id/review',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),approved=Boolean(req.body.approved);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);const swapResult=await client.query("SELECT sw.id AS swap_request_id,sw.shift_id,sw.target_user_id,sh.shift_date,sh.start_time,sh.end_time,sh.break_minutes FROM shift_swap_requests sw JOIN shifts sh ON sh.id=sw.shift_id WHERE sw.id=$1 AND sw.tenant_id=$2 AND sw.status='pending_admin' FOR UPDATE",[req.params.id,tenantId]);if(!swapResult.rows.length)throw Object.assign(new Error('Swap not found or not ready for review'),{statusCode:409});const sw=swapResult.rows[0];if(approved){const analysis=await analyseProposedShifts(client,tenantId,sw.target_user_id,[DateTime.fromISO(String(sw.shift_date).slice(0,10))],sw.start_time,sw.end_time,sw.break_minutes,sw.shift_id);if(analysis.conflicts.length||analysis.availability_conflicts.length)throw Object.assign(new Error(analysis.availability_conflicts[0]?.message||'Target guard now has a schedule conflict'),{statusCode:409});await client.query("UPDATE shifts SET user_id=$1,confirmation_status='confirmed',confirmed_at=NOW() WHERE id=$2",[sw.target_user_id,sw.shift_id]);}await client.query("UPDATE shift_swap_requests SET status=$1,admin_reviewed_at=NOW(),admin_reviewed_by=$2,admin_notes=$3 WHERE id=$4",[approved?'approved':'rejected',req.auth.user_id,req.body.admin_notes||null,sw.swap_request_id]);await client.query('COMMIT');res.json({status:approved?'approved':'rejected'});}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}});

app.get('/api/shifts', requireAuth, async (req, res) => {
  const { tenant_id, site_id, user_id, start_date, end_date } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  if (req.auth.role !== 'admin' && user_id && Number(user_id) !== req.auth.user_id) {
    return res.status(403).json({ error: 'Guards can only view their own shifts' });
  }
  const effectiveUserId = req.auth.role === 'admin' ? user_id : req.auth.user_id;

  try {
    const result = await withTenant(tenant_id, (client) => {
      let query = `SELECT sh.*, u.email AS guard_email, s.name AS site_name
                   FROM shifts sh JOIN users u ON u.id = sh.user_id JOIN sites s ON s.id = sh.site_id
                   WHERE sh.tenant_id = $1`;
      const params = [tenant_id];
      if (effectiveUserId) { params.push(effectiveUserId); query += ` AND sh.user_id = $${params.length}`; }
      if (req.auth.role !== 'admin') query += ` AND sh.assignment_status = 'assigned'`;
      if (site_id) { params.push(site_id); query += ` AND sh.site_id = $${params.length}`; }
      if (start_date) { params.push(start_date); query += ` AND sh.shift_date >= $${params.length}`; }
      if (end_date) { params.push(end_date); query += ` AND sh.shift_date <= $${params.length}`; }
      if (!start_date && !end_date) query += ' AND sh.shift_date >= CURRENT_DATE';
      query += ' ORDER BY sh.shift_date ASC, sh.start_time ASC LIMIT 500';
      return client.query(query, params);
    });
    res.json(result.rows.map(shift => ({ ...shift, duration_hours: Math.max(0, Math.round((computeShiftDurationHours(shift.start_time, shift.end_time) - Number(shift.break_minutes || 0) / 60) * 100) / 100) })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/shifts/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, site_id, shift_date, start_time, end_time, break_minutes, employment_type, notes } = req.body;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id is required' });
  if (start_time && !TIME_FORMAT_REGEX.test(start_time)) return res.status(400).json({ error: 'start_time must use HH:MM format' });
  if (end_time && !TIME_FORMAT_REGEX.test(end_time)) return res.status(400).json({ error: 'end_time must use HH:MM format' });
  const employmentType = employment_type && ['full_time', 'part_time'].includes(employment_type) ? employment_type : null;
  try {
    const result = await withTenant(tenant_id, async client => {
      const currentResult = await client.query('SELECT * FROM shifts WHERE id=$1 AND tenant_id=$2', [id, tenant_id]);
      if (!currentResult.rows.length) throw Object.assign(new Error('Shift not found'), { statusCode: 404 });
      const current = currentResult.rows[0];
      const nextDate = shift_date || String(current.shift_date).slice(0,10);
      const nextStart = start_time || current.start_time;
      const nextEnd = end_time || current.end_time;
      const nextBreak = break_minutes === undefined ? current.break_minutes : Number(break_minutes);
      const analysis = await analyseProposedShifts(client, tenant_id, current.user_id, [DateTime.fromISO(nextDate)], nextStart, nextEnd, nextBreak, Number(id));
      if (analysis.conflicts.length) {
        const err = new Error('Cannot save this shift because it overlaps the guard\'s existing schedule.');
        err.statusCode = 409; err.code = 'SHIFT_CONFLICT'; err.conflicts = analysis.conflicts; throw err;
      }
      if(analysis.availability_conflicts.length){const err=new Error('Cannot save this shift because the guard is unavailable.');err.statusCode=409;err.code='GUARD_UNAVAILABLE';err.availability_conflicts=analysis.availability_conflicts;throw err;}
      const updated = await client.query(
        `UPDATE shifts SET site_id = COALESCE($1, site_id), shift_date = COALESCE($2, shift_date),
         start_time = COALESCE($3, start_time), end_time = COALESCE($4, end_time),
         break_minutes = COALESCE($5, break_minutes), employment_type = COALESCE($6, employment_type), notes = $7
         WHERE id = $8 AND tenant_id = $9 RETURNING *`,
        [site_id || null, shift_date || null, start_time || null, end_time || null,
         break_minutes === undefined ? null : Number(break_minutes), employmentType, notes ?? null, id, tenant_id]
      );
      return { shift: updated.rows[0], warnings: analysis.warnings };
    });
    res.json(result);
  } catch (err) { res.status(err.statusCode || 500).json({ error: err.message, code: err.code, conflicts: err.conflicts, availability_conflicts:err.availability_conflicts }); }
});

app.delete('/api/shifts/:id', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) => client.query(
      'DELETE FROM shifts WHERE id = $1 AND tenant_id = $2 RETURNING *', [req.params.id, tenant_id]
    ));
    if (result.rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/shifts/series/:recurrenceGroupId', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) => client.query(
      'DELETE FROM shifts WHERE tenant_id = $1 AND recurrence_group_id = $2 AND shift_date >= CURRENT_DATE RETURNING id',
      [tenant_id, req.params.recurrenceGroupId]
    ));
    res.json({ deleted_count: result.rows.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ------------------------ GUARD CERTIFICATIONS ------------------------

const CERT_EXPIRY_WARNING_DAYS = 30;

function computeCertStatus(expiryDate) {
  const today = DateTime.now().startOf('day');
  const expiry = DateTime.fromJSDate(new Date(expiryDate)).startOf('day');
  const daysRemaining = Math.round(expiry.diff(today, 'days').days);

  let status = 'valid';
  if (daysRemaining < 0) status = 'expired';
  else if (daysRemaining <= CERT_EXPIRY_WARNING_DAYS) status = 'expiring_soon';

  return { status, days_remaining: daysRemaining };
}

app.get('/api/certifications', requireAuth, async (req, res) => {
  const { tenant_id: queryTenant } = req.query;
  const { user_id } = req.query;

  const effectiveTenantId = queryTenant || req.auth.tenant_id;
  if (!effectiveTenantId) {
    return res.status(400).json({ error: 'tenant_id is required' });
  }

  try {
    const result = await withTenant(effectiveTenantId, (client) => {
      if (user_id) {
        return client.query(
          `SELECT c.*, u.email as guard_email
           FROM guard_certifications c
           JOIN users u ON u.id = c.user_id
           WHERE c.tenant_id = $1 AND c.user_id = $2
           ORDER BY c.expiry_date ASC, c.cert_name ASC`,
          [effectiveTenantId, user_id]
        );
      }
      return client.query(
        `SELECT c.*, u.email as guard_email
         FROM guard_certifications c
         JOIN users u ON u.id = c.user_id
         WHERE c.tenant_id = $1
         ORDER BY c.expiry_date ASC, c.cert_name ASC`,
        [effectiveTenantId]
      );
    });
    res.json(result.rows.map(cert => ({ ...cert, ...computeCertStatus(cert.expiry_date) })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/certifications/expiring', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id: queryTenant } = req.query;
  const effectiveTenantId = queryTenant || req.auth.tenant_id;
  if (!effectiveTenantId) {
    return res.status(400).json({ error: 'tenant_id is required' });
  }

  try {
    const result = await withTenant(effectiveTenantId, (client) =>
      client.query(
        `SELECT c.*, u.email as guard_email
         FROM guard_certifications c
         JOIN users u ON u.id = c.user_id
         WHERE c.tenant_id = $1
         ORDER BY c.expiry_date ASC`,
        [effectiveTenantId]
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

app.post('/api/certifications', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, user_id, cert_name, cert_number, issue_date, expiry_date } = req.body;
  if (!tenant_id || !user_id || !cert_name || !expiry_date) {
    return res.status(400).json({ error: 'tenant_id, user_id, cert_name, and expiry_date are required' });
  }
  if (Number.isNaN(new Date(expiry_date).getTime())) {
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

app.patch('/api/certifications/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, cert_name, cert_number, issue_date, expiry_date } = req.body;
  if (!tenant_id) {
    return res.status(400).json({ error: 'tenant_id is required' });
  }

  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `UPDATE guard_certifications
         SET cert_name = COALESCE($3, cert_name),
             cert_number = $4,
             issue_date = $5,
             expiry_date = COALESCE($6, expiry_date)
         WHERE id = $1 AND tenant_id = $2
         RETURNING *`,
        [id, tenant_id, cert_name || null, cert_number || null, issue_date || null, expiry_date || null]
      )
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Certification not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/certifications/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) {
    return res.status(400).json({ error: 'tenant_id is required' });
  }

  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'DELETE FROM guard_certifications WHERE id = $1 AND tenant_id = $2 RETURNING *',
        [id, tenant_id]
      )
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Certification not found' });
    }
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ PHASE 4: NOTIFICATIONS & ESCALATIONS ------------------------

function communicationTenant(req, suppliedTenantId) {
  const tokenTenant = Number(req.auth && req.auth.tenant_id);
  const requestedTenant = Number(suppliedTenantId || tokenTenant);
  if (!Number.isInteger(tokenTenant) || !Number.isInteger(requestedTenant) || tokenTenant !== requestedTenant) return null;
  return requestedTenant;
}

function communicationAudienceSql(role, userPlaceholder = '$2') {
  return role === 'admin'
    ? `(${userPlaceholder}::integer IS NOT NULL)`
    : `(n.audience IN ('all','all_guards') OR n.recipient_user_id = ${userPlaceholder})`;
}

app.get('/api/communication-notifications', requireAuth, async (req, res) => {
  const tenantId = communicationTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!['admin', 'guard'].includes(req.auth.role)) return res.status(403).json({ error: 'Notification inbox is unavailable for this role' });
  const userId = Number(req.auth.user_id);
  const status = String(req.query.status || 'active');
  try {
    const result = await withTenant(tenantId, (client) => client.query(
      `SELECT n.*, r.read_at, r.acknowledged_at, u.email AS recipient_email, creator.email AS created_by_email
       FROM communication_notifications n
       LEFT JOIN communication_notification_receipts r ON r.notification_id=n.id AND r.user_id=$2 AND r.tenant_id=n.tenant_id
       LEFT JOIN users u ON u.id=n.recipient_user_id AND u.tenant_id=n.tenant_id
       LEFT JOIN users creator ON creator.id=n.created_by_user_id AND creator.tenant_id=n.tenant_id
       WHERE n.tenant_id=$1 AND ${communicationAudienceSql(req.auth.role)}
         AND (n.expires_at IS NULL OR n.expires_at > NOW())
         AND ($3='all' OR $3='active' OR ($3='unread' AND r.read_at IS NULL) OR ($3='ack_required' AND n.requires_acknowledgement=TRUE AND r.acknowledged_at IS NULL))
       ORDER BY CASE n.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END, n.created_at DESC LIMIT 250`,
      [tenantId, userId, status]
    ));
    res.json({ notifications: result.rows, unread_count: result.rows.filter(x => !x.read_at).length,
      acknowledgement_count: result.rows.filter(x => x.requires_acknowledgement && !x.acknowledged_at).length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/communication-notifications', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = communicationTenant(req, req.body.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const title=String(req.body.title||'').trim(), message=String(req.body.message||'').trim();
  const category=String(req.body.category||'general').trim().toLowerCase(), priority=String(req.body.priority||'normal').trim().toLowerCase();
  const audience=String(req.body.audience||'all_guards').trim().toLowerCase(), recipientUserId=req.body.recipient_user_id?Number(req.body.recipient_user_id):null;
  const actionUrl=String(req.body.action_url||'').trim()||null, expiresAt=req.body.expires_at||null;
  if (!title || !message) return res.status(400).json({ error: 'Title and message are required' });
  if (title.length>160 || message.length>4000) return res.status(400).json({ error: 'Title or message is too long' });
  if (!['low','normal','high','critical'].includes(priority)) return res.status(400).json({ error: 'Invalid priority' });
  if (!['all','admins','all_guards','specific_guard'].includes(audience)) return res.status(400).json({ error: 'Invalid audience' });
  if (audience==='specific_guard' && !Number.isInteger(recipientUserId)) return res.status(400).json({ error: 'Select a guard' });
  if (actionUrl && (/^\s*(javascript|data):/i.test(actionUrl) || actionUrl.length>500)) return res.status(400).json({ error: 'Invalid action URL' });
  try {
    const result = await withTenant(tenantId, async client => {
      if (audience==='specific_guard') {
        const guard=await client.query("SELECT id FROM users WHERE id=$1 AND tenant_id=$2 AND role='guard'",[recipientUserId,tenantId]);
        if (!guard.rowCount) { const e=new Error('Guard not found'); e.statusCode=404; throw e; }
      }
      return client.query(`INSERT INTO communication_notifications
        (tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
        [tenantId,title,message,category,priority,audience,audience==='specific_guard'?recipientUserId:null,actionUrl,
         Boolean(req.body.requires_acknowledgement),req.auth.user_id,expiresAt]);
    });
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(err.statusCode||500).json({ error: err.message }); }
});

async function updateCommunicationReceipt(req, res, acknowledge) {
  const tenantId=communicationTenant(req,req.body.tenant_id||req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error:'Tenant access denied' });
  try {
    const result=await withTenant(tenantId,async client=>{
      const visible=await client.query(`SELECT n.id,n.requires_acknowledgement FROM communication_notifications n
        WHERE n.id=$1 AND n.tenant_id=$2 AND ${communicationAudienceSql(req.auth.role, '$3')}`,[req.params.id,tenantId,req.auth.user_id]);
      if (!visible.rowCount) { const e=new Error('Notification not found'); e.statusCode=404; throw e; }
      if (acknowledge&&!visible.rows[0].requires_acknowledgement) { const e=new Error('This notification does not require acknowledgement'); e.statusCode=400; throw e; }
      return client.query(`INSERT INTO communication_notification_receipts(notification_id,tenant_id,user_id,read_at,acknowledged_at)
        VALUES($1,$2,$3,NOW(),${acknowledge?'NOW()':'NULL'}) ON CONFLICT(notification_id,user_id) DO UPDATE SET
        read_at=COALESCE(communication_notification_receipts.read_at,NOW()), acknowledged_at=${acknowledge?'NOW()':'communication_notification_receipts.acknowledged_at'} RETURNING *`,
        [req.params.id,tenantId,req.auth.user_id]);
    });
    res.json(result.rows[0]);
  } catch(err) { res.status(err.statusCode||500).json({ error:err.message }); }
}
app.patch('/api/communication-notifications/:id/read',requireAuth,(req,res)=>updateCommunicationReceipt(req,res,false));
app.patch('/api/communication-notifications/:id/acknowledge',requireAuth,(req,res)=>updateCommunicationReceipt(req,res,true));

app.delete('/api/communication-notifications/:id',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error:'Tenant access denied' });
  try { const result=await withTenant(tenantId,client=>client.query('DELETE FROM communication_notifications WHERE id=$1 AND tenant_id=$2 RETURNING id',[req.params.id,tenantId]));
    if(!result.rowCount)return res.status(404).json({error:'Notification not found'}); res.json({deleted:true});
  } catch(err){res.status(500).json({error:err.message});}
});

// ------------------------ PHASE 4.2: TEAM MESSAGING ------------------------

function conversationAccessSql(role, userPlaceholder = '$2') {
  return role === 'admin' ? `(${userPlaceholder}::integer IS NOT NULL)` : `(c.kind='company' OR (c.kind='direct' AND c.guard_user_id=${userPlaceholder}))`;
}

async function ensureCompanyConversation(client, tenantId, creatorId) {
  await client.query(`INSERT INTO team_conversations(tenant_id,title,kind,created_by_user_id)
    VALUES($1,'Company Announcements','company',$2) ON CONFLICT DO NOTHING`,[tenantId,creatorId]);
}

app.get('/api/team-conversations',requireAuth,async(req,res)=>{
  const tenantId=communicationTenant(req,req.query.tenant_id);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!['admin','guard'].includes(req.auth.role))return res.status(403).json({error:'Messaging is unavailable for this role'});
  try{
    const result=await withTenant(tenantId,async client=>{
      await ensureCompanyConversation(client,tenantId,req.auth.user_id);
      return client.query(`SELECT c.*,u.email AS guard_email,
        (SELECT m.message FROM team_messages m WHERE m.conversation_id=c.id AND m.tenant_id=c.tenant_id ORDER BY m.created_at DESC LIMIT 1) AS last_message,
        (SELECT m.created_at FROM team_messages m WHERE m.conversation_id=c.id AND m.tenant_id=c.tenant_id ORDER BY m.created_at DESC LIMIT 1) AS last_message_at,
        (SELECT COUNT(*)::int FROM team_messages m WHERE m.conversation_id=c.id AND m.tenant_id=c.tenant_id
          AND m.sender_user_id<>$2 AND m.created_at>COALESCE(r.last_read_at,'1970-01-01')) AS unread_count
        FROM team_conversations c LEFT JOIN users u ON u.id=c.guard_user_id AND u.tenant_id=c.tenant_id
        LEFT JOIN team_conversation_reads r ON r.conversation_id=c.id AND r.user_id=$2
        WHERE c.tenant_id=$1 AND ${conversationAccessSql(req.auth.role)}
        ORDER BY COALESCE((SELECT MAX(created_at) FROM team_messages WHERE conversation_id=c.id),c.created_at) DESC`,
        [tenantId,req.auth.user_id]);
    });
    res.json(result.rows);
  }catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/team-conversations/direct',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id),guardId=Number(req.body.guard_user_id);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!Number.isInteger(guardId))return res.status(400).json({error:'Select a guard'});
  try{
    const result=await withTenant(tenantId,async client=>{
      const guard=await client.query("SELECT id,email FROM users WHERE id=$1 AND tenant_id=$2 AND role='guard'",[guardId,tenantId]);
      if(!guard.rowCount){const e=new Error('Guard not found');e.statusCode=404;throw e;}
      return client.query(`INSERT INTO team_conversations(tenant_id,title,kind,guard_user_id,created_by_user_id)
        VALUES($1,$2,'direct',$3,$4) ON CONFLICT(tenant_id,guard_user_id) WHERE kind='direct'
        DO UPDATE SET title=EXCLUDED.title RETURNING *`,[tenantId,guard.rows[0].email,guardId,req.auth.user_id]);
    });
    res.status(201).json(result.rows[0]);
  }catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.get('/api/team-conversations/:id/messages',requireAuth,async(req,res)=>{
  const tenantId=communicationTenant(req,req.query.tenant_id);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{
    const result=await withTenant(tenantId,async client=>{
      const access=await client.query(`SELECT c.id FROM team_conversations c WHERE c.id=$1 AND c.tenant_id=$2 AND ${conversationAccessSql(req.auth.role,'$3')}`,
        [req.params.id,tenantId,req.auth.user_id]);
      if(!access.rowCount){const e=new Error('Conversation not found');e.statusCode=404;throw e;}
      await client.query(`INSERT INTO team_conversation_reads(tenant_id,conversation_id,user_id,last_read_at) VALUES($1,$2,$3,NOW())
        ON CONFLICT(conversation_id,user_id) DO UPDATE SET last_read_at=NOW()`,[tenantId,req.params.id,req.auth.user_id]);
      return client.query(`SELECT m.*,u.email AS sender_email FROM team_messages m LEFT JOIN users u ON u.id=m.sender_user_id AND u.tenant_id=m.tenant_id
        WHERE m.tenant_id=$1 AND m.conversation_id=$2 ORDER BY m.created_at ASC LIMIT 500`,[tenantId,req.params.id]);
    });
    res.json(result.rows);
  }catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.post('/api/team-conversations/:id/messages',requireAuth,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id),message=String(req.body.message||'').trim();
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!message)return res.status(400).json({error:'Message is required'});
  if(message.length>4000)return res.status(400).json({error:'Message is too long'});
  try{
    const result=await withTenant(tenantId,async client=>{
      const access=await client.query(`SELECT c.id,c.kind FROM team_conversations c WHERE c.id=$1 AND c.tenant_id=$2 AND ${conversationAccessSql(req.auth.role,'$3')}`,
        [req.params.id,tenantId,req.auth.user_id]);
      if(!access.rowCount){const e=new Error('Conversation not found');e.statusCode=404;throw e;}
      if(req.auth.role==='guard'&&access.rows[0].kind==='company'){const e=new Error('Only admins can post company announcements');e.statusCode=403;throw e;}
      const inserted=await client.query(`INSERT INTO team_messages(tenant_id,conversation_id,sender_user_id,sender_role,message)
        VALUES($1,$2,$3,$4,$5) RETURNING *`,[tenantId,req.params.id,req.auth.user_id,req.auth.role,message]);
      await client.query(`INSERT INTO team_conversation_reads(tenant_id,conversation_id,user_id,last_read_at) VALUES($1,$2,$3,NOW())
        ON CONFLICT(conversation_id,user_id) DO UPDATE SET last_read_at=NOW()`,[tenantId,req.params.id,req.auth.user_id]);
      return inserted;
    });
    res.status(201).json(result.rows[0]);
  }catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

// ------------------------ PHASE 4.3: LONE-WORKER SAFETY ------------------------

function loneWorkerStatusSql() {
  return `SELECT s.*,u.email AS guard_email,si.name AS site_name,a.clocked_in_at,
    (SELECT MAX(c.checked_in_at) FROM lone_worker_checkins c WHERE c.setting_id=s.id AND c.user_id=s.user_id) AS last_check_in,
    la.id AS alert_id,la.created_at AS alert_created_at,
    COALESCE((SELECT MAX(c.checked_in_at) FROM lone_worker_checkins c WHERE c.setting_id=s.id AND c.user_id=s.user_id),a.clocked_in_at) AS safety_reference
    FROM lone_worker_settings s JOIN users u ON u.id=s.user_id AND u.tenant_id=s.tenant_id
    JOIN sites si ON si.id=s.site_id AND si.tenant_id=s.tenant_id
    LEFT JOIN attendance_sessions a ON a.user_id=s.user_id AND a.site_id=s.site_id AND a.tenant_id=s.tenant_id AND a.clocked_out_at IS NULL
    LEFT JOIN lone_worker_alerts la ON la.setting_id=s.id AND la.resolved=FALSE`;
}

app.get('/api/lone-worker/settings',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`${loneWorkerStatusSql()} WHERE s.tenant_id=$1 ORDER BY u.email,si.name`,[tenantId]));res.json(result.rows);}
  catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/lone-worker/settings',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id),userId=Number(req.body.user_id),siteId=Number(req.body.site_id);
  const interval=Number(req.body.interval_minutes),grace=Number(req.body.grace_minutes);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!Number.isInteger(userId)||!Number.isInteger(siteId)||!Number.isInteger(interval)||interval<5||interval>720||!Number.isInteger(grace)||grace<0||grace>120)return res.status(400).json({error:'Guard, site, interval (5–720), and grace (0–120) are required'});
  try{const result=await withTenant(tenantId,async client=>{
    const valid=await client.query(`SELECT u.id FROM users u JOIN sites s ON s.tenant_id=u.tenant_id WHERE u.id=$1 AND s.id=$2 AND u.tenant_id=$3 AND u.role='guard'`,[userId,siteId,tenantId]);
    if(!valid.rowCount){const e=new Error('Guard or site not found');e.statusCode=404;throw e;}
    return client.query(`INSERT INTO lone_worker_settings(tenant_id,user_id,site_id,enabled,interval_minutes,grace_minutes,instructions)
      VALUES($1,$2,$3,TRUE,$4,$5,$6) ON CONFLICT(tenant_id,user_id,site_id) DO UPDATE SET enabled=TRUE,interval_minutes=$4,grace_minutes=$5,instructions=$6,updated_at=NOW() RETURNING *`,
      [tenantId,userId,siteId,interval,grace,String(req.body.instructions||'').trim()||null]);});res.status(201).json(result.rows[0]);}
  catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.patch('/api/lone-worker/settings/:id/toggle',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query('UPDATE lone_worker_settings SET enabled=$3,updated_at=NOW() WHERE id=$1 AND tenant_id=$2 RETURNING *',[req.params.id,tenantId,Boolean(req.body.enabled)]));if(!result.rowCount)return res.status(404).json({error:'Setting not found'});res.json(result.rows[0]);}
  catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/lone-worker/current',requireAuth,async(req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`${loneWorkerStatusSql()} WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.enabled=TRUE AND a.id IS NOT NULL ORDER BY a.clocked_in_at DESC LIMIT 1`,[tenantId,req.auth.user_id]));
    if(!result.rowCount)return res.json({active:false});const row=result.rows[0],reference=new Date(row.safety_reference),due=new Date(reference.getTime()+Number(row.interval_minutes)*60000),escalates=new Date(due.getTime()+Number(row.grace_minutes)*60000);res.json({active:true,setting:row,due_at:due,escalates_at:escalates,overdue:Date.now()>escalates.getTime()});}
  catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/lone-worker/check-in',requireAuth,async(req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const tenantId=communicationTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,async client=>{const active=await client.query(`${loneWorkerStatusSql()} WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.enabled=TRUE AND a.id IS NOT NULL ORDER BY a.clocked_in_at DESC LIMIT 1`,[tenantId,req.auth.user_id]);
    if(!active.rowCount){const e=new Error('No active lone-worker session. Clock in at a configured site first.');e.statusCode=409;throw e;}const s=active.rows[0];
    const check=await client.query(`INSERT INTO lone_worker_checkins(tenant_id,setting_id,user_id,site_id,latitude,longitude,accuracy,note) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[tenantId,s.id,req.auth.user_id,s.site_id,req.body.latitude??null,req.body.longitude??null,req.body.accuracy??null,String(req.body.note||'').trim()||null]);
    await client.query('UPDATE lone_worker_alerts SET resolved=TRUE,resolved_at=NOW() WHERE setting_id=$1 AND resolved=FALSE',[s.id]);return check;});res.status(201).json(result.rows[0]);}
  catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

async function runLoneWorkerSweep(){try{const due=await pool.query(`${loneWorkerStatusSql()} WHERE s.enabled=TRUE AND a.id IS NOT NULL AND COALESCE((SELECT MAX(c.checked_in_at) FROM lone_worker_checkins c WHERE c.setting_id=s.id AND c.user_id=s.user_id),a.clocked_in_at)+(s.interval_minutes+s.grace_minutes)*INTERVAL '1 minute'<NOW()`);
  for(const row of due.rows){const alert=await pool.query(`INSERT INTO lone_worker_alerts(tenant_id,setting_id,user_id,site_id,due_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id`,[row.tenant_id,row.id,row.user_id,row.site_id,new Date(new Date(row.safety_reference).getTime()+(Number(row.interval_minutes)+Number(row.grace_minutes))*60000)]);if(alert.rowCount)await pool.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,requires_acknowledgement)
    VALUES($1,$2,$3,'safety','critical','admins',TRUE)`,[row.tenant_id,'Lone-worker welfare check overdue',`${row.guard_email} at ${row.site_name} missed the required safety check-in.`]);}}
  catch(err){console.error('Lone-worker sweep failed:',err.message);}}
setInterval(runLoneWorkerSweep,60000);setTimeout(runLoneWorkerSweep,15000);

// ------------------------ PHASE 4.4: DISPATCH COMMAND CENTER ------------------------

app.get('/api/dispatch-jobs',requireAuth,async(req,res)=>{
  const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!['admin','guard'].includes(req.auth.role))return res.status(403).json({error:'Dispatch access denied'});
  try{const result=await withTenant(tenantId,client=>{let sql=`SELECT d.*,u.email AS guard_email,s.name AS site_name FROM dispatch_jobs d
    JOIN users u ON u.id=d.assigned_guard_id AND u.tenant_id=d.tenant_id LEFT JOIN sites s ON s.id=d.site_id AND s.tenant_id=d.tenant_id WHERE d.tenant_id=$1`;const params=[tenantId];
    if(req.auth.role==='guard'){params.push(req.auth.user_id);sql+=` AND d.assigned_guard_id=$2`;}if(req.query.status==='active')sql+=` AND d.status NOT IN ('completed','cancelled')`;sql+=' ORDER BY CASE d.priority WHEN \'critical\' THEN 1 WHEN \'high\' THEN 2 WHEN \'normal\' THEN 3 ELSE 4 END,d.created_at DESC LIMIT 300';return client.query(sql,params);});res.json(result.rows);}
  catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/dispatch-jobs',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id),guardId=Number(req.body.assigned_guard_id),siteId=req.body.site_id?Number(req.body.site_id):null;
  const title=String(req.body.title||'').trim(),priority=String(req.body.priority||'normal').toLowerCase();
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!title||!Number.isInteger(guardId))return res.status(400).json({error:'Title and assigned guard are required'});
  if(!['low','normal','high','critical'].includes(priority))return res.status(400).json({error:'Invalid priority'});
  try{const result=await withTenant(tenantId,async client=>{const guard=await client.query("SELECT id FROM users WHERE id=$1 AND tenant_id=$2 AND role='guard'",[guardId,tenantId]);if(!guard.rowCount){const e=new Error('Guard not found');e.statusCode=404;throw e;}
    if(siteId){const site=await client.query('SELECT id FROM sites WHERE id=$1 AND tenant_id=$2',[siteId,tenantId]);if(!site.rowCount){const e=new Error('Site not found');e.statusCode=404;throw e;}}
    const reference='DSP-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(2).toString('hex').toUpperCase();
    const inserted=await client.query(`INSERT INTO dispatch_jobs(tenant_id,reference_code,title,description,priority,site_id,assigned_guard_id,address,latitude,longitude,created_by_user_id)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[tenantId,reference,title,String(req.body.description||'').trim()||null,priority,siteId,guardId,String(req.body.address||'').trim()||null,req.body.latitude??null,req.body.longitude??null,req.auth.user_id]);
    await client.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id)
      VALUES($1,$2,$3,'dispatch',$4,'specific_guard',$5,'my_dispatches.html',TRUE,$6)`,[tenantId,'New dispatch: '+title,`Dispatch ${reference} has been assigned to you.`,priority,guardId,req.auth.user_id]);return inserted;});res.status(201).json(result.rows[0]);}
  catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.patch('/api/dispatch-jobs/:id/status',requireAuth,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id),status=String(req.body.status||'').toLowerCase();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!['admin','guard'].includes(req.auth.role))return res.status(403).json({error:'Dispatch access denied'});
  if(!['assigned','accepted','en_route','on_site','completed','cancelled'].includes(status))return res.status(400).json({error:'Invalid dispatch status'});
  try{const result=await withTenant(tenantId,async client=>{const current=await client.query('SELECT * FROM dispatch_jobs WHERE id=$1 AND tenant_id=$2',[req.params.id,tenantId]);if(!current.rowCount){const e=new Error('Dispatch not found');e.statusCode=404;throw e;}const job=current.rows[0];
    if(req.auth.role==='guard'&&Number(job.assigned_guard_id)!==Number(req.auth.user_id)){const e=new Error('This dispatch is not assigned to you');e.statusCode=403;throw e;}
    if(req.auth.role==='guard'){const allowed={assigned:['accepted'],accepted:['en_route'],en_route:['on_site'],on_site:['completed']}[job.status]||[];if(!allowed.includes(status)){const e=new Error(`Move the dispatch from ${job.status} to the next status first`);e.statusCode=409;throw e;}}
    const timeColumn={accepted:'accepted_at',en_route:'en_route_at',on_site:'on_site_at',completed:'completed_at'}[status];let sql='UPDATE dispatch_jobs SET status=$3,updated_at=NOW(),completion_note=CASE WHEN $3=\'completed\' THEN $4 ELSE completion_note END';if(timeColumn)sql+=`,${timeColumn}=COALESCE(${timeColumn},NOW())`;sql+=' WHERE id=$1 AND tenant_id=$2 RETURNING *';return client.query(sql,[req.params.id,tenantId,status,String(req.body.completion_note||'').trim()||null]);});res.json(result.rows[0]);}
  catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

// ------------------------ PHASE 4.6: TRAINING & COMPLIANCE ------------------------
app.get('/api/training/materials',requireAuth,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT m.*,s.name site_name,(SELECT COUNT(*)::int FROM training_assignments a WHERE a.material_id=m.id) assigned_count,(SELECT COUNT(*)::int FROM training_assignments a WHERE a.material_id=m.id AND a.status='completed') completed_count FROM training_materials m LEFT JOIN sites s ON s.id=m.site_id AND s.tenant_id=m.tenant_id WHERE m.tenant_id=$1 AND ($2='admin' OR m.active=TRUE) ORDER BY m.created_at DESC`,[t,req.auth.role]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/training/materials',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),title=String(req.body.title||'').trim(),content=String(req.body.content||'').trim(),type=String(req.body.material_type||'training');if(!t)return res.status(403).json({error:'Tenant access denied'});if(!title||!content||!['training','policy','post_order'].includes(type))return res.status(400).json({error:'Title, content and valid type are required'});let questions=req.body.questions||[];if(!Array.isArray(questions)||questions.some(q=>!q.question||!Array.isArray(q.options)||q.options.length<2||!Number.isInteger(Number(q.correct_index))||Number(q.correct_index)<0||Number(q.correct_index)>=q.options.length))return res.status(400).json({error:'Invalid quiz questions'});try{const r=await withTenant(t,c=>c.query(`INSERT INTO training_materials(tenant_id,title,material_type,version,content,site_id,questions,passing_score,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,[t,title,type,String(req.body.version||'1.0'),content,req.body.site_id?Number(req.body.site_id):null,JSON.stringify(questions),Number(req.body.passing_score??80),req.auth.user_id]));res.status(201).json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/training/materials/:id/assign',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),aud=String(req.body.audience||'all_guards'),uid=req.body.user_id?Number(req.body.user_id):null,sid=req.body.site_id?Number(req.body.site_id):null;if(!t)return res.status(403).json({error:'Tenant access denied'});try{const count=await withTenant(t,async c=>{const m=await c.query('SELECT * FROM training_materials WHERE id=$1 AND tenant_id=$2',[req.params.id,t]);if(!m.rowCount){const e=new Error('Material not found');e.statusCode=404;throw e;}let q="SELECT DISTINCT u.id FROM users u WHERE u.tenant_id=$1 AND u.role='guard'",p=[t];if(aud==='specific_guard'){p.push(uid);q+=' AND u.id=$2'}else if(aud==='site'){p.push(sid);q+=` AND EXISTS(SELECT 1 FROM guard_assignments g WHERE g.user_id=u.id AND g.site_id=$2 AND g.tenant_id=$1)`}const guards=await c.query(q,p);for(const g of guards.rows){await c.query(`INSERT INTO training_assignments(tenant_id,material_id,user_id,due_at,mandatory) VALUES($1,$2,$3,$4,$5) ON CONFLICT(material_id,user_id) DO UPDATE SET due_at=EXCLUDED.due_at,mandatory=EXCLUDED.mandatory`,[t,req.params.id,g.id,req.body.due_at||null,req.body.mandatory!==false]);await c.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id) VALUES($1,$2,$3,'compliance','normal','specific_guard',$4,'my_training.html',TRUE,$5)`,[t,'New '+m.rows[0].material_type+': '+m.rows[0].title,'A new required learning item has been assigned to you.',g.id,req.auth.user_id])}return guards.rowCount});res.json({assigned:count})}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.get('/api/training/assignments',requireAuth,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>{let q=`SELECT a.*,m.title,m.material_type,m.version,m.content,m.questions,m.passing_score,m.site_id,u.email guard_email,s.name site_name FROM training_assignments a JOIN training_materials m ON m.id=a.material_id JOIN users u ON u.id=a.user_id LEFT JOIN sites s ON s.id=m.site_id WHERE a.tenant_id=$1`,p=[t];if(req.auth.role==='guard'){p.push(req.auth.user_id);q+=' AND a.user_id=$2'}else if(req.auth.role!=='admin')throw Object.assign(new Error('Access denied'),{statusCode:403});q+=' ORDER BY CASE a.status WHEN \'assigned\' THEN 1 WHEN \'failed\' THEN 2 ELSE 3 END,a.due_at NULLS LAST';return c.query(q,p)});res.json(r.rows)}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.post('/api/training/assignments/:id/complete',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const t=communicationTenant(req,req.body.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,async c=>{const a=await c.query(`SELECT a.*,m.questions,m.passing_score FROM training_assignments a JOIN training_materials m ON m.id=a.material_id WHERE a.id=$1 AND a.tenant_id=$2 AND a.user_id=$3`,[req.params.id,t,req.auth.user_id]);if(!a.rowCount){const e=new Error('Assignment not found');e.statusCode=404;throw e}if(req.body.acknowledged!==true){const e=new Error('You must acknowledge that you read and understood the material');e.statusCode=400;throw e}const qs=a.rows[0].questions||[],answers=req.body.answers||[];let score=100;if(qs.length)score=Math.round(qs.reduce((n,q,i)=>n+(Number(answers[i])===Number(q.correct_index)?1:0),0)/qs.length*100);const passed=score>=Number(a.rows[0].passing_score);return c.query(`UPDATE training_assignments SET attempts=attempts+1,score=$4,status=$5,acknowledged_at=NOW(),completed_at=CASE WHEN $5='completed' THEN NOW() ELSE NULL END WHERE id=$1 AND tenant_id=$2 AND user_id=$3 RETURNING *`,[req.params.id,t,req.auth.user_id,score,passed?'completed':'failed'])});res.json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});

// ------------------------ PHASE 4.7: EQUIPMENT, KEYS & VEHICLES ------------------------
app.get('/api/assets',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT a.*,s.name site_name FROM managed_assets a LEFT JOIN sites s ON s.id=a.site_id AND s.tenant_id=a.tenant_id WHERE a.tenant_id=$1 ORDER BY a.name`,[t]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/assets',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),name=String(req.body.name||'').trim(),code=String(req.body.asset_code||'').trim(),type=String(req.body.asset_type||'equipment');if(!t)return res.status(403).json({error:'Tenant access denied'});if(!name||!code||!['equipment','key','vehicle','uniform','device','other'].includes(type))return res.status(400).json({error:'Name, asset code and valid type are required'});try{const r=await withTenant(t,c=>c.query(`INSERT INTO managed_assets(tenant_id,asset_type,name,asset_code,site_id,condition,notes) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[t,type,name,code,req.body.site_id?Number(req.body.site_id):null,String(req.body.condition||'good'),String(req.body.notes||'').trim()||null]));res.status(201).json(r.rows[0])}catch(e){res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'Asset code already exists':e.message})}});
app.get('/api/asset-custody',requireAuth,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>{let q=`SELECT c.*,a.name asset_name,a.asset_code,a.asset_type,a.condition,u.email guard_email,s.name site_name FROM asset_custody c JOIN managed_assets a ON a.id=c.asset_id JOIN users u ON u.id=c.user_id LEFT JOIN sites s ON s.id=a.site_id WHERE c.tenant_id=$1`,p=[t];if(req.auth.role==='guard'){p.push(req.auth.user_id);q+=' AND c.user_id=$2'}else if(req.auth.role!=='admin')throw Object.assign(new Error('Access denied'),{statusCode:403});if(req.query.active==='true')q+=` AND c.status<>'returned'`;q+=' ORDER BY c.issued_at DESC LIMIT 500';return c.query(q,p)});res.json(r.rows)}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.post('/api/asset-custody/issue',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),asset=Number(req.body.asset_id),user=Number(req.body.user_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,async c=>{const valid=await c.query(`SELECT a.name,a.status FROM managed_assets a JOIN users u ON u.id=$2 AND u.tenant_id=a.tenant_id AND u.role='guard' WHERE a.id=$1 AND a.tenant_id=$3`,[asset,user,t]);if(!valid.rowCount)throw Object.assign(new Error('Asset or guard not found'),{statusCode:404});if(valid.rows[0].status!=='available')throw Object.assign(new Error('Asset is not available'),{statusCode:409});const issued=await c.query(`INSERT INTO asset_custody(tenant_id,asset_id,user_id,issued_by_user_id,admin_note) VALUES($1,$2,$3,$4,$5) RETURNING *`,[t,asset,user,req.auth.user_id,String(req.body.admin_note||'').trim()||null]);await c.query("UPDATE managed_assets SET status='issued',updated_at=NOW() WHERE id=$1",[asset]);await c.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id) VALUES($1,$2,$3,'equipment','normal','specific_guard',$4,'my_equipment.html',TRUE,$5)`,[t,'Asset issued: '+valid.rows[0].name,'Review and acknowledge receipt of this asset.',user,req.auth.user_id]);return issued});res.status(201).json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.patch('/api/asset-custody/:id/guard-action',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const t=communicationTenant(req,req.body.tenant_id),action=String(req.body.action||''),map={acknowledge:'acknowledged',request_return:'return_requested',report_lost:'reported_lost',report_damaged:'reported_damaged'};if(!t)return res.status(403).json({error:'Tenant access denied'});if(!map[action])return res.status(400).json({error:'Invalid action'});try{const r=await withTenant(t,async c=>{const extra=action==='acknowledge'?',acknowledged_at=NOW()':action==='request_return'?',return_requested_at=NOW()':'';const u=await c.query(`UPDATE asset_custody SET status=$4,guard_note=$5${extra} WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND status<>'returned' RETURNING *`,[req.params.id,t,req.auth.user_id,map[action],String(req.body.note||'').trim()||null]);if(!u.rowCount)throw Object.assign(new Error('Active custody record not found'),{statusCode:404});if(action==='report_lost'||action==='report_damaged')await c.query('UPDATE managed_assets SET status=$2,updated_at=NOW() WHERE id=$1',[u.rows[0].asset_id,action==='report_lost'?'lost':'maintenance']);return u});res.json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.patch('/api/asset-custody/:id/confirm-return',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),condition=String(req.body.return_condition||'good');if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,async c=>{const u=await c.query(`UPDATE asset_custody SET status='returned',returned_at=NOW(),return_condition=$3,admin_note=COALESCE($4,admin_note) WHERE id=$1 AND tenant_id=$2 AND status<>'returned' RETURNING *`,[req.params.id,t,condition,String(req.body.admin_note||'').trim()||null]);if(!u.rowCount)throw Object.assign(new Error('Active custody record not found'),{statusCode:404});await c.query('UPDATE managed_assets SET status=$2,condition=$3,updated_at=NOW() WHERE id=$1',[u.rows[0].asset_id,condition==='damaged'?'maintenance':'available',condition]);return u});res.json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});

// ------------------------ PHASE 4.8: QUALITY INSPECTIONS & CAPA ------------------------
app.get('/api/inspection-templates',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT i.*,s.name site_name FROM inspection_templates i LEFT JOIN sites s ON s.id=i.site_id AND s.tenant_id=i.tenant_id WHERE i.tenant_id=$1 ORDER BY i.created_at DESC`,[t]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/inspection-templates',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),title=String(req.body.title||'').trim(),questions=req.body.questions||[];if(!t)return res.status(403).json({error:'Tenant access denied'});if(!title||!Array.isArray(questions)||!questions.length||questions.some(q=>!String(q.text||'').trim()))return res.status(400).json({error:'Title and at least one valid question are required'});try{const r=await withTenant(t,c=>c.query(`INSERT INTO inspection_templates(tenant_id,title,description,site_id,passing_score,questions,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[t,title,String(req.body.description||'').trim()||null,req.body.site_id?Number(req.body.site_id):null,Number(req.body.passing_score??80),JSON.stringify(questions.map(q=>({text:String(q.text).trim(),critical:Boolean(q.critical),guidance:String(q.guidance||'').trim()}))),req.auth.user_id]));res.status(201).json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/inspection-runs',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),template=Number(req.body.template_id),site=Number(req.body.site_id),user=Number(req.body.assigned_user_id);if(!t)return res.status(403).json({error:'Tenant access denied'});if(!template||!site||!user||!req.body.scheduled_for)return res.status(400).json({error:'Template, site, guard and schedule are required'});try{const r=await withTenant(t,async c=>{const valid=await c.query(`SELECT i.title FROM inspection_templates i JOIN sites s ON s.id=$2 AND s.tenant_id=i.tenant_id JOIN users u ON u.id=$3 AND u.tenant_id=i.tenant_id AND u.role='guard' WHERE i.id=$1 AND i.tenant_id=$4 AND i.active=TRUE`,[template,site,user,t]);if(!valid.rowCount)throw Object.assign(new Error('Template, site or guard not found'),{statusCode:404});const run=await c.query(`INSERT INTO inspection_runs(tenant_id,template_id,site_id,assigned_user_id,scheduled_for,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[t,template,site,user,req.body.scheduled_for,req.auth.user_id]);await c.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id) VALUES($1,$2,$3,'inspection','normal','specific_guard',$4,'my_inspections.html',TRUE,$5)`,[t,'Inspection assigned: '+valid.rows[0].title,'A site quality inspection has been assigned to you.',user,req.auth.user_id]);return run});res.status(201).json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.get('/api/inspection-runs',requireAuth,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>{let q=`SELECT r.*,i.title template_title,i.description template_description,i.questions,i.passing_score,s.name site_name,u.email guard_email FROM inspection_runs r JOIN inspection_templates i ON i.id=r.template_id JOIN sites s ON s.id=r.site_id JOIN users u ON u.id=r.assigned_user_id WHERE r.tenant_id=$1`,p=[t];if(req.auth.role==='guard'){p.push(req.auth.user_id);q+=' AND r.assigned_user_id=$2'}else if(req.auth.role!=='admin')throw Object.assign(new Error('Access denied'),{statusCode:403});q+=' ORDER BY CASE r.status WHEN \'scheduled\' THEN 1 WHEN \'in_progress\' THEN 2 ELSE 3 END,r.scheduled_for DESC LIMIT 500';return c.query(q,p)});res.json(r.rows)}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.post('/api/inspection-runs/:id/submit',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const t=communicationTenant(req,req.body.tenant_id),responses=req.body.responses||[];if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,async c=>{const found=await c.query(`SELECT r.*,i.questions,i.passing_score,i.title FROM inspection_runs r JOIN inspection_templates i ON i.id=r.template_id WHERE r.id=$1 AND r.tenant_id=$2 AND r.assigned_user_id=$3 AND r.status NOT IN ('submitted','cancelled')`,[req.params.id,t,req.auth.user_id]);if(!found.rowCount)throw Object.assign(new Error('Active inspection not found'),{statusCode:404});const questions=found.rows[0].questions||[];if(!Array.isArray(responses)||responses.length!==questions.length||responses.some(x=>!['pass','fail','na'].includes(x.answer)))throw Object.assign(new Error('Answer every inspection question'),{statusCode:400});const applicable=responses.filter(x=>x.answer!=='na'),passed=applicable.filter(x=>x.answer==='pass').length,score=applicable.length?Math.round(passed/applicable.length*100):100;const submitted=await c.query(`UPDATE inspection_runs SET status='submitted',responses=$4,score=$5,overall_note=$6,started_at=COALESCE(started_at,NOW()),submitted_at=NOW() WHERE id=$1 AND tenant_id=$2 AND assigned_user_id=$3 RETURNING *`,[req.params.id,t,req.auth.user_id,JSON.stringify(responses),score,String(req.body.overall_note||'').trim()||null]);for(let i=0;i<responses.length;i++){if(responses[i].answer==='fail'){const q=questions[i];await c.query(`INSERT INTO corrective_actions(tenant_id,inspection_run_id,question_index,title,description) VALUES($1,$2,$3,$4,$5)`,[t,req.params.id,i,'Failed inspection item: '+q.text,String(responses[i].note||q.guidance||'').trim()||null])}}if(score<Number(found.rows[0].passing_score)||responses.some((x,i)=>x.answer==='fail'&&questions[i].critical))await c.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,action_url,requires_acknowledgement) VALUES($1,$2,$3,'inspection','high','admins','quality_inspections.html',TRUE)`,[t,'Inspection failed: '+found.rows[0].title,`Inspection score ${score}%. Corrective action is required.`]);return submitted});res.json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.get('/api/corrective-actions',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT a.*,i.score,i.template_id,t.title template_title,s.name site_name,u.email assigned_email FROM corrective_actions a JOIN inspection_runs i ON i.id=a.inspection_run_id JOIN inspection_templates t ON t.id=i.template_id JOIN sites s ON s.id=i.site_id LEFT JOIN users u ON u.id=a.assigned_user_id WHERE a.tenant_id=$1 ORDER BY CASE a.status WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 ELSE 3 END,a.due_at NULLS LAST`,[t]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.patch('/api/corrective-actions/:id',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),status=String(req.body.status||'open');if(!t)return res.status(403).json({error:'Tenant access denied'});if(!['open','in_progress','resolved','cancelled'].includes(status))return res.status(400).json({error:'Invalid status'});try{const r=await withTenant(t,c=>c.query(`UPDATE corrective_actions SET assigned_user_id=$3,due_at=$4,status=$5,resolution_note=$6,resolved_at=CASE WHEN $5='resolved' THEN NOW() ELSE NULL END WHERE id=$1 AND tenant_id=$2 RETURNING *`,[req.params.id,t,req.body.assigned_user_id?Number(req.body.assigned_user_id):null,req.body.due_at||null,status,String(req.body.resolution_note||'').trim()||null]));if(!r.rowCount)return res.status(404).json({error:'Corrective action not found'});res.json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});

// ------------------------ PHASE 4.9: STAFF ACCESS CONTROL ------------------------
app.get('/api/staff-users',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT id,email,job_title,permissions,account_active,created_at FROM users WHERE tenant_id=$1 AND role='staff' ORDER BY email`,[t]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/staff-users',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||''),permissions=req.body.permissions||[],valid=['scheduling','attendance','patrols','incidents','dispatch','safety','communications','training','assets','quality','clients','finance','analytics'];if(!t)return res.status(403).json({error:'Tenant access denied'});if(!email||password.length<8||!Array.isArray(permissions)||permissions.some(x=>!valid.includes(x)))return res.status(400).json({error:'Valid email, password of at least 8 characters and permissions are required'});try{const hash=await bcrypt.hash(password,10),r=await withTenant(t,c=>c.query(`INSERT INTO users(tenant_id,email,password_hash,role,job_title,permissions,account_active) VALUES($1,$2,$3,'staff',$4,$5,TRUE) RETURNING id,email,job_title,permissions,account_active`,[t,email,hash,String(req.body.job_title||'').trim()||null,JSON.stringify(permissions)]));res.status(201).json(r.rows[0])}catch(e){res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'Email already exists':e.message})}});
app.patch('/api/staff-users/:id',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),permissions=req.body.permissions||[],valid=['scheduling','attendance','patrols','incidents','dispatch','safety','communications','training','assets','quality','clients','finance','analytics'];if(!t)return res.status(403).json({error:'Tenant access denied'});if(!Array.isArray(permissions)||permissions.some(x=>!valid.includes(x)))return res.status(400).json({error:'Invalid permissions'});try{const r=await withTenant(t,c=>c.query(`UPDATE users SET job_title=$3,permissions=$4,account_active=$5 WHERE id=$1 AND tenant_id=$2 AND role='staff' RETURNING id,email,job_title,permissions,account_active`,[req.params.id,t,String(req.body.job_title||'').trim()||null,JSON.stringify(permissions),req.body.account_active!==false]));if(!r.rowCount)return res.status(404).json({error:'Staff user not found'});res.json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/staff-session',requireAuth,async(req,res)=>{if(req.auth.role!=='staff')return res.status(403).json({error:'Staff access required'});try{const r=await pool.query(`SELECT id,email,job_title,permissions,account_active FROM users WHERE id=$1 AND tenant_id=$2 AND role='staff'`,[req.auth.user_id,req.auth.tenant_id]);if(!r.rowCount||!r.rows[0].account_active)return res.status(403).json({error:'Staff account disabled'});res.json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});

// ------------------------ PHASE 4.10: API & WEBHOOK INTEGRATIONS ------------------------
function hashApiKey(key){return crypto.createHash('sha256').update(key).digest('hex')}
async function requireIntegrationKey(req,res,next){const raw=String(req.headers['x-patrolsync-api-key']||'');if(!raw)return res.status(401).json({error:'API key required'});try{const r=await pool.query(`SELECT * FROM integration_api_keys WHERE key_hash=$1 AND active=TRUE`,[hashApiKey(raw)]);if(!r.rowCount)return res.status(401).json({error:'Invalid API key'});req.integration=r.rows[0];await pool.query('UPDATE integration_api_keys SET last_used_at=NOW() WHERE id=$1',[r.rows[0].id]);next()}catch(e){res.status(500).json({error:'API authentication failed'})}}
async function queueWebhookEvent(tenantId,eventType,payload){try{await pool.query(`INSERT INTO webhook_deliveries(tenant_id,webhook_id,event_type,payload) SELECT tenant_id,id,$2,$3 FROM webhook_endpoints WHERE tenant_id=$1 AND active=TRUE AND (event_filter='*' OR $2 LIKE event_filter||'%')`,[tenantId,eventType,JSON.stringify({event:eventType,tenant_id:tenantId,occurred_at:new Date().toISOString(),data:payload})])}catch(e){console.error('Webhook queue failed:',e.message)}}
app.get('/api/integrations',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const[k,w,d]=await Promise.all([pool.query(`SELECT id,name,key_prefix,active,last_used_at,created_at FROM integration_api_keys WHERE tenant_id=$1 ORDER BY created_at DESC`,[t]),pool.query(`SELECT id,name,url,event_filter,active,created_at FROM webhook_endpoints WHERE tenant_id=$1 ORDER BY created_at DESC`,[t]),pool.query(`SELECT d.*,w.name webhook_name FROM webhook_deliveries d JOIN webhook_endpoints w ON w.id=d.webhook_id WHERE d.tenant_id=$1 ORDER BY d.created_at DESC LIMIT 100`,[t])]);res.json({api_keys:k.rows,webhooks:w.rows,deliveries:d.rows})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/integrations/api-keys',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),name=String(req.body.name||'').trim();if(!t)return res.status(403).json({error:'Tenant access denied'});if(!name)return res.status(400).json({error:'Key name required'});const raw='ps_'+crypto.randomBytes(32).toString('hex');try{const r=await pool.query(`INSERT INTO integration_api_keys(tenant_id,name,key_prefix,key_hash,created_by_user_id) VALUES($1,$2,$3,$4,$5) RETURNING id,name,key_prefix,created_at`,[t,name,raw.slice(0,11),hashApiKey(raw),req.auth.user_id]);res.status(201).json({...r.rows[0],api_key:raw,warning:'Copy this key now. It will not be shown again.'})}catch(e){res.status(500).json({error:e.message})}});
app.patch('/api/integrations/api-keys/:id/revoke',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id);const r=await pool.query(`UPDATE integration_api_keys SET active=FALSE WHERE id=$1 AND tenant_id=$2 RETURNING id`,[req.params.id,t]);if(!r.rowCount)return res.status(404).json({error:'Key not found'});res.json({revoked:true})});
app.post('/api/integrations/webhooks',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),name=String(req.body.name||'').trim(),url=String(req.body.url||'').trim();if(!t)return res.status(403).json({error:'Tenant access denied'});let parsed;try{parsed=new URL(url)}catch(e){}if(!name||!parsed||parsed.protocol!=='https:'||['localhost','127.0.0.1','::1'].includes(parsed.hostname))return res.status(400).json({error:'Name and public HTTPS URL required'});const secret=crypto.randomBytes(24).toString('hex');try{const r=await pool.query(`INSERT INTO webhook_endpoints(tenant_id,name,url,secret,event_filter) VALUES($1,$2,$3,$4,$5) RETURNING id,name,url,event_filter,active`,[t,name,url,secret,String(req.body.event_filter||'*')]);res.status(201).json({...r.rows[0],signing_secret:secret,warning:'Copy the signing secret now.'})}catch(e){res.status(500).json({error:e.message})}});
app.patch('/api/integrations/webhooks/:id/toggle',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id);const r=await pool.query(`UPDATE webhook_endpoints SET active=$3 WHERE id=$1 AND tenant_id=$2 RETURNING id,active`,[req.params.id,t,Boolean(req.body.active)]);if(!r.rowCount)return res.status(404).json({error:'Webhook not found'});res.json(r.rows[0])});
app.post('/api/integrations/webhooks/:id/test',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});const payload={event:'test.integration',tenant_id:t,occurred_at:new Date().toISOString(),data:{message:'PatrolSync webhook test'}};const r=await pool.query(`INSERT INTO webhook_deliveries(tenant_id,webhook_id,event_type,payload) SELECT tenant_id,id,'test.integration',$3 FROM webhook_endpoints WHERE id=$1 AND tenant_id=$2 RETURNING id`,[req.params.id,t,JSON.stringify(payload)]);if(!r.rowCount)return res.status(404).json({error:'Webhook not found'});res.json({queued:true})});
app.get('/api/public/v1/summary',requireIntegrationKey,async(req,res)=>{const t=req.integration.tenant_id;try{const[s,g,c]=await Promise.all([pool.query('SELECT COUNT(*)::int count FROM sites WHERE tenant_id=$1',[t]),pool.query("SELECT COUNT(*)::int count FROM users WHERE tenant_id=$1 AND role='guard'",[t]),pool.query("SELECT COUNT(*)::int count FROM attendance_sessions WHERE tenant_id=$1 AND clocked_out_at IS NULL",[t])]);res.json({tenant_id:t,sites:s.rows[0].count,guards:g.rows[0].count,currently_clocked_in:c.rows[0].count})}catch(e){res.status(500).json({error:e.message})}});
async function processWebhookQueue(){try{const rows=await pool.query(`SELECT d.*,w.url,w.secret FROM webhook_deliveries d JOIN webhook_endpoints w ON w.id=d.webhook_id WHERE d.status IN ('queued','failed') AND d.next_attempt_at<=NOW() AND d.attempts<5 AND w.active=TRUE ORDER BY d.created_at LIMIT 20`);for(const d of rows.rows){const body=JSON.stringify(d.payload),signature=crypto.createHmac('sha256',d.secret).update(body).digest('hex');try{const response=await fetch(d.url,{method:'POST',headers:{'Content-Type':'application/json','X-PatrolSync-Signature':'sha256='+signature,'X-PatrolSync-Event':d.event_type},body,signal:AbortSignal.timeout(10000)});if(!response.ok)throw Object.assign(new Error('HTTP '+response.status),{status:response.status});await pool.query(`UPDATE webhook_deliveries SET status='delivered',attempts=attempts+1,response_status=$2,delivered_at=NOW(),last_error=NULL WHERE id=$1`,[d.id,response.status])}catch(e){await pool.query(`UPDATE webhook_deliveries SET status='failed',attempts=attempts+1,response_status=$2,last_error=$3,next_attempt_at=NOW()+(POWER(2,attempts)*INTERVAL '1 minute') WHERE id=$1`,[d.id,e.status||null,String(e.message).slice(0,500)])}}}catch(e){console.error('Webhook worker failed:',e.message)}}setInterval(processWebhookQueue,30000);setTimeout(processWebhookQueue,10000);

// ------------------------ PHASE 5.1: AUTOMATED INTEGRITY & SMOKE TESTS ------------------------
app.get('/api/diagnostics/database-paths',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});let tenantClient;try{const systemRole=(await systemPool.query(`SELECT current_user role_name,r.rolsuper is_superuser,r.rolbypassrls bypasses_rls FROM pg_roles r WHERE r.rolname=current_user`)).rows[0];tenantClient=await tenantPool.connect();await tenantClient.query(`SELECT set_config('app.current_tenant',$1,false)`,[String(t)]);const tenantRole=(await tenantClient.query(`SELECT current_user role_name,r.rolsuper is_superuser,r.rolbypassrls bypasses_rls,current_setting('app.current_tenant',true) tenant_context FROM pg_roles r WHERE r.rolname=current_user`)).rows[0];const crossTenant=(await tenantClient.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id<>$1`,[t])).rows[0].count;res.json({status:DATABASE_PATHS_SEPARATED&&systemRole.role_name!==tenantRole.role_name&&Number(crossTenant)===0?'ready_for_enforcement':DATABASE_PATHS_SEPARATED?'separated_but_not_isolated':'compatibility_mode',generated_at:new Date(),tenant_id:t,paths_separated:DATABASE_PATHS_SEPARATED,system_role:systemRole,tenant_role:tenantRole,tenant_probe:{cross_tenant_users_visible:Number(crossTenant),passed:Number(crossTenant)===0},configuration:{system_database_url_set:Boolean(process.env.SYSTEM_DATABASE_URL),tenant_database_url_set:Boolean(process.env.TENANT_DATABASE_URL),rls_activation_performed:false},next_action:DATABASE_PATHS_SEPARATED?'Verify the tenant role has policies and cannot bypass RLS before activation.':'Create a restricted PostgreSQL login and set TENANT_DATABASE_URL; keep SYSTEM_DATABASE_URL on the current trusted login.',request_id:req.requestId})}catch(e){res.status(500).json({error:e.message,request_id:req.requestId})}finally{if(tenantClient){let resetError;try{await tenantClient.query('RESET app.current_tenant')}catch(e){resetError=e}tenantClient.release(resetError)}}});

app.get('/api/diagnostics/rls-readiness',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const roleResult=await pool.query(`SELECT current_user role_name,r.rolsuper is_superuser,r.rolbypassrls bypasses_rls FROM pg_roles r WHERE r.rolname=current_user`);const tablesResult=await pool.query(`SELECT c.relname table_name,c.relrowsecurity rls_enabled,c.relforcerowsecurity rls_forced,pg_get_userbyid(c.relowner)=current_user app_role_owns_table,COUNT(p.policyname)::int policy_count,COALESCE(BOOL_OR(p.cmd='ALL' OR p.cmd='SELECT'),FALSE) protects_select,COALESCE(BOOL_OR(p.cmd='ALL' OR p.cmd='INSERT'),FALSE) protects_insert,COALESCE(BOOL_OR(p.cmd='ALL' OR p.cmd='UPDATE'),FALSE) protects_update,COALESCE(BOOL_OR(p.cmd='ALL' OR p.cmd='DELETE'),FALSE) protects_delete FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped LEFT JOIN pg_policies p ON p.schemaname=n.nspname AND p.tablename=c.relname WHERE n.nspname='public' AND c.relkind IN('r','p') GROUP BY c.oid,c.relname,c.relrowsecurity,c.relforcerowsecurity,c.relowner ORDER BY c.relname`);const role=roleResult.rows[0]||{},tables=tablesResult.rows.map(x=>({...x,ready_for_enforcement:Boolean(x.rls_enabled&&x.rls_forced&&x.policy_count>0&&x.protects_select&&x.protects_insert&&x.protects_update&&x.protects_delete)}));const summary={tenant_tables:tables.length,policies_missing:tables.filter(x=>x.policy_count===0).length,rls_disabled:tables.filter(x=>!x.rls_enabled).length,rls_not_forced:tables.filter(x=>!x.rls_forced).length,fully_enforced:tables.filter(x=>x.ready_for_enforcement).length};const blockers=[];if(role.is_superuser)blockers.push('The application database role is a PostgreSQL superuser and therefore bypasses RLS.');if(role.bypasses_rls)blockers.push('The application database role has BYPASSRLS.');if(tables.some(x=>x.app_role_owns_table&&!x.rls_forced))blockers.push('The application role owns tenant tables; table owners bypass RLS until FORCE ROW LEVEL SECURITY is enabled.');if(summary.policies_missing)blockers.push(`${summary.policies_missing} tenant table(s) do not yet have an RLS policy.`);blockers.push('Authentication lookups and background workers must use a separately controlled system path before forced RLS is activated.');res.json({status:summary.fully_enforced===summary.tenant_tables&&summary.tenant_tables>0&&!role.is_superuser&&!role.bypasses_rls?'enforced':'preparation_required',generated_at:new Date(),tenant_id:t,application_role:role,summary,blockers,tables,activation_performed:false,request_id:req.requestId})}catch(e){res.status(500).json({error:e.message,request_id:req.requestId})}});

app.get('/api/diagnostics/integrity',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});const checks=[],add=(key,label,severity,count,message,details=[])=>checks.push({key,label,status:count===0?'pass':severity,count,message,details});try{const started=Date.now(),coreTables=['tenants','users','sites','guard_assignments','shifts','attendance_sessions','patrol_logs','patrol_runs','incidents','audit_logs'];const tableRows=await pool.query(`SELECT x name,to_regclass('public.'||x) present FROM unnest($1::text[]) x`,[coreTables]);const missing=tableRows.rows.filter(x=>!x.present).map(x=>x.name);add('schema','Core database tables',missing.length?'fail':'warn',missing.length,missing.length?'Required tables are missing':'All required core tables are available',missing);
const results=await withTenant(t,async c=>Promise.all([
c.query(`SELECT LOWER(email) email,role,COUNT(*)::int count,ARRAY_AGG(id ORDER BY id) ids FROM users WHERE tenant_id=$1 AND COALESCE(account_active,TRUE)=TRUE GROUP BY LOWER(email),role HAVING COUNT(*)>1`,[t]),
c.query(`SELECT ga.id,ga.user_id,u.email,ga.site_id FROM guard_assignments ga JOIN users u ON u.id=ga.user_id AND u.tenant_id=ga.tenant_id WHERE ga.tenant_id=$1 AND COALESCE(u.account_active,TRUE)=FALSE`,[t]),
c.query(`SELECT ga.id,ga.user_id,ga.site_id FROM guard_assignments ga LEFT JOIN users u ON u.id=ga.user_id AND u.tenant_id=ga.tenant_id LEFT JOIN sites s ON s.id=ga.site_id AND s.tenant_id=ga.tenant_id WHERE ga.tenant_id=$1 AND (u.id IS NULL OR s.id IS NULL)`,[t]),
c.query(`SELECT user_id,COUNT(*)::int count,ARRAY_AGG(id ORDER BY id) session_ids FROM attendance_sessions WHERE tenant_id=$1 AND clocked_out_at IS NULL GROUP BY user_id HAVING COUNT(*)>1`,[t]),
c.query(`SELECT a.id,a.user_id,u.email FROM attendance_sessions a JOIN users u ON u.id=a.user_id AND u.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.clocked_out_at IS NULL AND COALESCE(u.account_active,TRUE)=FALSE`,[t]),
c.query(`SELECT s.id,s.user_id,s.site_id FROM shifts s LEFT JOIN users u ON u.id=s.user_id AND u.tenant_id=s.tenant_id LEFT JOIN sites si ON si.id=s.site_id AND si.tenant_id=s.tenant_id WHERE s.tenant_id=$1 AND (u.id IS NULL OR si.id IS NULL) LIMIT 100`,[t]),
c.query(`SELECT id,event_type,attempts,last_error,created_at FROM webhook_deliveries WHERE tenant_id=$1 AND status='failed' AND attempts>=5 ORDER BY created_at DESC LIMIT 50`,[t]),
c.query(`SELECT id,event_type,attempt_count,last_error,created_at FROM email_deliveries WHERE tenant_id=$1 AND status='failed' AND attempt_count>=5 ORDER BY created_at DESC LIMIT 50`,[t]),
c.query(`SELECT COUNT(*)::int count FROM password_reset_tokens WHERE tenant_id=$1 AND used_at IS NULL AND expires_at<=NOW()`,[t]),
c.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id<>$1`,[t])
]));
const[duplicates,inactiveAssignments,brokenAssignments,multipleAttendance,inactiveAttendance,brokenShifts,deadWebhooks,deadEmails,expiredTokens,crossTenant]=results;
add('duplicate_users','Duplicate active guard/staff identities','fail',duplicates.rowCount,'Each active email and role should identify one account',duplicates.rows);add('inactive_assignments','Assignments owned by archived guards','warn',inactiveAssignments.rowCount,'Archived guards should not retain active site assignments',inactiveAssignments.rows);add('broken_assignments','Broken site assignments','fail',brokenAssignments.rowCount,'Every assignment must reference a valid guard and site in this company',brokenAssignments.rows);add('attendance_overlap','Multiple open clock-ins','fail',multipleAttendance.rowCount,'A guard should have at most one open attendance session',multipleAttendance.rows);add('inactive_attendance','Archived guards still clocked in','fail',inactiveAttendance.rowCount,'Archived accounts cannot remain clocked in',inactiveAttendance.rows);add('broken_shifts','Shifts with missing guard or site','fail',brokenShifts.rowCount,'Every shift must reference a valid guard and site',brokenShifts.rows);add('webhook_dead_letters','Webhooks exhausted retries','warn',deadWebhooks.rowCount,'Failed integrations require review',deadWebhooks.rows);add('email_dead_letters','Emails exhausted retries','warn',deadEmails.rowCount,'Failed email deliveries require review',deadEmails.rows);add('expired_reset_tokens','Expired unused reset tokens','warn',Number(expiredTokens.rows[0].count),'Expired tokens are harmless and will be cleaned automatically');add('tenant_isolation','Database tenant isolation probe','fail',Number(crossTenant.rows[0].count),'A tenant-scoped database session must not see users from other companies');
const summary={pass:checks.filter(x=>x.status==='pass').length,warn:checks.filter(x=>x.status==='warn').length,fail:checks.filter(x=>x.status==='fail').length};res.json({status:summary.fail?'action_required':summary.warn?'warning':'healthy',generated_at:new Date(),duration_ms:Date.now()-started,tenant_id:t,summary,checks,request_id:req.requestId})}catch(e){res.status(500).json({error:e.message,request_id:req.requestId})}});

// ------------------------ PHASE 4.12: SECURITY, BACKUP & RECOVERY ------------------------
app.post('/api/auth/guard-login-v2',fixedWindowRateLimit('guard-login-scoped-v2',20),async(req,res)=>{const tenantId=Number(req.body.company_id||req.body.tenant_id),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(!Number.isInteger(tenantId)||tenantId<1||!email||!password)return res.status(400).json({error:'Company ID, email and password are required'});try{const result=await withTenant(tenantId,c=>c.query(`SELECT u.id,u.tenant_id,u.email,u.role,u.password_hash,u.account_active,(SELECT COUNT(*)::int FROM guard_assignments ga WHERE ga.tenant_id=u.tenant_id AND ga.user_id=u.id) assignment_count FROM users u WHERE u.tenant_id=$1 AND LOWER(u.email)=$2 AND u.role='guard' AND COALESCE(u.account_active,TRUE)=TRUE ORDER BY assignment_count DESC,u.id DESC`,[tenantId,email]));let user=null;for(const candidate of result.rows){if(candidate.password_hash&&await bcrypt.compare(password,candidate.password_hash)){user=candidate;break}}if(!user)return res.status(401).json({error:'Invalid Company ID, guard email or password'});const token=jwt.sign({user_id:user.id,tenant_id:user.tenant_id,role:'guard',email:user.email},JWT_SECRET,{expiresIn:'12h'});res.json({token,tenant_id:user.tenant_id,user:{id:user.id,email:user.email,role:'guard'},assignment_count:user.assignment_count})}catch(e){console.error('Guard login v2 failed:',e.message);res.status(500).json({error:'Guard login failed'})}});

app.post('/api/auth/guard-login',fixedWindowRateLimit('guard-login-scoped',20),async(req,res)=>{const tenantId=Number(req.body.company_id||req.body.tenant_id),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(!Number.isInteger(tenantId)||tenantId<1||!email||!password)return res.status(400).json({error:'Company ID, email and password are required'});try{const result=await withTenant(tenantId,c=>c.query(`SELECT id,tenant_id,email,role,password_hash,account_active FROM users WHERE tenant_id=$1 AND LOWER(email)=$2 AND role='guard' LIMIT 1`,[tenantId,email]));const user=result.rows[0];if(!user||user.account_active===false||!user.password_hash||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:'Invalid Company ID, guard email or password'});const token=jwt.sign({user_id:user.id,tenant_id:user.tenant_id,role:'guard',email:user.email},JWT_SECRET,{expiresIn:'12h'});res.json({token,tenant_id:user.tenant_id,user:{id:user.id,email:user.email,role:'guard'}})}catch(e){res.status(500).json({error:'Guard login failed'})}});

app.post('/api/auth/scoped-forgot-password',fixedWindowRateLimit('password-reset-scoped',5),async(req,res)=>{const tenantId=Number(req.body.company_id||req.body.tenant_id),email=String(req.body.email||'').trim().toLowerCase(),accountType=String(req.body.account_type||'admin').toLowerCase(),accepted={message:'If that company account exists, a reset link has been sent.'};if(!Number.isInteger(tenantId)||tenantId<1||!email||!['admin','guard'].includes(accountType))return res.json(accepted);try{const roles=accountType==='guard'?['guard']:['admin','staff'],found=await withTenant(tenantId,c=>c.query(`SELECT id,tenant_id,email,role FROM users WHERE tenant_id=$1 AND LOWER(email)=$2 AND role=ANY($3::text[]) AND COALESCE(account_active,TRUE)=TRUE ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'staff' THEN 2 ELSE 3 END LIMIT 1`,[tenantId,email,roles]));if(!found.rowCount)return res.json(accepted);const user=found.rows[0],raw=crypto.randomBytes(32).toString('hex'),hash=crypto.createHash('sha256').update(raw).digest('hex');await pool.query(`UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND tenant_id=$2 AND used_at IS NULL`,[user.id,user.tenant_id]);await pool.query(`INSERT INTO password_reset_tokens(tenant_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL '30 minutes')`,[user.tenant_id,user.id,hash]);const link=`${FRONTEND_URL||'https://patrolsync.co'}/reset_password.html?token=${encodeURIComponent(raw)}`;await sendProviderEmail({to:user.email,subject:`Reset your PatrolSync ${accountType} password`,html:emailHtml(`Reset your ${accountType} password`,'<p>This secure link expires in 30 minutes. If you did not request it, you can ignore this email.</p>','Reset Password',link)});await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details) VALUES($1,'password_reset_requested','info','Password reset requested',$2::jsonb)`,[tenantId,JSON.stringify({user_id:user.id,role:user.role,account_type:accountType})]);res.json(accepted)}catch(e){console.error('Scoped password reset failed:',e.message);res.json(accepted)}});

app.post('/api/auth/forgot-password-by-role',fixedWindowRateLimit('password-reset-role',5),async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase(),accountType=String(req.body.account_type||'admin').toLowerCase(),accepted={message:'If that account exists, a reset link has been sent.'};if(!email||!['admin','guard'].includes(accountType))return res.json(accepted);try{let user=null;const tenants=await pool.query('SELECT id FROM tenants');for(const tenant of tenants.rows){const roles=accountType==='guard'?['guard']:['admin','staff'];const found=await withTenant(tenant.id,c=>c.query(`SELECT id,tenant_id,email,role FROM users WHERE tenant_id=$1 AND LOWER(email)=$2 AND role=ANY($3::text[]) AND COALESCE(account_active,TRUE)=TRUE ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'staff' THEN 2 ELSE 3 END LIMIT 1`,[tenant.id,email,roles]));if(found.rowCount){user=found.rows[0];break}}if(!user)return res.json(accepted);const raw=crypto.randomBytes(32).toString('hex'),hash=crypto.createHash('sha256').update(raw).digest('hex');await pool.query(`UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND tenant_id=$2 AND used_at IS NULL`,[user.id,user.tenant_id]);await pool.query(`INSERT INTO password_reset_tokens(tenant_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL '30 minutes')`,[user.tenant_id,user.id,hash]);const link=`${FRONTEND_URL||'https://patrolsync.co'}/reset_password.html?token=${encodeURIComponent(raw)}`;await sendProviderEmail({to:user.email,subject:`Reset your PatrolSync ${accountType} password`,html:emailHtml(`Reset your ${accountType} password`,'<p>This secure link expires in 30 minutes. If you did not request it, you can ignore this email.</p>','Reset Password',link)});await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details) VALUES($1,'password_reset_requested','info','Password reset requested',$2::jsonb)`,[user.tenant_id,JSON.stringify({user_id:user.id,role:user.role,account_type:accountType})]);res.json(accepted)}catch(e){console.error('Role-specific password reset failed:',e.message);res.json(accepted)}});

app.post('/api/auth/forgot-password',fixedWindowRateLimit('password-reset',5),async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase();const accepted={message:'If that email exists, a reset link has been sent.'};if(!email)return res.json(accepted);try{const found=await pool.query(`SELECT id,tenant_id,email FROM users WHERE LOWER(email)=$1 AND COALESCE(account_active,TRUE)=TRUE ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'staff' THEN 2 ELSE 3 END LIMIT 1`,[email]);if(!found.rowCount)return res.json(accepted);const user=found.rows[0],raw=crypto.randomBytes(32).toString('hex'),hash=crypto.createHash('sha256').update(raw).digest('hex');await pool.query(`UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND tenant_id=$2 AND used_at IS NULL`,[user.id,user.tenant_id]);await pool.query(`INSERT INTO password_reset_tokens(tenant_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL '30 minutes')`,[user.tenant_id,user.id,hash]);const link=`${FRONTEND_URL||'https://patrolsync.co'}/reset_password.html?token=${encodeURIComponent(raw)}`;await sendProviderEmail({to:user.email,subject:'Reset your PatrolSync password',html:emailHtml('Reset your password','<p>This secure link expires in 30 minutes. If you did not request it, you can ignore this email.</p>','Reset Password',link)});await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details) VALUES($1,'password_reset_requested','info','Password reset requested',$2)`,[user.tenant_id,JSON.stringify({user_id:user.id})]);res.json(accepted)}catch(e){console.error('Password reset request failed:',e.message);res.json(accepted)}});

app.post('/api/auth/reset-password',fixedWindowRateLimit('password-reset-submit',10),async(req,res)=>{const raw=String(req.body.token||''),password=String(req.body.password||'');if(password.length<10||!/[A-Z]/.test(password)||!/[a-z]/.test(password)||!/[0-9]/.test(password))return res.status(400).json({error:'Use at least 10 characters including uppercase, lowercase and a number'});const hash=crypto.createHash('sha256').update(raw).digest('hex'),client=await pool.connect();try{await client.query('BEGIN');const found=await client.query(`SELECT * FROM password_reset_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW() FOR UPDATE`,[hash]);if(!found.rowCount){await client.query('ROLLBACK');return res.status(400).json({error:'Reset link is invalid or expired'})}const record=found.rows[0],passwordHash=await bcrypt.hash(password,12);await client.query(`UPDATE users SET password_hash=$1,password_changed_at=NOW() WHERE id=$2 AND tenant_id=$3`,[passwordHash,record.user_id,record.tenant_id]);await client.query(`UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND tenant_id=$2 AND used_at IS NULL`,[record.user_id,record.tenant_id]);await client.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details) VALUES($1,'password_changed','warning','Account password changed; older sessions invalidated',$2)`,[record.tenant_id,JSON.stringify({user_id:record.user_id})]);await client.query('COMMIT');res.json({message:'Password changed successfully. You can now log in.'})}catch(e){await client.query('ROLLBACK');res.status(500).json({error:'Could not reset password'})}finally{client.release()}});

app.get('/api/security-center',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const [events,disabled,resets]=await Promise.all([pool.query(`SELECT event_type,severity,message,details,request_id,created_at FROM system_events WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`,[t]),pool.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id=$1 AND COALESCE(account_active,TRUE)=FALSE`,[t]),pool.query(`SELECT COUNT(*) FILTER(WHERE used_at IS NULL AND expires_at>NOW())::int active,COUNT(*) FILTER(WHERE used_at IS NOT NULL)::int used FROM password_reset_tokens WHERE tenant_id=$1`,[t])]);res.json({events:events.rows,disabled_accounts:disabled.rows[0].count,password_resets:resets.rows[0],session_lifetime_hours:12,backup_responsibility:'Database backups and point-in-time restoration are managed in your PostgreSQL hosting provider.',request_id:req.requestId})}catch(e){res.status(500).json({error:e.message})}});

app.get('/api/company-data-export',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const queries={tenant:`SELECT id,name,plan,timezone,created_at FROM tenants WHERE id=$1`,sites:`SELECT * FROM sites WHERE tenant_id=$1`,users:`SELECT id,tenant_id,email,role,job_title,permissions,account_active,created_at FROM users WHERE tenant_id=$1`,shifts:`SELECT * FROM shifts WHERE tenant_id=$1`,attendance:`SELECT * FROM attendance_sessions WHERE tenant_id=$1`,patrol_runs:`SELECT * FROM patrol_runs WHERE tenant_id=$1`,incidents:`SELECT * FROM incidents WHERE tenant_id=$1`,contracts:`SELECT * FROM service_contracts WHERE tenant_id=$1`,invoices:`SELECT * FROM invoices WHERE tenant_id=$1`,audit_logs:`SELECT * FROM audit_logs WHERE tenant_id=$1 ORDER BY created_at DESC`};const data={exported_at:new Date().toISOString(),format_version:1};for(const[name,sql]of Object.entries(queries))data[name]=(await pool.query(sql,[t])).rows;await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details,request_id) VALUES($1,'company_data_exported','warning','Company data export downloaded',$2,$3)`,[t,JSON.stringify({requested_by:req.auth.user_id}),req.requestId]);res.setHeader('Content-Type','application/json');res.setHeader('Content-Disposition',`attachment; filename="patrolsync-company-${t}-${new Date().toISOString().slice(0,10)}.json"`);res.send(JSON.stringify(data,null,2))}catch(e){res.status(500).json({error:e.message})}});

// ------------------------ PHASE 4.11: PRODUCTION HARDENING ------------------------
app.get('/api/system-health',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const dbStarted=Date.now();await pool.query('SELECT 1');const dbLatency=Date.now()-dbStarted;const[webhooks,events,audit,activeUsers]=await Promise.all([pool.query(`SELECT COUNT(*) FILTER(WHERE status='queued')::int queued,COUNT(*) FILTER(WHERE status='failed')::int failed,COUNT(*) FILTER(WHERE status='delivered')::int delivered,MAX(delivered_at) last_delivered_at FROM webhook_deliveries WHERE tenant_id=$1`,[t]),pool.query(`SELECT id,event_type,severity,message,details,request_id,created_at FROM system_events WHERE tenant_id IS NULL OR tenant_id=$1 ORDER BY created_at DESC LIMIT 50`,[t]),pool.query(`SELECT COUNT(*)::int total,MAX(created_at) latest_at FROM audit_logs WHERE tenant_id=$1`,[t]),pool.query(`SELECT COUNT(*)::int total FROM users WHERE tenant_id=$1 AND COALESCE(account_active,TRUE)=TRUE`,[t])]);const memory=process.memoryUsage();res.json({status:'healthy',generated_at:new Date(),started_at:APP_STARTED_AT,uptime_seconds:Math.floor(process.uptime()),database:{connected:true,latency_ms:dbLatency,pool_total:pool.totalCount,pool_idle:pool.idleCount,pool_waiting:pool.waitingCount},memory:{rss_mb:Math.round(memory.rss/1048576),heap_used_mb:Math.round(memory.heapUsed/1048576)},webhooks:webhooks.rows[0],audit:audit.rows[0],active_users:activeUsers.rows[0].total,retention:{audit_days:AUDIT_RETENTION_DAYS,webhook_days:WEBHOOK_RETENTION_DAYS},events:events.rows,request_id:req.requestId})}catch(e){res.status(503).json({status:'unhealthy',error:e.message,request_id:req.requestId})}});

async function runOperationsCleanup(){try{const result=await pool.query(`WITH a AS (DELETE FROM audit_logs WHERE created_at<NOW()-($1::int*INTERVAL '1 day') RETURNING 1),w AS (DELETE FROM webhook_deliveries WHERE created_at<NOW()-($2::int*INTERVAL '1 day') RETURNING 1),e AS (DELETE FROM system_events WHERE created_at<NOW()-INTERVAL '30 days' RETURNING 1) SELECT (SELECT COUNT(*) FROM a)::int audit_deleted,(SELECT COUNT(*) FROM w)::int webhook_deleted,(SELECT COUNT(*) FROM e)::int events_deleted`,[AUDIT_RETENTION_DAYS,WEBHOOK_RETENTION_DAYS]);const counts=result.rows[0];if(counts.audit_deleted||counts.webhook_deleted||counts.events_deleted)console.log('Operations cleanup:',counts)}catch(e){console.error('Operations cleanup failed:',e.message)}}setInterval(runOperationsCleanup,24*60*60*1000);setTimeout(runOperationsCleanup,60000);

app.use((err,req,res,next)=>{console.error(JSON.stringify({level:'error',type:'unhandled_request_error',request_id:req.requestId,method:req.method,path:req.path,message:err.message}));if(res.headersSent)return next(err);res.status(err.statusCode||500).json({error:err.statusCode?err.message:'Unexpected server error',request_id:req.requestId})});

// ------------------------ SERVER START ------------------------

app.listen(PORT, () => {
  console.log(`PatrolSync backend running on port ${PORT}`);
});
