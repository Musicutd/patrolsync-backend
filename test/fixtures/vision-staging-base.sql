-- Test-only baseline for a disposable PostgreSQL database. Never apply to production.
-- These seven legacy tables predate the backend's CREATE TABLE IF NOT EXISTS setup.
-- Keep names unqualified so the integration test can use an isolated schema.
CREATE TABLE tenants (
  id SERIAL PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
  plan TEXT DEFAULT 'starter', billing_status TEXT DEFAULT 'trial',
  created_at TIMESTAMPTZ DEFAULT now(), timezone TEXT DEFAULT 'UTC',
  emergency_phone TEXT, emergency_whatsapp TEXT,
  account_active BOOLEAN NOT NULL DEFAULT true, suspended_at TIMESTAMPTZ,
  suspension_reason TEXT, subscription_status TEXT NOT NULL DEFAULT 'active',
  billing_cycle TEXT NOT NULL DEFAULT 'monthly', trial_ends_at TIMESTAMPTZ,
  renewal_at TIMESTAMPTZ, platform_notes TEXT
);
CREATE TABLE sites (
  id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL, address TEXT, created_at TIMESTAMPTZ DEFAULT now(),
  latitude DOUBLE PRECISION, longitude DOUBLE PRECISION,
  geofence_radius_m INTEGER NOT NULL DEFAULT 150,
  geofence_enabled BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE users (
  id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id),
  firebase_uid TEXT UNIQUE, email TEXT NOT NULL, role TEXT DEFAULT 'guard',
  created_at TIMESTAMPTZ DEFAULT now(), password_hash TEXT,
  permissions JSONB NOT NULL DEFAULT '[]'::jsonb, job_title TEXT,
  account_active BOOLEAN NOT NULL DEFAULT true,
  password_changed_at TIMESTAMPTZ, email_mfa_enabled BOOLEAN NOT NULL DEFAULT false,
  first_name TEXT, last_name TEXT
);
CREATE TABLE checkpoints (
  id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id),
  site_id INTEGER NOT NULL REFERENCES sites(id), name TEXT NOT NULL,
  qr_code TEXT NOT NULL UNIQUE, latitude NUMERIC, longitude NUMERIC,
  created_at TIMESTAMPTZ DEFAULT now(), building TEXT, floor TEXT,
  nfc_tag_uid TEXT
);
CREATE TABLE patrol_schedules (
  id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id),
  site_id INTEGER NOT NULL REFERENCES sites(id), schedule_type TEXT NOT NULL
    CHECK (schedule_type IN ('fixed', 'hourly', 'custom')),
  config JSONB NOT NULL, created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE patrol_logs (
  id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id),
  checkpoint_id INTEGER NOT NULL REFERENCES checkpoints(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  scanned_at TIMESTAMPTZ DEFAULT now(), latitude NUMERIC, longitude NUMERIC,
  patrol_run_id BIGINT, accuracy_m DOUBLE PRECISION, distance_m DOUBLE PRECISION,
  location_status TEXT NOT NULL DEFAULT 'unavailable',
  device_scanned_at TIMESTAMPTZ, received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  client_scan_id TEXT, scan_method TEXT NOT NULL DEFAULT 'qr',
  device_id TEXT, offline_captured BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE alert_log (
  id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
  checkpoint_id INTEGER NOT NULL, last_alerted_at TIMESTAMP NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, checkpoint_id)
);
-- Existing production has this app-created table. Pre-create it in a fresh
-- staging database because startup otherwise races its CREATE and ALTER calls.
CREATE TABLE guard_assignments (
  id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
  site_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now(), round_size INTEGER,
  UNIQUE (tenant_id, site_id, user_id)
);

CREATE INDEX idx_sites_tenant ON sites(tenant_id);
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_tenant_role_active ON users(tenant_id, role, account_active);
CREATE UNIQUE INDEX users_active_identity_unique ON users(tenant_id, lower(email), role)
  WHERE account_active AND role IN ('guard', 'staff');
CREATE INDEX idx_checkpoints_tenant ON checkpoints(tenant_id);
CREATE UNIQUE INDEX uq_checkpoints_tenant_nfc_tag ON checkpoints(tenant_id, nfc_tag_uid)
  WHERE nfc_tag_uid IS NOT NULL;
CREATE INDEX idx_schedules_tenant ON patrol_schedules(tenant_id);
CREATE INDEX idx_logs_tenant ON patrol_logs(tenant_id);
CREATE INDEX idx_patrol_logs_checkpoint ON patrol_logs(checkpoint_id);
CREATE INDEX idx_patrol_logs_evidence ON patrol_logs(tenant_id, location_status, scanned_at DESC);
CREATE INDEX idx_patrol_logs_user ON patrol_logs(user_id);
CREATE UNIQUE INDEX uq_patrol_logs_tenant_client_scan ON patrol_logs(tenant_id, client_scan_id)
  WHERE client_scan_id IS NOT NULL;

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE patrol_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE patrol_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE guard_assignments ENABLE ROW LEVEL SECURITY;

-- This fixture uses a disposable restricted role created by the integration test.
CREATE POLICY tenant_row ON tenants TO vision_base_reader
  USING (id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
  WITH CHECK (id = NULLIF(current_setting('app.current_tenant', true), '')::integer);
CREATE POLICY tenant_row ON sites TO vision_base_reader
  USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer);
CREATE POLICY tenant_row ON users TO vision_base_reader
  USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer);
CREATE POLICY tenant_row ON checkpoints TO vision_base_reader
  USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer);
CREATE POLICY tenant_row ON patrol_schedules TO vision_base_reader
  USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer);
CREATE POLICY tenant_row ON patrol_logs TO vision_base_reader
  USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer);
CREATE POLICY tenant_row ON alert_log TO vision_base_reader
  USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer);
CREATE POLICY tenant_row ON guard_assignments TO vision_base_reader
  USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::integer);

