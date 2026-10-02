-- Reviewed restricted-role boundary for the 56 previously unprotected workflow tables.
-- Parent/child tenant constraints are intentionally handled by the next migration.
DO $migration$
DECLARE
  target_table text;
  tenant_tables text[] := ARRAY[
    'asset_custody','attendance_breaks','attendance_sessions','audit_logs','auth_sessions',
    'client_report_runs','client_report_schedules','client_users',
    'communication_notification_receipts','communication_notifications',
    'contract_renewal_history','contract_renewals','corrective_actions','dispatch_jobs',
    'email_deliveries','guard_availability','guard_certifications','guard_location_history',
    'guard_locations','handover_logs','incident_activities','incident_photos','incidents',
    'inspection_runs','inspection_templates','integration_api_keys','invoice_lines',
    'invoice_payments','invoices','leave_requests','lone_worker_alerts',
    'lone_worker_checkins','lone_worker_settings','managed_assets','notifications',
    'password_reset_tokens','patrol_alerts','patrol_route_checkpoints','patrol_routes',
    'patrol_run_scans','patrol_runs','service_ticket_comments','service_tickets',
    'shift_swap_requests','shift_templates','shifts','sos_alerts','system_events',
    'team_conversation_reads','team_conversations','team_messages','timesheets',
    'training_assignments','training_materials','webhook_deliveries','webhook_endpoints'
  ];
BEGIN
  FOREACH target_table IN ARRAY tenant_tables LOOP
    IF to_regclass(format('public.%I',target_table)) IS NULL THEN
      RAISE EXCEPTION 'Required workflow table % is missing', target_table;
    END IF;
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',target_table);
    IF NOT EXISTS (
      SELECT 1 FROM pg_policies
      WHERE schemaname='public' AND tablename=target_table
        AND policyname='patrolsync_tenant_isolation'
    ) THEN
      EXECUTE format(
        'CREATE POLICY patrolsync_tenant_isolation ON public.%I TO {{TENANT_ROLE}} USING (tenant_id = NULLIF(current_setting(''app.current_tenant'',true),'''')::integer) WITH CHECK (tenant_id = NULLIF(current_setting(''app.current_tenant'',true),'''')::integer)',
        target_table
      );
    END IF;
    EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.%I FROM {{TENANT_ROLE}}',target_table);
  END LOOP;
END
$migration$;

GRANT SELECT,INSERT,UPDATE,DELETE ON
  patrol_routes,patrol_route_checkpoints,shift_templates,shifts,leave_requests,
  communication_notifications,client_users
TO {{TENANT_ROLE}};

GRANT SELECT,INSERT,UPDATE ON
  attendance_sessions,attendance_breaks,patrol_runs,incidents,shift_swap_requests,
  guard_availability,timesheets,dispatch_jobs,sos_alerts,
  communication_notification_receipts,team_conversations,team_conversation_reads,
  lone_worker_settings,guard_locations,handover_logs,training_assignments,
  managed_assets,asset_custody,inspection_runs,corrective_actions,
  client_report_schedules,client_report_runs,contract_renewals,invoices,
  guard_certifications
TO {{TENANT_ROLE}};

GRANT SELECT,INSERT ON
  patrol_run_scans,incident_activities,team_messages,lone_worker_checkins,
  guard_location_history,training_materials,inspection_templates,
  contract_renewal_history,invoice_lines,invoice_payments,system_events
TO {{TENANT_ROLE}};

GRANT SELECT,UPDATE ON
  patrol_alerts,lone_worker_alerts,service_tickets,email_deliveries
TO {{TENANT_ROLE}};

GRANT SELECT ON audit_logs,service_ticket_comments TO {{TENANT_ROLE}};
GRANT SELECT,INSERT,DELETE ON incident_photos TO {{TENANT_ROLE}};
GRANT SELECT,UPDATE,DELETE ON notifications TO {{TENANT_ROLE}};

DO $migration$
DECLARE
  target_table text;
  insert_tables text[] := ARRAY[
    'patrol_routes','patrol_route_checkpoints','shift_templates','shifts','leave_requests',
    'communication_notifications','client_users','attendance_sessions','attendance_breaks',
    'patrol_runs','incidents','shift_swap_requests','guard_availability','timesheets',
    'dispatch_jobs','sos_alerts','communication_notification_receipts','team_conversations',
    'team_conversation_reads','lone_worker_settings','guard_locations','handover_logs',
    'training_assignments','managed_assets','asset_custody','inspection_runs',
    'corrective_actions','client_report_schedules','client_report_runs','contract_renewals',
    'invoices','guard_certifications','patrol_run_scans','incident_activities','team_messages',
    'lone_worker_checkins','guard_location_history','training_materials','inspection_templates',
    'contract_renewal_history','invoice_lines','invoice_payments','system_events','incident_photos'
  ];
  sequence_name text;
BEGIN
  FOREACH target_table IN ARRAY insert_tables LOOP
    IF EXISTS (
      SELECT 1
      FROM pg_attribute
      WHERE attrelid=to_regclass(format('public.%I',target_table))
        AND attname='id' AND attnum>0 AND NOT attisdropped
    ) THEN
      SELECT pg_get_serial_sequence(format('public.%I',target_table),'id') INTO sequence_name;
      IF sequence_name IS NOT NULL THEN
        EXECUTE format('GRANT USAGE,SELECT ON SEQUENCE %s TO {{TENANT_ROLE}}',sequence_name);
      END IF;
    END IF;
  END LOOP;
END
$migration$;
