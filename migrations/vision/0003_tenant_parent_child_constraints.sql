-- Prevent a row owned by one tenant from referencing a parent owned by another.
-- Existing rows are validated atomically before this migration is recorded.
CREATE OR REPLACE FUNCTION pg_temp.add_tenant_unique(target_table text, constraint_name text)
RETURNS void LANGUAGE plpgsql AS $migration$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid=to_regclass(format('public.%I',target_table)) AND conname=constraint_name
  ) THEN
    EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I UNIQUE(tenant_id,id)',target_table,constraint_name);
  END IF;
END
$migration$;

CREATE OR REPLACE FUNCTION pg_temp.add_tenant_fk(
  child_table text,
  constraint_name text,
  child_columns text,
  parent_table text
) RETURNS void LANGUAGE plpgsql AS $migration$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid=to_regclass(format('public.%I',child_table)) AND conname=constraint_name
  ) THEN
    EXECUTE format(
      'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY(tenant_id,%s) REFERENCES public.%I(tenant_id,id)',
      child_table,constraint_name,child_columns,parent_table
    );
  END IF;
END
$migration$;

SELECT pg_temp.add_tenant_unique(parent_table,'patrolsync_' || parent_table || '_tenant_id_unique')
FROM unnest(ARRAY[
  'communication_notifications','team_conversations','lone_worker_settings','crisis_activations',
  'guard_trusted_devices','sites','users','training_materials','managed_assets',
  'inspection_templates','inspection_runs','service_contracts','client_report_schedules',
  'contract_renewals','invoices','webhook_endpoints','guard_certifications','service_tickets'
]) AS parent_table;

SELECT pg_temp.add_tenant_fk(child_table,constraint_name,child_column,parent_table)
FROM (VALUES
  ('communication_notification_receipts','patrolsync_notification_receipts_tenant_notification_fk','notification_id','communication_notifications'),
  ('team_messages','patrolsync_team_messages_tenant_conversation_fk','conversation_id','team_conversations'),
  ('team_conversation_reads','patrolsync_conversation_reads_tenant_conversation_fk','conversation_id','team_conversations'),
  ('lone_worker_checkins','patrolsync_worker_checkins_tenant_setting_fk','setting_id','lone_worker_settings'),
  ('lone_worker_alerts','patrolsync_worker_alerts_tenant_setting_fk','setting_id','lone_worker_settings'),
  ('crisis_roles','patrolsync_crisis_roles_tenant_crisis_fk','crisis_id','crisis_activations'),
  ('crisis_actions','patrolsync_crisis_actions_tenant_crisis_fk','crisis_id','crisis_activations'),
  ('crisis_updates','patrolsync_crisis_updates_tenant_crisis_fk','crisis_id','crisis_activations'),
  ('identity_verification_events','patrolsync_identity_events_tenant_device_fk','device_id','guard_trusted_devices'),
  ('client_users','patrolsync_client_users_tenant_site_fk','site_id','sites'),
  ('handover_logs','patrolsync_handovers_tenant_site_fk','site_id','sites'),
  ('handover_logs','patrolsync_handovers_tenant_from_user_fk','from_user_id','users'),
  ('handover_logs','patrolsync_handovers_tenant_to_user_fk','to_user_id','users'),
  ('handover_logs','patrolsync_handovers_tenant_acknowledged_by_fk','acknowledged_by','users'),
  ('handover_logs','patrolsync_handovers_tenant_resolved_by_fk','resolved_by','users'),
  ('training_materials','patrolsync_training_materials_tenant_site_fk','site_id','sites'),
  ('training_materials','patrolsync_training_materials_tenant_creator_fk','created_by_user_id','users'),
  ('training_assignments','patrolsync_training_assignments_tenant_material_fk','material_id','training_materials'),
  ('training_assignments','patrolsync_training_assignments_tenant_user_fk','user_id','users'),
  ('managed_assets','patrolsync_managed_assets_tenant_site_fk','site_id','sites'),
  ('asset_custody','patrolsync_asset_custody_tenant_asset_fk','asset_id','managed_assets'),
  ('asset_custody','patrolsync_asset_custody_tenant_user_fk','user_id','users'),
  ('asset_custody','patrolsync_asset_custody_tenant_issued_by_user_fk','issued_by_user_id','users'),
  ('inspection_templates','patrolsync_inspection_templates_tenant_site_fk','site_id','sites'),
  ('inspection_templates','patrolsync_inspection_templates_tenant_creator_fk','created_by_user_id','users'),
  ('inspection_runs','patrolsync_inspection_runs_tenant_template_fk','template_id','inspection_templates'),
  ('inspection_runs','patrolsync_inspection_runs_tenant_site_fk','site_id','sites'),
  ('inspection_runs','patrolsync_inspection_runs_tenant_assigned_user_fk','assigned_user_id','users'),
  ('inspection_runs','patrolsync_inspection_runs_tenant_created_by_user_fk','created_by_user_id','users'),
  ('corrective_actions','patrolsync_corrective_actions_tenant_run_fk','inspection_run_id','inspection_runs'),
  ('corrective_actions','patrolsync_corrective_actions_tenant_assignee_fk','assigned_user_id','users'),
  ('client_report_schedules','patrolsync_report_schedules_tenant_contract_fk','contract_id','service_contracts'),
  ('client_report_schedules','patrolsync_report_schedules_tenant_creator_fk','created_by','users'),
  ('client_report_runs','patrolsync_report_runs_tenant_schedule_fk','schedule_id','client_report_schedules'),
  ('client_report_runs','patrolsync_report_runs_tenant_contract_fk','contract_id','service_contracts'),
  ('client_report_runs','patrolsync_report_runs_tenant_deliverer_fk','delivered_by','users'),
  ('contract_renewals','patrolsync_contract_renewals_tenant_contract_fk','contract_id','service_contracts'),
  ('contract_renewals','patrolsync_contract_renewals_tenant_completed_contract_fk','completed_contract_id','service_contracts'),
  ('contract_renewals','patrolsync_contract_renewals_tenant_owner_fk','owner_user_id','users'),
  ('contract_renewal_history','patrolsync_contract_history_tenant_renewal_fk','renewal_id','contract_renewals'),
  ('contract_renewal_history','patrolsync_contract_history_tenant_user_fk','user_id','users'),
  ('invoices','patrolsync_invoices_tenant_contract_fk','contract_id','service_contracts'),
  ('invoices','patrolsync_invoices_tenant_creator_fk','created_by','users'),
  ('invoice_payments','patrolsync_invoice_payments_tenant_invoice_fk','invoice_id','invoices'),
  ('invoice_payments','patrolsync_invoice_payments_tenant_recorder_fk','recorded_by','users'),
  ('webhook_deliveries','patrolsync_webhook_deliveries_tenant_webhook_fk','webhook_id','webhook_endpoints'),
  ('integration_api_keys','patrolsync_integration_keys_tenant_creator_fk','created_by_user_id','users'),
  ('auth_sessions','patrolsync_auth_sessions_tenant_user_fk','user_id','users'),
  ('password_reset_tokens','patrolsync_password_resets_tenant_user_fk','user_id','users'),
  ('audit_logs','patrolsync_audit_logs_tenant_user_fk','user_id','users'),
  ('guard_certifications','patrolsync_guard_certifications_tenant_user_fk','user_id','users'),
  ('guard_certifications','patrolsync_guard_certifications_tenant_archiver_fk','archived_by_user_id','users'),
  ('guard_certifications','patrolsync_guard_certifications_tenant_replacement_for_fk','replacement_for_id','guard_certifications'),
  ('guard_certifications','patrolsync_guard_certifications_tenant_replaced_by_fk','replaced_by_id','guard_certifications'),
  ('operations_risk_snapshots','patrolsync_operations_risk_tenant_site_fk','site_id','sites'),
  ('site_risk_twins','patrolsync_site_risk_twins_tenant_site_fk','site_id','sites'),
  ('site_risk_scenarios','patrolsync_site_risk_scenarios_tenant_site_fk','site_id','sites'),
  ('client_retention_snapshots','patrolsync_retention_tenant_contract_fk','contract_id','service_contracts'),
  ('service_ticket_comments','patrolsync_ticket_comments_tenant_ticket_fk','ticket_id','service_tickets')
) AS relationships(child_table,constraint_name,child_column,parent_table);
