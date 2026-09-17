-- Read-only preflight for V01 tenant-matched parent/child constraints.
-- Run against the intended database immediately before planning any migration.
-- This reports aggregate counts only; it does not change data or schema.
SELECT 'notification_receipts' AS relationship,
       COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE p.id IS NULL)::int AS orphaned,
       COUNT(*) FILTER (WHERE p.id IS NOT NULL AND c.tenant_id IS DISTINCT FROM p.tenant_id)::int AS cross_tenant
FROM communication_notification_receipts c
LEFT JOIN communication_notifications p ON p.id = c.notification_id
UNION ALL
SELECT 'team_messages', COUNT(*)::int,
       COUNT(*) FILTER (WHERE p.id IS NULL)::int,
       COUNT(*) FILTER (WHERE p.id IS NOT NULL AND c.tenant_id IS DISTINCT FROM p.tenant_id)::int
FROM team_messages c LEFT JOIN team_conversations p ON p.id = c.conversation_id
UNION ALL
SELECT 'team_conversation_reads', COUNT(*)::int,
       COUNT(*) FILTER (WHERE p.id IS NULL)::int,
       COUNT(*) FILTER (WHERE p.id IS NOT NULL AND c.tenant_id IS DISTINCT FROM p.tenant_id)::int
FROM team_conversation_reads c LEFT JOIN team_conversations p ON p.id = c.conversation_id
UNION ALL
SELECT 'lone_worker_checkins', COUNT(*)::int,
       COUNT(*) FILTER (WHERE p.id IS NULL)::int,
       COUNT(*) FILTER (WHERE p.id IS NOT NULL AND c.tenant_id IS DISTINCT FROM p.tenant_id)::int
FROM lone_worker_checkins c LEFT JOIN lone_worker_settings p ON p.id = c.setting_id
UNION ALL
SELECT 'lone_worker_alerts', COUNT(*)::int,
       COUNT(*) FILTER (WHERE p.id IS NULL)::int,
       COUNT(*) FILTER (WHERE p.id IS NOT NULL AND c.tenant_id IS DISTINCT FROM p.tenant_id)::int
FROM lone_worker_alerts c LEFT JOIN lone_worker_settings p ON p.id = c.setting_id
UNION ALL
SELECT 'client_accounts_to_sites', COUNT(*)::int,
       COUNT(*) FILTER (WHERE s.id IS NULL)::int,
       COUNT(*) FILTER (WHERE s.id IS NOT NULL AND cu.tenant_id IS DISTINCT FROM s.tenant_id)::int
FROM client_users cu LEFT JOIN sites s ON s.id = cu.site_id
UNION ALL
SELECT 'ticket_comments_to_tickets', COUNT(*)::int,
       COUNT(*) FILTER (WHERE t.id IS NULL)::int,
       COUNT(*) FILTER (WHERE t.id IS NOT NULL AND c.tenant_id IS DISTINCT FROM t.tenant_id)::int
FROM service_ticket_comments c LEFT JOIN service_tickets t ON t.id = c.ticket_id
UNION ALL
SELECT 'crisis_roles_to_activations', COUNT(*)::int,
       COUNT(*) FILTER (WHERE p.id IS NULL)::int,
       COUNT(*) FILTER (WHERE p.id IS NOT NULL AND c.tenant_id IS DISTINCT FROM p.tenant_id)::int
FROM crisis_roles c LEFT JOIN crisis_activations p ON p.id = c.crisis_id
UNION ALL
SELECT 'crisis_actions_to_activations', COUNT(*)::int,
       COUNT(*) FILTER (WHERE p.id IS NULL)::int,
       COUNT(*) FILTER (WHERE p.id IS NOT NULL AND c.tenant_id IS DISTINCT FROM p.tenant_id)::int
FROM crisis_actions c LEFT JOIN crisis_activations p ON p.id = c.crisis_id
UNION ALL
SELECT 'crisis_updates_to_activations', COUNT(*)::int,
       COUNT(*) FILTER (WHERE p.id IS NULL)::int,
       COUNT(*) FILTER (WHERE p.id IS NOT NULL AND c.tenant_id IS DISTINCT FROM p.tenant_id)::int
FROM crisis_updates c LEFT JOIN crisis_activations p ON p.id = c.crisis_id;

