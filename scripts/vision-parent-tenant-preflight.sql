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
FROM lone_worker_alerts c LEFT JOIN lone_worker_settings p ON p.id = c.setting_id;

