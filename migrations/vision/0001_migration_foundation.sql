-- Establishes the controlled Vision migration stream without changing application data.
-- The runner owns the checksum ledger and wraps this file in a transaction.
-- The restricted role substitution proves identifier validation before later grants.
DO $migration$
BEGIN
  IF to_regrole('{{TENANT_ROLE}}') IS NULL THEN
    RAISE EXCEPTION 'Required restricted tenant role does not exist';
  END IF;
END
$migration$;
