-- 02-migrate-kill-chain.sql
-- Idempotent migration: adds columns to attacker_sessions and honeypot_events
-- that were introduced after initial deployment.
--
-- Run on any VPS that was deployed before 2026-06-05, OR that was restored from
-- a pre-P3 backup.  Safe to run multiple times (IF NOT EXISTS / DO NOTHING).
--
-- NOTE: PostgreSQL runs all files in pg_docker-entrypoint-initdb.d/ alphabetically
-- on a FRESH volume only.  On an existing live DB, run this file manually:
--   docker exec postgres psql -U honeypot -d honeypot -f /docker-entrypoint-initdb.d/02-migrate-kill-chain.sql
--
-- Columns added by P2/P3 sessions that were applied as hand-run ALTERs on the
-- live VPS and therefore absent from any snapshot taken before those sessions:

-- P3 — kill_chain_stage on attacker_sessions
ALTER TABLE attacker_sessions ADD COLUMN IF NOT EXISTS kill_chain_stage TEXT;

-- P2 — enrichment columns on honeypot_events (added during Session 3, 2026-06-01)
ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS is_tor        BOOLEAN DEFAULT FALSE;
ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS threat_score  SMALLINT;
ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS tags          TEXT[] DEFAULT '{}';

-- P2 — enrichment columns on attacker_sessions (added during Session 3, 2026-06-01)
ALTER TABLE attacker_sessions ADD COLUMN IF NOT EXISTS threat_score SMALLINT;
