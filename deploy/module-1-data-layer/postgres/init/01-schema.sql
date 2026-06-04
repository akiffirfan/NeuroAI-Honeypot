-- =============================================================================
-- 01-schema.sql
-- Neuro Honeypot Platform — PostgreSQL + TimescaleDB Schema
--
-- This script runs automatically on first container start when the postgres-data
-- volume is empty. It does NOT run on subsequent starts. To reset and re-run:
--   docker compose -f module-1-data-layer/docker-compose.yml down
--   docker volume rm <project>_postgres-data
--   docker compose -f module-1-data-layer/docker-compose.yml up -d
--
-- Schema source: Section 5.1 of honeypot-project-plans.md
-- =============================================================================

-- Enable TimescaleDB extension — must be first
-- WHY: TimescaleDB's create_hypertable() and add_retention_policy() calls below
-- require this extension. It is bundled in the timescale/timescaledb image but
-- must be explicitly enabled in the database.
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- =============================================================================
-- TABLE: honeypot_events
-- The primary event store — every attacker interaction is written here by the
-- log-shipper service. All sensors (Cowrie, FastAPI, OpenCanary, MariaDB lure)
-- write to this table via the unified schema.
--
-- DESIGN NOTES:
--   - BIGSERIAL for id: monotonically increasing, useful for pagination
--   - UUID event_id: globally unique identifier shared with external systems
--     (HoneyDash ingest, MISP exports, CloudTrail correlation)
--   - TIMESTAMPTZ: always store with timezone (UTC). Never use TIMESTAMP without TZ.
--   - INET for IP addresses: native Postgres type with subnet operators (<<, &&)
--     enabling efficient IP range queries without string parsing
--   - JSONB for payload and raw_log: flexible — sensor-specific fields that don't
--     have a fixed schema can be stored here without schema migrations
--   - TEXT[] for tags: supports GIN index for array containment queries
--     (e.g. WHERE 'brute-force' = ANY(tags))
--   - SMALLINT for threat_score: 0-100 range fits in 2 bytes; no need for INTEGER
-- =============================================================================

CREATE TABLE honeypot_events (
    id              BIGSERIAL NOT NULL,
    event_id        UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sensor          TEXT NOT NULL,          -- 'cowrie', 'api', 'opencanary'
    event_type      TEXT NOT NULL,          -- 'ssh.login.attempt', 'http.request', etc.
    src_ip          INET NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER,
    geo_country     TEXT,
    geo_country_code CHAR(2),
    geo_city        TEXT,
    geo_lat         DOUBLE PRECISION,
    geo_lon         DOUBLE PRECISION,
    geo_asn         INTEGER,
    geo_org         TEXT,
    is_tor          BOOLEAN DEFAULT FALSE,
    is_vpn          BOOLEAN DEFAULT FALSE,
    username        TEXT,
    password        TEXT,
    payload         JSONB,
    raw_log         JSONB,
    session_id      TEXT,
    threat_score    SMALLINT,               -- 0-100; log-shipper assigns based on event type + history
    tags            TEXT[] DEFAULT '{}',    -- 'scanner', 'brute-force', 'exfil-attempt', etc.
    PRIMARY KEY (id, created_at)            -- TimescaleDB requires the partition column (created_at) in every unique index
);

-- =============================================================================
-- TimescaleDB Hypertable
-- WHY: Converts honeypot_events into a time-partitioned hypertable.
-- Each time chunk covers 1 week by default.
--
-- Benefits for this workload:
--   - Chunk-level DROP (retention policy) is O(1) — no table scan or VACUUM
--   - Index scans stay within a single chunk for recent-data queries (the 90%+ case)
--   - Chunk-level compression (optional) can reduce old data storage by 90%
--
-- NOTE: create_hypertable must be called BEFORE any data is inserted.
-- If you need to run this on an existing populated table, use:
--   SELECT create_hypertable('honeypot_events', 'created_at', migrate_data => true);
-- (migration is slow and locks the table — only for development/recovery)
-- =============================================================================

SELECT create_hypertable('honeypot_events', 'created_at');

-- =============================================================================
-- Retention Policy: 90-day automatic chunk expiry
-- WHY: Without a retention policy, at 100 events/sec sustained (attack flood),
-- the hypertable grows at 8.6M events/day. A 100GB SSD fills in ~11 days.
-- The 90-day retention balances forensic value (enough history for pattern
-- analysis and legal holds) against disk growth.
--
-- HOW IT WORKS: TimescaleDB's background job scheduler runs this policy
-- automatically. It drops complete chunks (1-week blocks) that are entirely
-- older than 90 days. Partial chunks (containing events newer than 90 days)
-- are NOT dropped — no data is truncated mid-chunk.
--
-- OFF-HOST ARCHIVE: The log-shipper writes daily JSONL archives to S3 Object Lock
-- (Section 14.2). Events older than 90 days are archived before this policy
-- drops them. The S3 archive has its own 90-day Object Lock retention.
--
-- TO VERIFY the policy is active after deployment:
--   SELECT * FROM timescaledb_information.jobs WHERE application_name LIKE '%Retention%';
-- =============================================================================

SELECT add_retention_policy('honeypot_events', INTERVAL '90 days');

-- =============================================================================
-- Indexes on honeypot_events
-- WHY each index exists:
--   src_ip:       most common filter — "all events from this attacker IP"
--   sensor:       filter by sensor type for cross-sensor correlation
--   event_type:   filter by attack category (all brute-force vs all scans)
--   session_id:   join events from a single attacker session across sensors
--   tags GIN:     array containment queries: WHERE 'brute-force' = ANY(tags)
--   threat_score: sort high-priority events for operator triage dashboard
--   created_at is already the hypertable partition key — TimescaleDB creates
--   a cluster index on it automatically; do not add a redundant index.
-- =============================================================================

-- event_id lookup — UUID uniqueness enforced by gen_random_uuid(); no UNIQUE constraint because
-- TimescaleDB requires all unique indexes to include the partition column (created_at)
CREATE INDEX idx_events_event_id ON honeypot_events (event_id);

-- IP-based lookups — most frequent operator query pattern
CREATE INDEX idx_events_src_ip ON honeypot_events (src_ip);

-- Sensor type filtering (Cowrie vs API vs OpenCanary correlation)
CREATE INDEX idx_events_sensor ON honeypot_events (sensor);

-- Event type filtering (all login attempts, all file downloads, etc.)
CREATE INDEX idx_events_event_type ON honeypot_events (event_type);

-- Session correlation — group all events from a single attacker session
CREATE INDEX idx_events_session_id ON honeypot_events (session_id);

-- Tags array containment — GIN index required for ANY() and @> operators
CREATE INDEX idx_events_tags ON honeypot_events USING GIN (tags);

-- Threat score ordering — operator dashboard shows highest-threat events first
CREATE INDEX idx_events_threat_score ON honeypot_events (threat_score DESC)
    WHERE threat_score IS NOT NULL;

-- =============================================================================
-- TABLE: attacker_sessions
-- Aggregates all events from a single attacker session into a summary record.
-- Maintained by the log-shipper: upserted on each event using session_id as key.
--
-- WHY a separate sessions table:
--   Querying "what did this attacker do in this session?" would require
--   aggregating across potentially hundreds of honeypot_events rows.
--   The sessions table caches these aggregates, making the dashboard fast
--   for session-level views without complex GROUP BY queries on the hypertable.
-- =============================================================================

CREATE TABLE attacker_sessions (
    session_id          TEXT PRIMARY KEY,
    src_ip              INET NOT NULL,
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    event_count         INTEGER DEFAULT 0,
    sensors_hit         TEXT[],              -- e.g. ARRAY['cowrie', 'api', 'opencanary']
    credentials_tried   JSONB,              -- {"root": ["pass1","pass2"], "admin": ["123"]}
    commands_run        TEXT[],              -- list of raw command strings from Cowrie
    paths_accessed      TEXT[],              -- HTTP paths from FastAPI honeypot
    files_requested     TEXT[],              -- file download URLs from Cowrie
    threat_score        SMALLINT,
    disposition         TEXT DEFAULT 'active',  -- 'active', 'closed', 'blocked', 'escalated'
    kill_chain_stage    TEXT                    -- RECON, INITIAL_ACCESS, DISCOVERY, CREDENTIAL_ACCESS, EXECUTION, EXFILTRATION
);

-- Index for IP-based session lookup (which sessions came from this IP?)
CREATE INDEX idx_sessions_src_ip ON attacker_sessions (src_ip);
-- Index for time-ordered session listing in operator dashboard
CREATE INDEX idx_sessions_last_seen ON attacker_sessions (last_seen DESC);

-- =============================================================================
-- TABLE: payload_samples
-- Stores raw payload data (malware uploads, exploit strings, large POST bodies)
-- that exceed the 64KB cap stored in honeypot_events.payload.
--
-- WHY a separate table:
--   payload_raw is BYTEA — large binary objects stored inline in Postgres.
--   Putting these in the hypertable would bloat chunk sizes and degrade TimescaleDB
--   performance. Separating them keeps honeypot_events lean for time-series queries
--   while still allowing forensic access via the event_id foreign key.
--
-- NOTE: sha256 enables deduplication (same malware from different sessions)
--   and VirusTotal lookups via the log-shipper (Section 5.3 threshold alerts).
-- =============================================================================

CREATE TABLE payload_samples (
    id              BIGSERIAL PRIMARY KEY,
    event_id        UUID,                   -- references honeypot_events.event_id; no FK constraint because TimescaleDB hypertables do not support foreign key references
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload_type    TEXT,           -- 'ssh_upload', 'http_post_body', 'malware_download', etc.
    payload_raw     BYTEA,          -- raw binary content
    payload_text    TEXT,           -- UTF-8 decoded version (if decodable)
    sha256          TEXT,           -- hex SHA-256 of payload_raw (for VirusTotal/dedup)
    mime_type       TEXT,           -- detected MIME type (via python-magic or file(1))
    size_bytes      INTEGER
);

-- SHA-256 index for deduplication and VirusTotal lookup queries
CREATE INDEX idx_payloads_sha256 ON payload_samples (sha256);
-- event_id index for join performance (event → payloads)
CREATE INDEX idx_payloads_event_id ON payload_samples (event_id);

-- =============================================================================
-- Verification queries — run after deployment to confirm schema is correct:
--
--   \dt                      -- should show 3 tables
--   SELECT * FROM timescaledb_information.hypertables;  -- honeypot_events should appear
--   SELECT * FROM timescaledb_information.jobs WHERE application_name LIKE '%Retention%';
--   \di                      -- should show all indexes listed above
-- =============================================================================
