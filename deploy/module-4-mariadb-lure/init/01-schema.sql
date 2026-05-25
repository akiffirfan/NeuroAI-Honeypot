-- Module 4 — mariadb-lure seed schema
-- Database: neuro_prod (fake AI/ML platform schema — honeypot deception target)
--
-- This file runs automatically on MariaDB first start when the mariadb-data
-- volume is empty. It is mounted at /docker-entrypoint-initdb.d/ (read-only).
--
-- CONSISTENCY REQUIREMENT (from Section 3.4 of honeypot-project-plans.md):
--   Seed rows in training_runs, models, and users must match the fake run list
--   visible on the Neuro web frontend (Section 4.2): run-042 through run-047,
--   users m.chen@neuro.ai / priya.nair@neuro.ai / j.park@neuro.ai / s.ali@neuro.ai / svc-deploy.
--   Any change to the frontend fake data MUST be mirrored here in the same edit.
--
-- ACCESS MODEL:
--   root        — password from .env (MARIADB_ROOT_PASSWORD); all privileges
--   neuro_app   — password from .env (MARIADB_PASSWORD); SELECT-only on neuro_prod
--                 This is the "leaked service account" an attacker would target.

USE neuro_prod;

-- ─── training_runs ────────────────────────────────────────────────────────────
CREATE TABLE training_runs (
    id           INT          PRIMARY KEY AUTO_INCREMENT,
    run_id       VARCHAR(16)  NOT NULL UNIQUE,
    model_name   VARCHAR(64),
    status       ENUM('RUNNING','COMPLETED','FAILED','PENDING','PAUSED') DEFAULT 'PENDING',
    gpu_node     VARCHAR(32),
    epoch        INT          DEFAULT 0,
    total_epochs INT          DEFAULT 0,
    loss         FLOAT,
    created_by   VARCHAR(64),
    created_at   DATETIME     DEFAULT NOW(),
    updated_at   DATETIME     DEFAULT NOW()
);

INSERT INTO training_runs (run_id, model_name, status, gpu_node, epoch, total_epochs, loss, created_by, created_at, updated_at) VALUES
('run-042', 'llama3-8b-finetune-v1',  'COMPLETED', 'neurocore-gpu01', 50,  50,  0.1821, 'm.chen@neuro.ai',    '2026-04-28 09:11:04', '2026-04-28 22:47:33'),
('run-043', 'mistral-7b-instruct-v2', 'COMPLETED', 'neurocore-gpu01', 80,  80,  0.2103, 'priya.nair@neuro.ai','2026-05-02 14:30:22', '2026-05-03 08:19:57'),
('run-044', 'llama3-8b-finetune-v2',  'FAILED',    'neurocore-gpu01', 12,  50,  0.5544, 'm.chen@neuro.ai',    '2026-05-07 10:05:18', '2026-05-07 13:22:41'),
('run-045', 'llama3-8b-finetune-v3',  'COMPLETED', 'neurocore-gpu01', 50,  50,  0.1677, 'm.chen@neuro.ai',    '2026-05-09 08:44:01', '2026-05-09 21:33:08'),
('run-046', 'mistral-7b-rlhf-v1',     'PAUSED',    'neurocore-gpu01', 31,  100, 0.3012, 'priya.nair@neuro.ai','2026-05-13 11:20:55', '2026-05-14 09:01:42'),
('run-047', 'llama3-70b-sft-v1',      'RUNNING',   'neurocore-gpu01', 18,  200, 0.4238, 'svc-deploy',          '2026-05-18 07:55:30', NOW());

-- ─── models ───────────────────────────────────────────────────────────────────
CREATE TABLE models (
    id          INT          PRIMARY KEY AUTO_INCREMENT,
    name        VARCHAR(128),
    version     VARCHAR(16),
    s3_path     VARCHAR(256),
    deployed    BOOLEAN      DEFAULT FALSE,
    created_by  VARCHAR(64),
    run_id      VARCHAR(16),
    created_at  DATETIME     DEFAULT NOW()
);

INSERT INTO models (name, version, s3_path, deployed, created_by, run_id, created_at) VALUES
('llama3-8b-finetune', 'v1.0', 's3://neuro-ml-artifacts/models/llama3-8b-ft-v1/', TRUE,  'm.chen@neuro.ai',    'run-042', '2026-04-29 10:05:00'),
('mistral-7b-instruct', 'v2.0', 's3://neuro-ml-artifacts/models/mistral-7b-inst-v2/', TRUE,  'priya.nair@neuro.ai','run-043', '2026-05-03 09:30:00'),
('llama3-8b-finetune', 'v3.0', 's3://neuro-ml-artifacts/models/llama3-8b-ft-v3/', FALSE, 'm.chen@neuro.ai',    'run-045', '2026-05-10 08:00:00'),
('llama3-70b-sft',     'v1.0', 's3://neuro-ml-artifacts/models/llama3-70b-sft-v1/', FALSE, 'svc-deploy',          'run-047', '2026-05-18 08:00:00');

-- ─── users ────────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id            INT          PRIMARY KEY AUTO_INCREMENT,
    username      VARCHAR(32)  NOT NULL UNIQUE,
    email         VARCHAR(128),
    role          ENUM('admin','ml_engineer','service_account') DEFAULT 'ml_engineer',
    api_key_hash  VARCHAR(64),
    last_login    DATETIME,
    created_at    DATETIME     DEFAULT NOW()
);

-- api_key_hash values are SHA-256 of fake API keys — attacker cannot reverse them
INSERT INTO users (username, email, role, api_key_hash, last_login, created_at) VALUES
('m.chen',    'm.chen@neuro.ai',    'admin',           'a3f2c1d4e5b6a7f8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2', '2026-05-19 08:12:33', '2026-01-15 09:00:00'),
('p.nair',    'priya.nair@neuro.ai','ml_engineer',     'b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3', '2026-05-18 17:44:01', '2026-02-01 10:30:00'),
('j.park',    'j.park@neuro.ai',   'ml_engineer',     'd6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5', '2026-05-16 11:03:42', '2026-02-15 09:00:00'),
('s.ali',     's.ali@neuro.ai',    'ml_engineer',     'e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6', '2026-05-15 08:21:17', '2026-03-01 10:00:00'),
('svc-deploy','',                    'service_account', 'c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4', NULL,                  '2026-01-10 06:00:00');

-- ─── gpu_jobs ─────────────────────────────────────────────────────────────────
CREATE TABLE gpu_jobs (
    id          INT          PRIMARY KEY AUTO_INCREMENT,
    run_id      VARCHAR(16),
    gpu_node    VARCHAR(32),
    gpu_index   TINYINT      DEFAULT 0,
    vram_gb     FLOAT,
    utilization FLOAT,
    started_at  DATETIME,
    ended_at    DATETIME
);

INSERT INTO gpu_jobs (run_id, gpu_node, gpu_index, vram_gb, utilization, started_at, ended_at) VALUES
('run-042', 'neurocore-gpu01', 0, 78.5, 98.2, '2026-04-28 09:11:04', '2026-04-28 22:47:33'),
('run-043', 'neurocore-gpu01', 0, 62.3, 95.7, '2026-05-02 14:30:22', '2026-05-03 08:19:57'),
('run-045', 'neurocore-gpu01', 0, 78.8, 97.1, '2026-05-09 08:44:01', '2026-05-09 21:33:08'),
('run-047', 'neurocore-gpu01', 0, 79.9, 99.1, '2026-05-18 07:55:30', NULL);

-- ─── dataset_metadata ─────────────────────────────────────────────────────────
CREATE TABLE dataset_metadata (
    id           INT          PRIMARY KEY AUTO_INCREMENT,
    name         VARCHAR(128),
    version      VARCHAR(16),
    s3_path      VARCHAR(256),
    record_count BIGINT,
    size_gb      FLOAT,
    created_by   VARCHAR(64),
    created_at   DATETIME     DEFAULT NOW()
);

INSERT INTO dataset_metadata (name, version, s3_path, record_count, size_gb, created_by, created_at) VALUES
('neuro-instruct-v1', '1.0', 's3://neuro-ml-datasets/instruct/v1/', 485000,  8.3,  'm.chen@neuro.ai',    '2026-03-10 11:00:00'),
('neuro-rlhf-pairs',  '1.2', 's3://neuro-ml-datasets/rlhf/v1.2/',  120000,  2.1,  'priya.nair@neuro.ai','2026-04-15 14:22:00'),
('neuro-sft-70b',     '1.0', 's3://neuro-ml-datasets/sft-70b/v1/', 2100000, 44.7, 'svc-deploy',          '2026-05-01 08:00:00');

-- ─── Access control ───────────────────────────────────────────────────────────
-- The MariaDB Docker entrypoint grants ALL PRIVILEGES on neuro_prod.* to
-- MARIADB_USER (neuro_app) before init SQL runs. Revoke that and re-grant
-- SELECT-only so the account reflects a realistic read-only service account posture.
-- Attacker can read all fake data but cannot modify it, keeping schema clean.
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'neuro_app'@'%';
GRANT SELECT ON neuro_prod.* TO 'neuro_app'@'%';
FLUSH PRIVILEGES;
