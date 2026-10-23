-- CYPHER Phase 1 core schema. Target PostgreSQL 16+ with pgvector available.
CREATE EXTENSION IF NOT EXISTS vector;

DO $$ BEGIN CREATE TYPE cypher_verdict AS ENUM (
 'VULNERABLE_STATE_CHANGE','VULNERABLE_DATA_EXPOSURE','PROTECTED',
 'INCONCLUSIVE_ENVIRONMENT','INCONCLUSIVE_CONTROL','INCONCLUSIVE_AMBIGUOUS','INCONCLUSIVE_FLAKY');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE cypher_vuln_class AS ENUM ('BOLA','IDOR');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE cypher_mutation_kind AS ENUM ('principal','object_id');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE projects (
 id uuid PRIMARY KEY,
 name varchar(160) NOT NULL,
 owner_id uuid NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE users (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 email varchar(320) NOT NULL,
 display_name varchar(160) NOT NULL,
 is_active boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(project_id, email)
);
ALTER TABLE projects ADD CONSTRAINT fk_projects_owner FOREIGN KEY(owner_id) REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE memberships (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 user_id uuid NOT NULL REFERENCES users(id),
 role varchar(16) NOT NULL CHECK(role IN ('admin','reviewer','analyst','viewer')),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(project_id, user_id)
);
CREATE TABLE api_keys (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 user_id uuid NOT NULL REFERENCES users(id),
 key_hash char(64) NOT NULL UNIQUE,
 name varchar(160) NOT NULL,
 role varchar(16) NOT NULL CHECK(role IN ('admin','reviewer','analyst','viewer')),
 expires_at timestamptz NULL,
 revoked_at timestamptz NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE targets (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 name varchar(160) NOT NULL,
 base_url text NOT NULL,
 host_allowlist text[] NOT NULL,
 sandbox_only boolean NOT NULL DEFAULT true CHECK(sandbox_only),
 openapi_spec_ref text NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(project_id, name)
);
CREATE TABLE target_builds (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 target_id uuid NOT NULL REFERENCES targets(id),
 label varchar(24) NOT NULL CHECK(label IN ('vulnerable','fixed','partial_fix','over_blocking','reintroduced','other')),
 git_ref text NOT NULL,
 image_digest varchar(71) NOT NULL CHECK(image_digest ~ '^sha256:[0-9a-f]{64}$'),
 reintroduction_patch_ref text NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE seed_snapshots (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 target_id uuid NOT NULL REFERENCES targets(id),
 content_hash char(64) NOT NULL CHECK(content_hash ~ '^[0-9a-f]{64}$'),
 ownership_map jsonb NOT NULL,
 seed_value bigint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(target_id, content_hash)
);
CREATE TABLE environments (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 target_id uuid NOT NULL REFERENCES targets(id),
 build_id uuid NOT NULL REFERENCES target_builds(id),
 seed_snapshot_id uuid NULL REFERENCES seed_snapshots(id),
 status varchar(16) NOT NULL CHECK(status IN ('creating','seeding','ready','resetting','destroyed','failed')),
 base_url text NOT NULL,
 docker_network_id text NULL,
 container_id text NULL,
 oracle_dsn_ref text NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 destroyed_at timestamptz NULL
);
CREATE TABLE principals (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 target_id uuid NOT NULL REFERENCES targets(id),
 name varchar(120) NOT NULL,
 role varchar(80) NOT NULL,
 credential_ref varchar(240) NOT NULL,
 login_flow jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(target_id, name)
);
CREATE TABLE policy_versions (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 target_id uuid NOT NULL REFERENCES targets(id),
 version integer NOT NULL CHECK(version > 0),
 rules jsonb NOT NULL,
 content_hash char(64) NOT NULL CHECK(content_hash ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(target_id, version)
);
CREATE TABLE capsules (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 title varchar(240) NOT NULL,
 vuln_class cypher_vuln_class NOT NULL,
 created_by uuid NOT NULL REFERENCES users(id),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE capsule_versions (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 capsule_id uuid NOT NULL REFERENCES capsules(id),
 version integer NOT NULL CHECK(version > 0),
 schema_version varchar(16) NOT NULL,
 content jsonb NOT NULL,
 content_hash char(64) NOT NULL CHECK(content_hash ~ '^[0-9a-f]{64}$'),
 authored_by varchar(16) NOT NULL CHECK(authored_by IN ('human','guidance')),
 suggestion_id uuid NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(capsule_id, version), UNIQUE(project_id, content_hash)
);
CREATE TABLE capsule_status_events (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 capsule_version_id uuid NOT NULL REFERENCES capsule_versions(id),
 status varchar(16) NOT NULL CHECK(status IN ('draft','validated','approved','deprecated')),
 actor_id uuid NOT NULL REFERENCES users(id),
 event_seq bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE OR REPLACE VIEW capsule_current_status AS
 SELECT DISTINCT ON (capsule_version_id) project_id,capsule_version_id,status,actor_id,created_at,event_seq
 FROM capsule_status_events ORDER BY capsule_version_id,event_seq DESC;
CREATE TABLE regression_suites (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE regression_suite_runs (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 suite_id uuid NOT NULL REFERENCES regression_suites(id),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE jobs (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 kind varchar(64) NOT NULL,
 state varchar(16) NOT NULL CHECK(state IN ('queued','running','succeeded','failed','cancelled')),
 payload jsonb NOT NULL,
 result_ref text NULL,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts >= 0),
 idempotency_key varchar(128) NULL,
 created_by uuid NULL REFERENCES users(id),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(project_id, kind, idempotency_key)
);
CREATE TABLE replay_runs (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 capsule_version_id uuid NOT NULL REFERENCES capsule_versions(id),
 build_id uuid NOT NULL REFERENCES target_builds(id),
 environment_id uuid NOT NULL REFERENCES environments(id),
 harness_version varchar(64) NOT NULL,
 adjudicator_version varchar(64) NOT NULL,
 repeat_index integer NOT NULL CHECK(repeat_index >= 0),
 seed bigint NOT NULL,
 state varchar(16) NOT NULL CHECK(state IN ('queued','running','succeeded','completed','failed','cancelled')),
 created_at timestamptz NOT NULL DEFAULT now(),
 started_at timestamptz NULL,
 completed_at timestamptz NULL
);
CREATE TABLE observations (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 run_id uuid NOT NULL REFERENCES replay_runs(id),
 step varchar(32) NOT NULL CHECK(step IN ('positive_control','counterfactual')),
 redacted_request jsonb NOT NULL,
 status integer NULL,
 redacted_headers jsonb NOT NULL DEFAULT '{}'::jsonb,
 body_sha256 char(64) NULL,
 evidence_ref char(64) NULL,
 extracted_fields jsonb NOT NULL DEFAULT '{}'::jsonb,
 latency_ms numeric(12,3) NULL CHECK(latency_ms >= 0),
 redaction_report jsonb NOT NULL DEFAULT '{}'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE state_snapshots (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 run_id uuid NOT NULL REFERENCES replay_runs(id),
 phase varchar(8) NOT NULL CHECK(phase IN ('pre','post')),
 probe_name varchar(120) NOT NULL,
 result_sha256 char(64) NOT NULL CHECK(result_sha256 ~ '^[0-9a-f]{64}$'),
 evidence_ref char(64) NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE verdicts (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 run_id uuid NOT NULL REFERENCES replay_runs(id),
 verdict cypher_verdict NOT NULL,
 fired_rules text[] NOT NULL,
 signals jsonb NOT NULL,
 completeness_score numeric(5,4) NOT NULL CHECK(completeness_score BETWEEN 0 AND 1),
 adjudicator_version varchar(64) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 supersedes_verdict_id uuid NULL REFERENCES verdicts(id),
 verdict_seq bigint GENERATED ALWAYS AS IDENTITY,
 UNIQUE(run_id, adjudicator_version)
);
CREATE TABLE suggestions (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 agent varchar(16) NOT NULL CHECK(agent IN ('guidance','history')),
 kind varchar(64) NOT NULL,
 input_hash char(64) NOT NULL,
 model_id varchar(160) NOT NULL,
 prompt_version varchar(160) NOT NULL,
 prompt_hash char(64) NOT NULL,
 raw_output_sha256 char(64) NOT NULL,
 validated_payload jsonb NULL,
 validation_errors jsonb NOT NULL DEFAULT '[]'::jsonb,
 requested_by uuid NOT NULL REFERENCES users(id),
 state varchar(32) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE suggestion_events (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 suggestion_id uuid NOT NULL REFERENCES suggestions(id),
 event_type varchar(32) NOT NULL CHECK(event_type IN ('proposed','rejected_by_validator','pending_review','approved','rejected')),
 actor_id uuid NULL REFERENCES users(id),
 comment text NULL,
 event_seq bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE OR REPLACE VIEW suggestion_current_state AS
 SELECT DISTINCT ON (suggestion_id) project_id,suggestion_id,event_type AS current_state,actor_id,comment,created_at,event_seq
 FROM suggestion_events ORDER BY suggestion_id,event_seq DESC;
CREATE TABLE cases (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 finding_id uuid NOT NULL,
 vuln_class cypher_vuln_class NOT NULL,
 mutation_dimension cypher_mutation_kind NOT NULL,
 http_method varchar(8) NOT NULL,
 resource_type varchar(120) NOT NULL,
 policy_rule_type varchar(120) NOT NULL,
 pattern_summary text NOT NULL,
 fix_pattern text NOT NULL,
 outcome_label varchar(32) NOT NULL CHECK(outcome_label IN ('fix_verified','fix_incomplete','recurred','false_positive','accepted_risk')),
 review_status varchar(16) NOT NULL CHECK(review_status IN ('draft','reviewed','superseded')),
 reviewer_id uuid NULL REFERENCES users(id),
 evidence_ids text[] NOT NULL,
 finding_event_ids uuid[] NOT NULL,
 embedding vector(384) NULL,
 embedding_model varchar(160) NULL,
 search_document tsvector GENERATED ALWAYS AS (to_tsvector('english', coalesce(pattern_summary,'') || ' ' || coalesce(fix_pattern,''))) STORED,
 supersedes_case_id uuid NULL REFERENCES cases(id),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_cases_search ON cases USING gin(search_document);
CREATE INDEX ix_cases_embedding ON cases USING hnsw(embedding vector_cosine_ops);
CREATE TABLE case_links (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 case_id uuid NOT NULL REFERENCES cases(id),
 object_kind varchar(32) NOT NULL,
 object_id uuid NOT NULL,
 evidence_id text NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE experiments (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 name varchar(200) NOT NULL,
 config jsonb NOT NULL,
 state varchar(16) NOT NULL CHECK(state IN ('configured','running','succeeded','failed')),
 ground_truth_hash char(64) NOT NULL,
 manifest_hash char(64) NULL,
 created_by uuid NOT NULL REFERENCES users(id),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE experiment_results (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 experiment_id uuid NOT NULL REFERENCES experiments(id),
 arm varchar(1) NOT NULL CHECK(arm IN ('A','B','C','D','E','F')),
 seed bigint NOT NULL,
 repeat_index integer NOT NULL,
 metrics jsonb NOT NULL,
 manifest jsonb NOT NULL,
 manifest_hash char(64) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(experiment_id, arm, seed, repeat_index)
);
CREATE TABLE cypher_oracle_sentinel (id boolean PRIMARY KEY DEFAULT true);
INSERT INTO cypher_oracle_sentinel(id) VALUES (true) ON CONFLICT DO NOTHING;
CREATE TABLE audit_log (
 seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 actor_id uuid NULL REFERENCES users(id),
 action varchar(160) NOT NULL,
 object_ref varchar(240) NOT NULL,
 payload_sha256 char(64) NOT NULL CHECK(payload_sha256 ~ '^[0-9a-f]{64}$'),
 prev_hash char(64) NOT NULL CHECK(prev_hash ~ '^[0-9a-f]{64}$'),
 hash char(64) NOT NULL CHECK(hash ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only tables store history; current state is reconstructed from events or views.
CREATE OR REPLACE FUNCTION cypher_reject_append_only_mutation() RETURNS trigger AS $$
BEGIN
 RAISE EXCEPTION 'append-only table % rejects %', TG_TABLE_NAME, TG_OP USING ERRCODE='55000';
END; $$ LANGUAGE plpgsql;
DO $$ DECLARE tbl text; BEGIN
 FOREACH tbl IN ARRAY ARRAY['target_builds','seed_snapshots','policy_versions','capsule_versions','capsule_status_events',
 'replay_runs','observations','state_snapshots','verdicts','suggestions','suggestion_events','case_links','experiments','experiment_results','audit_log'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION cypher_reject_append_only_mutation()', 'trg_'||tbl||'_append_only', tbl);
 END LOOP;
END $$;

-- Project RLS. All normal application requests must SET LOCAL app.project_id inside a transaction.
DO $$ DECLARE tbl text; BEGIN
 FOREACH tbl IN ARRAY ARRAY['users','memberships','api_keys','targets','target_builds','seed_snapshots','environments','principals',
 'policy_versions','capsules','capsule_versions','capsule_status_events','regression_suites','regression_suite_runs','jobs',
 'replay_runs','observations','state_snapshots','verdicts','suggestions','suggestion_events','cases','case_links','experiments','experiment_results','audit_log'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
  EXECUTE format('CREATE POLICY %I ON %I USING (project_id = NULLIF(current_setting(''app.project_id'', true), '''')::uuid) WITH CHECK (project_id = NULLIF(current_setting(''app.project_id'', true), '''')::uuid)', 'cypher_scope_'||tbl, tbl);
 END LOOP;
END $$;

-- Projects use id as their tenant key. FORCE prevents the table owner from bypassing RLS.
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
CREATE POLICY cypher_scope_projects ON projects
 USING (id = NULLIF(current_setting('app.project_id', true), '')::uuid)
 WITH CHECK (id = NULLIF(current_setting('app.project_id', true), '')::uuid);

-- Draft cases may be reviewed, but once reviewed their facts cannot be edited in place.
CREATE OR REPLACE FUNCTION cypher_freeze_reviewed_case() RETURNS trigger AS $$
BEGIN
 IF OLD.review_status = 'reviewed' THEN
  RAISE EXCEPTION 'reviewed cases are immutable; create a superseding case' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_cases_freeze_reviewed BEFORE UPDATE ON cases
 FOR EACH ROW EXECUTE FUNCTION cypher_freeze_reviewed_case();

CREATE INDEX ix_replay_runs_project_created ON replay_runs(project_id, created_at DESC, id DESC);
CREATE INDEX ix_observations_run ON observations(project_id, run_id, step);
CREATE INDEX ix_verdicts_latest ON verdicts(project_id, run_id, verdict_seq DESC);
CREATE INDEX ix_suggestions_project_state ON suggestions(project_id, state, created_at DESC);
CREATE INDEX ix_experiment_results_project ON experiment_results(project_id, experiment_id, arm, seed, repeat_index);
