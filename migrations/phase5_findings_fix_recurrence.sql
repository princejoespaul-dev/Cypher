-- CYPHER Phase 5 schema extension.
-- Apply only after Phase 1-4 base tables exist. The Alembic revision in this
-- package wraps these statements; its parent revision must be wired to the real
-- Phase 4 revision ID from the integrating repository.

CREATE TABLE IF NOT EXISTS findings (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    fingerprint char(64) NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    capsule_id uuid NOT NULL REFERENCES capsules(id),
    first_seen_build_id uuid NOT NULL REFERENCES target_builds(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE findings ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS finding_events (
    id uuid PRIMARY KEY,
    event_seq bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    project_id uuid NOT NULL REFERENCES projects(id),
    finding_id uuid NOT NULL REFERENCES findings(id),
    event_type varchar(32) NOT NULL CHECK (event_type IN ('open', 'fixed_verified', 'reintroduced')),
    actor_id uuid NULL REFERENCES users(id),
    run_id uuid NULL REFERENCES replay_runs(id),
    related_run_ids uuid[] NOT NULL DEFAULT '{}',
    fix_verification_id uuid NULL,
    suite_run_id uuid NULL REFERENCES regression_suite_runs(id),
    build_id uuid NULL REFERENCES target_builds(id),
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS event_seq bigint GENERATED ALWAYS AS IDENTITY;
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS related_run_ids uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS details jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS fix_verification_id uuid NULL;
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS suite_run_id uuid NULL;
ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS build_id uuid NULL;

CREATE TABLE IF NOT EXISTS fix_verifications (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    fingerprint char(64) NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    capsule_version_id uuid NOT NULL REFERENCES capsule_versions(id),
    vulnerable_build_id uuid NOT NULL REFERENCES target_builds(id),
    fixed_build_id uuid NOT NULL REFERENCES target_builds(id),
    vulnerable_run_id uuid NOT NULL REFERENCES replay_runs(id),
    fixed_run_id uuid NOT NULL REFERENCES replay_runs(id),
    outcome varchar(32) NOT NULL CHECK (outcome IN ('FIX_VERIFIED', 'FIX_INCOMPLETE', 'FIX_BREAKS_CONTROL', 'FIX_UNVERIFIABLE')),
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_fix_verification_distinct_runs CHECK (vulnerable_run_id <> fixed_run_id)
);

ALTER TABLE fix_verifications ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE fix_verifications ADD COLUMN IF NOT EXISTS vulnerable_build_id uuid NULL REFERENCES target_builds(id);
ALTER TABLE fix_verifications ADD COLUMN IF NOT EXISTS fixed_build_id uuid NULL REFERENCES target_builds(id);
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM fix_verifications WHERE vulnerable_build_id IS NULL OR fixed_build_id IS NULL) THEN
        -- One-time schema backfill only; application paths remain append-only.
        ALTER TABLE fix_verifications DISABLE TRIGGER USER;
        UPDATE fix_verifications fv
        SET vulnerable_build_id = vr.build_id
        FROM replay_runs vr
        WHERE fv.vulnerable_run_id = vr.id AND fv.vulnerable_build_id IS NULL;
        UPDATE fix_verifications fv
        SET fixed_build_id = fr.build_id
        FROM replay_runs fr
        WHERE fv.fixed_run_id = fr.id AND fv.fixed_build_id IS NULL;
        ALTER TABLE fix_verifications ENABLE TRIGGER USER;
    END IF;
END $$;
ALTER TABLE fix_verifications ALTER COLUMN vulnerable_build_id SET NOT NULL;
ALTER TABLE fix_verifications ALTER COLUMN fixed_build_id SET NOT NULL;

-- Phase 1 adds the suite tables; Phase 5 fills in fields used by the finished workflow.
ALTER TABLE regression_suites
    ADD COLUMN IF NOT EXISTS name varchar(160) NOT NULL DEFAULT 'Imported regression suite';
ALTER TABLE regression_suites
    ADD COLUMN IF NOT EXISTS created_by uuid NULL REFERENCES users(id);
ALTER TABLE regression_suites
    ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE regression_suite_runs
    ADD COLUMN IF NOT EXISTS build_id uuid NULL REFERENCES target_builds(id);
ALTER TABLE regression_suite_runs
    ADD COLUMN IF NOT EXISTS state varchar(16) NOT NULL DEFAULT 'queued';
ALTER TABLE regression_suite_runs
    ADD COLUMN IF NOT EXISTS failed boolean NOT NULL DEFAULT false;
ALTER TABLE regression_suite_runs
    ADD COLUMN IF NOT EXISTS run_ids uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE regression_suite_runs
    ADD COLUMN IF NOT EXISTS created_by uuid NULL REFERENCES users(id);
ALTER TABLE regression_suite_runs
    ADD COLUMN IF NOT EXISTS started_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE regression_suite_runs
    ADD COLUMN IF NOT EXISTS completed_at timestamptz NULL;
ALTER TABLE regression_suite_runs
    ADD COLUMN IF NOT EXISTS error_code varchar(96) NULL;
ALTER TABLE regression_suite_runs
    ADD COLUMN IF NOT EXISTS error_message text NULL;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS project_id uuid;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM findings WHERE project_id IS NULL) THEN
        -- Tenant-scope backfill for legacy rows before append-only enforcement is used.
        ALTER TABLE findings DISABLE TRIGGER USER;
        UPDATE findings f
        SET project_id = c.project_id
        FROM capsules c
        WHERE f.capsule_id = c.id AND f.project_id IS NULL;
        ALTER TABLE findings ENABLE TRIGGER USER;
    END IF;
END $$;
ALTER TABLE findings ALTER COLUMN project_id SET NOT NULL;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_cases_finding') THEN
        ALTER TABLE cases ADD CONSTRAINT fk_cases_finding FOREIGN KEY (finding_id) REFERENCES findings(id);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS regression_suite_capsules (
    project_id uuid NOT NULL REFERENCES projects(id),
    suite_id uuid NOT NULL REFERENCES regression_suites(id),
    capsule_version_id uuid NOT NULL REFERENCES capsule_versions(id),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (suite_id, capsule_version_id),
    UNIQUE (suite_id, ordinal)
);

-- Support immutable re-adjudication rows while preserving every earlier verdict.
-- The plan requires project_id on every row; derive it from the owning run for legacy rows.
ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS project_id uuid;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM verdicts WHERE project_id IS NULL) THEN
        -- This is a one-time tenant-scope backfill during migration, not an application UPDATE path.
        ALTER TABLE verdicts DISABLE TRIGGER USER;
        UPDATE verdicts v
        SET project_id = c.project_id
        FROM replay_runs rr
        JOIN capsule_versions cv ON cv.id = rr.capsule_version_id
        JOIN capsules c ON c.id = cv.capsule_id
        WHERE v.run_id = rr.id AND v.project_id IS NULL;
        ALTER TABLE verdicts ENABLE TRIGGER USER;
    END IF;
END $$;
ALTER TABLE verdicts ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS supersedes_verdict_id uuid NULL REFERENCES verdicts(id);
ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS verdict_seq bigint GENERATED ALWAYS AS IDENTITY;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_finding_events_fix_verification') THEN
        ALTER TABLE finding_events ADD CONSTRAINT fk_finding_events_fix_verification
            FOREIGN KEY (fix_verification_id) REFERENCES fix_verifications(id);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION cypher_reject_append_only_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'append-only table % rejects %', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_findings_append_only') THEN
        CREATE TRIGGER trg_findings_append_only BEFORE UPDATE OR DELETE ON findings
        FOR EACH ROW EXECUTE FUNCTION cypher_reject_append_only_mutation();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_finding_events_append_only') THEN
        CREATE TRIGGER trg_finding_events_append_only BEFORE UPDATE OR DELETE ON finding_events
        FOR EACH ROW EXECUTE FUNCTION cypher_reject_append_only_mutation();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fix_verifications_append_only') THEN
        CREATE TRIGGER trg_fix_verifications_append_only BEFORE UPDATE OR DELETE ON fix_verifications
        FOR EACH ROW EXECUTE FUNCTION cypher_reject_append_only_mutation();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_regression_suite_capsules_append_only') THEN
        CREATE TRIGGER trg_regression_suite_capsules_append_only BEFORE UPDATE OR DELETE ON regression_suite_capsules
        FOR EACH ROW EXECUTE FUNCTION cypher_reject_append_only_mutation();
    END IF;
END $$;

CREATE OR REPLACE VIEW finding_current_state AS
SELECT DISTINCT ON (finding_id)
       project_id, finding_id, event_type AS current_state, event_seq, created_at
FROM finding_events
ORDER BY finding_id, event_seq DESC;

-- Row-level security is scoped by the app's transaction-local app.project_id.
DO $$
DECLARE tbl text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['findings', 'finding_events', 'fix_verifications', 'regression_suite_capsules', 'verdicts'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', 'cypher_project_scope_' || tbl, tbl);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (project_id = NULLIF(current_setting(''app.project_id'', true), '''')::uuid) WITH CHECK (project_id = NULLIF(current_setting(''app.project_id'', true), '''')::uuid)',
            'cypher_project_scope_' || tbl, tbl
        );
    END LOOP;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_project_fingerprint_idx ON findings (project_id, fingerprint);
CREATE INDEX IF NOT EXISTS ix_verdicts_run_seq ON verdicts (run_id, verdict_seq DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_verdict_run_adjudicator_version ON verdicts (run_id, adjudicator_version);
CREATE INDEX IF NOT EXISTS ix_finding_events_finding_seq ON finding_events (finding_id, event_seq DESC);
CREATE INDEX IF NOT EXISTS ix_fix_verifications_fingerprint ON fix_verifications (project_id, fingerprint, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_regression_suite_runs_project_created ON regression_suite_runs (project_id, started_at DESC);
