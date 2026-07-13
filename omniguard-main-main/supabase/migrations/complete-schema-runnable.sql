-- =============================================================================
-- OmniGuard — Complete Schema Migration
-- Run this in the Supabase SQL Editor if you need to apply all tables at once.
-- All statements are idempotent (IF NOT EXISTS / ADD COLUMN IF NOT EXISTS).
-- =============================================================================

-- ─── Extensions ───────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS vector;

-- ─── Core tables (from 001_schema) ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS organizations (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name            text NOT NULL,
  slug            text UNIQUE NOT NULL,
  logo_url        text,
  plan            text NOT NULL DEFAULT 'free',
  settings        jsonb DEFAULT '{}',
  ai_config       jsonb DEFAULT '{}',
  ai_keys_vault_id text,
  rate_limits     jsonb DEFAULT '{}',
  created_by      uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at      timestamptz DEFAULT now(),
  updated_at      timestamptz DEFAULT now(),
  deleted_at      timestamptz
);
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

-- Safely add missing columns to existing tables
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS ai_config jsonb DEFAULT '{}';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS ai_keys_vault_id text;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS rate_limits jsonb DEFAULT '{}';

CREATE TABLE IF NOT EXISTS user_profiles (
  id          uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email       text NOT NULL,
  first_name  text,
  last_name   text,
  avatar_url  text,
  preferences jsonb DEFAULT '{}',
  last_login_at timestamptz,
  created_at  timestamptz DEFAULT now(),
  updated_at  timestamptz DEFAULT now()
);
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS organization_members (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role        text NOT NULL DEFAULT 'developer'
              CHECK (role IN ('owner','admin','engineer','developer','auditor')),
  status      text NOT NULL DEFAULT 'active'
              CHECK (status IN ('active','invited','suspended')),
  invited_by  uuid REFERENCES auth.users(id),
  joined_at   timestamptz DEFAULT now(),
  UNIQUE(org_id, user_id)
);
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS repositories (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  name            text NOT NULL,
  full_name       text,
  url             text,
  provider        text DEFAULT 'github' CHECK (provider IN ('github','gitlab','bitbucket','azure','local')),
  default_branch  text DEFAULT 'main',
  is_active       boolean DEFAULT true,
  risk_score      integer DEFAULT 0,
  last_scan_at    timestamptz,
  language        text,
  settings        jsonb DEFAULT '{}',
  created_by      uuid REFERENCES auth.users(id),
  created_at      timestamptz DEFAULT now(),
  updated_at      timestamptz DEFAULT now()
);
ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS risk_score integer DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS last_scan_at timestamptz;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS language text;

CREATE TABLE IF NOT EXISTS scans (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid REFERENCES organizations(id) ON DELETE CASCADE,
  organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  repo_id         uuid REFERENCES repositories(id) ON DELETE SET NULL,
  repository_id   uuid REFERENCES repositories(id) ON DELETE SET NULL,
  triggered_by    uuid REFERENCES auth.users(id),
  status          text NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','running','completed','failed','cancelled')),
  scan_type       text NOT NULL DEFAULT 'full'
                  CHECK (scan_type IN ('full','incremental','file','pr','scheduled','quick','secrets','dependencies','container','dockerfile','terraform','kubernetes','github_actions','azure_pipeline','cloudformation','ansible','helm','yaml','json','config','license','sbom','inventory','policy')),
  branch          text,
  commit_sha      text,
  target_path     text,
  scanners_run    text[] DEFAULT '{}',
  files_scanned   integer DEFAULT 0,
  findings_count  integer DEFAULT 0,
  critical_count  integer DEFAULT 0,
  high_count      integer DEFAULT 0,
  medium_count    integer DEFAULT 0,
  low_count       integer DEFAULT 0,
  duration_ms     integer,
  duration_seconds integer,
  worker_id       text,
  summary         jsonb DEFAULT '{}',
  metadata        jsonb DEFAULT '{}',
  error_message   text,
  started_at      timestamptz,
  completed_at    timestamptz,
  created_at      timestamptz DEFAULT now()
);
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS repository_id uuid REFERENCES repositories(id) ON DELETE SET NULL;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS worker_id text;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS duration_seconds integer;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS summary jsonb DEFAULT '{}';

CREATE TABLE IF NOT EXISTS findings (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                   uuid REFERENCES organizations(id) ON DELETE CASCADE,
  organization_id          uuid REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id                  uuid REFERENCES scans(id) ON DELETE SET NULL,
  repo_id                  uuid REFERENCES repositories(id) ON DELETE SET NULL,
  repository_id            uuid REFERENCES repositories(id) ON DELETE SET NULL,
  rule_id                  text NOT NULL,
  rule_name                text,
  scanner                  text NOT NULL,
  category                 text,
  severity                 text NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  title                    text NOT NULL,
  description              text,
  evidence                 text,
  file_path                text,
  line_start               integer,
  line_end                 integer,
  cwe                      text[],
  owasp                    text[],
  cvss_score               numeric,
  cve_id                   text,
  package_name             text,
  package_version          text,
  status                   text NOT NULL DEFAULT 'open'
                           CHECK (status IN ('open','resolved','suppressed','false_positive')),
  fingerprint              text,
  risk_score               integer DEFAULT 0,
  confidence_score         numeric DEFAULT 0.5,
  false_positive_likelihood numeric DEFAULT 0.5,
  ai_explanation           text,
  ai_summary               text,
  ai_remediation           text,
  ai_provider              text,
  ai_model                 text,
  policy_violations        text[],
  business_impact          text,
  suggested_commit         text,
  finding_references       text[],
  metadata                 jsonb DEFAULT '{}',
  created_at               timestamptz DEFAULT now(),
  updated_at               timestamptz DEFAULT now(),
  resolved_at              timestamptz
);
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS repository_id uuid REFERENCES repositories(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS rule_name text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS category text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS description text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS owasp text[];
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe text[];
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_score numeric;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cve_id text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS package_name text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS package_version text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_score integer DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence_score numeric DEFAULT 0.5;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS false_positive_likelihood numeric DEFAULT 0.5;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_summary text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_provider text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_model text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS policy_violations text[];
ALTER TABLE findings ADD COLUMN IF NOT EXISTS business_impact text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS suggested_commit text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS finding_references text[];
ALTER TABLE findings ADD COLUMN IF NOT EXISTS metadata jsonb DEFAULT '{}';

CREATE TABLE IF NOT EXISTS api_keys (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  name        text NOT NULL,
  key_hash    text NOT NULL UNIQUE,
  key_prefix  text NOT NULL,
  scopes      text[] DEFAULT '{read,write}',
  last_used_at timestamptz,
  expires_at  timestamptz,
  is_active   boolean DEFAULT true,
  created_at  timestamptz DEFAULT now()
);
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS audit_logs (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid REFERENCES organizations(id) ON DELETE SET NULL,
  organization_id uuid REFERENCES organizations(id) ON DELETE SET NULL,
  user_id       uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  action        text NOT NULL,
  resource_type text,
  resource_id   uuid,
  metadata      jsonb DEFAULT '{}',
  ip_address    inet,
  user_agent    text,
  created_at    timestamptz DEFAULT now()
);
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS notifications (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid REFERENCES organizations(id) ON DELETE CASCADE,
  organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  type        text NOT NULL,
  title       text NOT NULL,
  message     text,
  body        text,
  data        jsonb DEFAULT '{}',
  is_read     boolean DEFAULT false,
  created_at  timestamptz DEFAULT now()
);
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS body text;

-- ─── Supporting tables ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS integrations (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider        text NOT NULL,
  status          text NOT NULL DEFAULT 'inactive' CHECK (status IN ('active','inactive','error')),
  config          jsonb DEFAULT '{}',
  last_sync_at    timestamptz,
  created_at      timestamptz DEFAULT now(),
  updated_at      timestamptz DEFAULT now(),
  UNIQUE(organization_id, provider)
);
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS policies (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name            text NOT NULL,
  severity        text DEFAULT 'medium',
  content         jsonb DEFAULT '{}',
  enabled         boolean DEFAULT true,
  compliance_mappings text[],
  tags            text[],
  created_at      timestamptz DEFAULT now(),
  deleted_at      timestamptz
);
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS ai_cache (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cache_key       text UNIQUE NOT NULL,
  organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  provider        text NOT NULL,
  model           text NOT NULL,
  prompt_hash     text NOT NULL,
  response_text   text NOT NULL,
  tokens_used     integer DEFAULT 0,
  hit_count       integer DEFAULT 0,
  expires_at      timestamptz NOT NULL,
  created_at      timestamptz DEFAULT now()
);
ALTER TABLE ai_cache ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS ai_cache_key_idx ON ai_cache(cache_key);
CREATE INDEX IF NOT EXISTS ai_cache_expires_idx ON ai_cache(expires_at);

CREATE TABLE IF NOT EXISTS ai_usage (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id     uuid REFERENCES organizations(id) ON DELETE SET NULL,
  scan_id             uuid REFERENCES scans(id) ON DELETE SET NULL,
  provider            text NOT NULL,
  model               text NOT NULL,
  tier                text NOT NULL,
  prompt_tokens       integer DEFAULT 0,
  completion_tokens   integer DEFAULT 0,
  total_tokens        integer DEFAULT 0,
  cache_hit           boolean DEFAULT false,
  latency_ms          integer DEFAULT 0,
  created_at          timestamptz DEFAULT now()
);
ALTER TABLE ai_usage ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS policy_chunks (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  policy_id       uuid REFERENCES policies(id) ON DELETE CASCADE,
  content         text NOT NULL,
  embedding       vector(1536),
  created_at      timestamptz DEFAULT now()
);
ALTER TABLE policy_chunks ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS scan_artifacts (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id         uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  artifact_type   text NOT NULL,
  filename        text NOT NULL,
  storage_path    text,
  size_bytes      integer DEFAULT 0,
  mime_type       text DEFAULT 'application/json',
  metadata        jsonb DEFAULT '{}',
  created_at      timestamptz DEFAULT now()
);
ALTER TABLE scan_artifacts ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS worker_heartbeats (
  worker_id       text PRIMARY KEY,
  worker_type     text DEFAULT 'scanner',
  status          text DEFAULT 'idle',
  current_scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
  last_heartbeat  timestamptz DEFAULT now()
);
ALTER TABLE worker_heartbeats ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS project_risk_history (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  repository_id   uuid REFERENCES repositories(id) ON DELETE CASCADE,
  scan_id         uuid REFERENCES scans(id) ON DELETE SET NULL,
  score           integer DEFAULT 0,
  factors         jsonb DEFAULT '{}',
  created_at      timestamptz DEFAULT now()
);
ALTER TABLE project_risk_history ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS organization_suppression_rules (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id                 text,
  scanner                 text,
  file_pattern            text,
  false_positive_likelihood numeric DEFAULT 0.5,
  active                  boolean DEFAULT true,
  created_at              timestamptz DEFAULT now()
);
ALTER TABLE organization_suppression_rules ENABLE ROW LEVEL SECURITY;

-- ─── RLS Policies (idempotent — use DO block to skip if exists) ───────────────

DO $$ BEGIN
  -- organizations
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='organizations' AND policyname='select_own_orgs') THEN
    CREATE POLICY "select_own_orgs" ON organizations FOR SELECT TO authenticated
      USING (id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='organizations' AND policyname='insert_orgs') THEN
    CREATE POLICY "insert_orgs" ON organizations FOR INSERT TO authenticated WITH CHECK (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='organizations' AND policyname='update_own_orgs') THEN
    CREATE POLICY "update_own_orgs" ON organizations FOR UPDATE TO authenticated
      USING (id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))) WITH CHECK (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='organizations' AND policyname='delete_own_orgs') THEN
    CREATE POLICY "delete_own_orgs" ON organizations FOR DELETE TO authenticated
      USING (id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role = 'owner'));
  END IF;

  -- user_profiles
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='user_profiles' AND policyname='select_own_profile') THEN
    CREATE POLICY "select_own_profile" ON user_profiles FOR SELECT TO authenticated USING (id = auth.uid());
    CREATE POLICY "insert_own_profile" ON user_profiles FOR INSERT TO authenticated WITH CHECK (id = auth.uid());
    CREATE POLICY "update_own_profile" ON user_profiles FOR UPDATE TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid());
    CREATE POLICY "delete_own_profile" ON user_profiles FOR DELETE TO authenticated USING (id = auth.uid());
  END IF;

  -- organization_members
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='organization_members' AND policyname='select_org_members') THEN
    CREATE POLICY "select_org_members" ON organization_members FOR SELECT TO authenticated
      USING (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
    CREATE POLICY "insert_org_members" ON organization_members FOR INSERT TO authenticated
      WITH CHECK (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));
    CREATE POLICY "update_org_members" ON organization_members FOR UPDATE TO authenticated
      USING (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))) WITH CHECK (true);
    CREATE POLICY "delete_org_members" ON organization_members FOR DELETE TO authenticated
      USING (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));
  END IF;

  -- scans
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='scans' AND policyname='select_scans') THEN
    CREATE POLICY "select_scans" ON scans FOR SELECT TO authenticated
      USING (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
          OR organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
    CREATE POLICY "insert_scans" ON scans FOR INSERT TO authenticated WITH CHECK (true);
    CREATE POLICY "update_scans" ON scans FOR UPDATE TO authenticated USING (true) WITH CHECK (true);
    CREATE POLICY "delete_scans" ON scans FOR DELETE TO authenticated USING (true);
    CREATE POLICY "service_role_scans" ON scans FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  -- findings
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='findings' AND policyname='select_findings') THEN
    CREATE POLICY "select_findings" ON findings FOR SELECT TO authenticated
      USING (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
          OR organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
    CREATE POLICY "insert_findings" ON findings FOR INSERT TO authenticated WITH CHECK (true);
    CREATE POLICY "update_findings" ON findings FOR UPDATE TO authenticated USING (true) WITH CHECK (true);
    CREATE POLICY "delete_findings" ON findings FOR DELETE TO authenticated USING (true);
    CREATE POLICY "service_role_findings" ON findings FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  -- api_keys
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='api_keys' AND policyname='select_api_keys') THEN
    CREATE POLICY "select_api_keys" ON api_keys FOR SELECT TO authenticated
      USING (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
    CREATE POLICY "insert_api_keys" ON api_keys FOR INSERT TO authenticated
      WITH CHECK (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));
    CREATE POLICY "update_api_keys" ON api_keys FOR UPDATE TO authenticated
      USING (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))) WITH CHECK (true);
    CREATE POLICY "delete_api_keys" ON api_keys FOR DELETE TO authenticated
      USING (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));
  END IF;

  -- audit_logs
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='audit_logs' AND policyname='select_audit_logs') THEN
    CREATE POLICY "select_audit_logs" ON audit_logs FOR SELECT TO authenticated
      USING (org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin','auditor')));
    CREATE POLICY "insert_audit_logs" ON audit_logs FOR INSERT TO authenticated WITH CHECK (true);
    CREATE POLICY "update_audit_logs" ON audit_logs FOR UPDATE TO authenticated USING (false) WITH CHECK (false);
    CREATE POLICY "delete_audit_logs" ON audit_logs FOR DELETE TO authenticated USING (false);
    CREATE POLICY "service_role_audit" ON audit_logs FOR ALL TO service_role USING (true) WITH CHECK (true);
  END IF;

  -- notifications
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='notifications' AND policyname='select_notifications') THEN
    CREATE POLICY "select_notifications" ON notifications FOR SELECT TO authenticated USING (user_id = auth.uid());
    CREATE POLICY "insert_notifications" ON notifications FOR INSERT TO authenticated WITH CHECK (true);
    CREATE POLICY "update_notifications" ON notifications FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (true);
    CREATE POLICY "delete_notifications" ON notifications FOR DELETE TO authenticated USING (user_id = auth.uid());
  END IF;

  -- integrations
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='integrations' AND policyname='select_integrations') THEN
    CREATE POLICY "select_integrations" ON integrations FOR SELECT TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
    CREATE POLICY "insert_integrations" ON integrations FOR INSERT TO authenticated
      WITH CHECK (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));
    CREATE POLICY "update_integrations" ON integrations FOR UPDATE TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))) WITH CHECK (true);
    CREATE POLICY "delete_integrations" ON integrations FOR DELETE TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));
  END IF;

  -- policies
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='policies' AND policyname='select_policies') THEN
    CREATE POLICY "select_policies" ON policies FOR SELECT TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
    CREATE POLICY "insert_policies" ON policies FOR INSERT TO authenticated
      WITH CHECK (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin','engineer')));
    CREATE POLICY "update_policies" ON policies FOR UPDATE TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin','engineer'))) WITH CHECK (true);
    CREATE POLICY "delete_policies" ON policies FOR DELETE TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));
  END IF;

  -- service role bypass for AI pipeline tables
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='ai_cache' AND policyname='service_role_ai_cache') THEN
    CREATE POLICY "service_role_ai_cache" ON ai_cache FOR ALL TO service_role USING (true) WITH CHECK (true);
    CREATE POLICY "service_role_ai_usage" ON ai_usage FOR ALL TO service_role USING (true) WITH CHECK (true);
    CREATE POLICY "service_role_policy_chunks" ON policy_chunks FOR ALL TO service_role USING (true) WITH CHECK (true);
    CREATE POLICY "service_role_scan_artifacts" ON scan_artifacts FOR ALL TO service_role USING (true) WITH CHECK (true);
    CREATE POLICY "service_role_heartbeats" ON worker_heartbeats FOR ALL TO service_role USING (true) WITH CHECK (true);
    CREATE POLICY "service_role_risk_history" ON project_risk_history FOR ALL TO service_role USING (true) WITH CHECK (true);
    CREATE POLICY "service_role_suppression" ON organization_suppression_rules FOR ALL TO service_role USING (true) WITH CHECK (true);
    CREATE POLICY "select_ai_usage" ON ai_usage FOR SELECT TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));
    CREATE POLICY "select_policy_chunks" ON policy_chunks FOR SELECT TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
    CREATE POLICY "select_scan_artifacts" ON scan_artifacts FOR SELECT TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
    CREATE POLICY "select_risk_history" ON project_risk_history FOR SELECT TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
    CREATE POLICY "select_suppression" ON organization_suppression_rules FOR SELECT TO authenticated
      USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
  END IF;
END $$;

-- ─── Functions ────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION match_policy_chunks(
  p_org_id uuid, query_embedding vector(1536), match_count int DEFAULT 3
) RETURNS TABLE (id uuid, content text, similarity float) LANGUAGE plpgsql AS $$
BEGIN
  RETURN QUERY
  SELECT pc.id, pc.content, 1 - (pc.embedding <=> query_embedding) AS similarity
  FROM policy_chunks pc
  WHERE pc.organization_id = p_org_id AND pc.embedding IS NOT NULL
  ORDER BY pc.embedding <=> query_embedding LIMIT match_count;
END;
$$;

CREATE OR REPLACE FUNCTION check_rate_limit(p_key text, p_window_seconds int, p_max_count int)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE current_count int;
BEGIN
  SELECT COUNT(*) INTO current_count FROM audit_logs
  WHERE metadata->>'rate_key' = p_key
    AND created_at > NOW() - (p_window_seconds || ' seconds')::interval;
  IF current_count >= p_max_count THEN RETURN false; END IF;
  INSERT INTO audit_logs (action, metadata) VALUES ('rate_limit_check', jsonb_build_object('rate_key', p_key));
  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION claim_next_scan(p_worker_id text)
RETURNS TABLE(scan_id uuid, repository_id uuid, organization_id uuid) LANGUAGE plpgsql AS $$
DECLARE claimed_scan scans%ROWTYPE;
BEGIN
  SELECT * INTO claimed_scan FROM scans WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN RETURN; END IF;
  UPDATE scans SET status = 'running', worker_id = p_worker_id, started_at = NOW() WHERE id = claimed_scan.id;
  RETURN QUERY SELECT claimed_scan.id, claimed_scan.repo_id, claimed_scan.org_id;
END;
$$;

-- ─── Realtime ────────────────────────────────────────────────────────────────
-- (Run each line individually if ALTER PUBLICATION fails — some tables may already be subscribed)
ALTER PUBLICATION supabase_realtime ADD TABLE scans;
ALTER PUBLICATION supabase_realtime ADD TABLE findings;
ALTER PUBLICATION supabase_realtime ADD TABLE notifications;
ALTER PUBLICATION supabase_realtime ADD TABLE ai_usage;
