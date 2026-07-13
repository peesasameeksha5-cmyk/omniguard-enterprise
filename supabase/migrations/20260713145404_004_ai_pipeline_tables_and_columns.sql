-- Add ai_config and ai_keys_vault_id to organizations
ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS ai_config jsonb DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS ai_keys_vault_id text,
  ADD COLUMN IF NOT EXISTS rate_limits jsonb DEFAULT '{}';

-- Repositories supporting columns
ALTER TABLE repositories
  ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS risk_score integer DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_scan_at timestamptz,
  ADD COLUMN IF NOT EXISTS language text;

-- Findings extended schema
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS repository_id uuid REFERENCES repositories(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS rule_name text,
  ADD COLUMN IF NOT EXISTS category text,
  ADD COLUMN IF NOT EXISTS description text,
  ADD COLUMN IF NOT EXISTS owasp text[],
  ADD COLUMN IF NOT EXISTS cwe text[],
  ADD COLUMN IF NOT EXISTS cvss_score numeric,
  ADD COLUMN IF NOT EXISTS cve_id text,
  ADD COLUMN IF NOT EXISTS package_name text,
  ADD COLUMN IF NOT EXISTS package_version text,
  ADD COLUMN IF NOT EXISTS risk_score integer DEFAULT 0,
  ADD COLUMN IF NOT EXISTS confidence_score numeric DEFAULT 0.5,
  ADD COLUMN IF NOT EXISTS false_positive_likelihood numeric DEFAULT 0.5,
  ADD COLUMN IF NOT EXISTS ai_summary text,
  ADD COLUMN IF NOT EXISTS ai_provider text,
  ADD COLUMN IF NOT EXISTS ai_model text,
  ADD COLUMN IF NOT EXISTS policy_violations text[],
  ADD COLUMN IF NOT EXISTS business_impact text,
  ADD COLUMN IF NOT EXISTS suggested_commit text,
  ADD COLUMN IF NOT EXISTS finding_references text[],
  ADD COLUMN IF NOT EXISTS metadata jsonb DEFAULT '{}';

-- Scans extended schema
ALTER TABLE scans
  ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS repository_id uuid REFERENCES repositories(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS worker_id text,
  ADD COLUMN IF NOT EXISTS duration_seconds integer,
  ADD COLUMN IF NOT EXISTS summary jsonb DEFAULT '{}';

-- Integrations
CREATE TABLE IF NOT EXISTS integrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider text NOT NULL,
  status text NOT NULL DEFAULT 'inactive' CHECK (status IN ('active','inactive','error')),
  config jsonb DEFAULT '{}',
  last_sync_at timestamptz,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  UNIQUE(organization_id, provider)
);
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_integrations" ON integrations FOR SELECT TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
CREATE POLICY "insert_integrations" ON integrations FOR INSERT TO authenticated
  WITH CHECK (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));
CREATE POLICY "update_integrations" ON integrations FOR UPDATE TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))) WITH CHECK (true);
CREATE POLICY "delete_integrations" ON integrations FOR DELETE TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));

-- Custom scan policies
CREATE TABLE IF NOT EXISTS policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL,
  severity text DEFAULT 'medium',
  content jsonb DEFAULT '{}',
  enabled boolean DEFAULT true,
  compliance_mappings text[],
  tags text[],
  created_at timestamptz DEFAULT now(),
  deleted_at timestamptz
);
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_policies" ON policies FOR SELECT TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));
CREATE POLICY "insert_policies" ON policies FOR INSERT TO authenticated
  WITH CHECK (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin','engineer')));
CREATE POLICY "update_policies" ON policies FOR UPDATE TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin','engineer'))) WITH CHECK (true);
CREATE POLICY "delete_policies" ON policies FOR DELETE TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));

-- AI cache (7-day prompt deduplication)
CREATE TABLE IF NOT EXISTS ai_cache (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cache_key text UNIQUE NOT NULL,
  organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  provider text NOT NULL,
  model text NOT NULL,
  prompt_hash text NOT NULL,
  response_text text NOT NULL,
  tokens_used integer DEFAULT 0,
  hit_count integer DEFAULT 0,
  expires_at timestamptz NOT NULL,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE ai_cache ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_role_ai_cache" ON ai_cache FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE INDEX IF NOT EXISTS ai_cache_key_idx ON ai_cache(cache_key);
CREATE INDEX IF NOT EXISTS ai_cache_expires_idx ON ai_cache(expires_at);

-- AI usage metering
CREATE TABLE IF NOT EXISTS ai_usage (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid REFERENCES organizations(id) ON DELETE SET NULL,
  scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
  provider text NOT NULL,
  model text NOT NULL,
  tier text NOT NULL,
  prompt_tokens integer DEFAULT 0,
  completion_tokens integer DEFAULT 0,
  total_tokens integer DEFAULT 0,
  cache_hit boolean DEFAULT false,
  latency_ms integer DEFAULT 0,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE ai_usage ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_role_ai_usage" ON ai_usage FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "select_own_ai_usage" ON ai_usage FOR SELECT TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin')));

-- Policy chunks for RAG (vector search)
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS policy_chunks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  policy_id uuid REFERENCES policies(id) ON DELETE CASCADE,
  content text NOT NULL,
  embedding vector(1536),
  created_at timestamptz DEFAULT now()
);
ALTER TABLE policy_chunks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_role_policy_chunks" ON policy_chunks FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "select_policy_chunks" ON policy_chunks FOR SELECT TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));

-- Scan artifacts (SBOM, dependency tree)
CREATE TABLE IF NOT EXISTS scan_artifacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  artifact_type text NOT NULL,
  filename text NOT NULL,
  storage_path text,
  size_bytes integer DEFAULT 0,
  mime_type text DEFAULT 'application/json',
  metadata jsonb DEFAULT '{}',
  created_at timestamptz DEFAULT now()
);
ALTER TABLE scan_artifacts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_role_scan_artifacts" ON scan_artifacts FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "select_scan_artifacts" ON scan_artifacts FOR SELECT TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));

-- Worker heartbeats
CREATE TABLE IF NOT EXISTS worker_heartbeats (
  worker_id text PRIMARY KEY,
  worker_type text DEFAULT 'scanner',
  status text DEFAULT 'idle',
  current_scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
  last_heartbeat timestamptz DEFAULT now()
);
ALTER TABLE worker_heartbeats ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_role_heartbeats" ON worker_heartbeats FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Project risk history
CREATE TABLE IF NOT EXISTS project_risk_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  repository_id uuid REFERENCES repositories(id) ON DELETE CASCADE,
  scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
  score integer DEFAULT 0,
  factors jsonb DEFAULT '{}',
  created_at timestamptz DEFAULT now()
);
ALTER TABLE project_risk_history ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_role_risk_history" ON project_risk_history FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "select_risk_history" ON project_risk_history FOR SELECT TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));

-- Suppression rules
CREATE TABLE IF NOT EXISTS organization_suppression_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id text,
  scanner text,
  file_pattern text,
  false_positive_likelihood numeric DEFAULT 0.5,
  active boolean DEFAULT true,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE organization_suppression_rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_role_suppression" ON organization_suppression_rules FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "select_suppression" ON organization_suppression_rules FOR SELECT TO authenticated
  USING (organization_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid()));

-- match_policy_chunks RPC for vector similarity search
CREATE OR REPLACE FUNCTION match_policy_chunks(
  p_org_id uuid,
  query_embedding vector(1536),
  match_count int DEFAULT 3
)
RETURNS TABLE (id uuid, content text, similarity float)
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT pc.id, pc.content, 1 - (pc.embedding <=> query_embedding) AS similarity
  FROM policy_chunks pc
  WHERE pc.organization_id = p_org_id
    AND pc.embedding IS NOT NULL
  ORDER BY pc.embedding <=> query_embedding
  LIMIT match_count;
END;
$$;

-- check_rate_limit RPC
CREATE OR REPLACE FUNCTION check_rate_limit(
  p_key text,
  p_window_seconds int,
  p_max_count int
)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
  current_count int;
BEGIN
  SELECT COUNT(*) INTO current_count
  FROM audit_logs
  WHERE metadata->>'rate_key' = p_key
    AND created_at > NOW() - (p_window_seconds || ' seconds')::interval;
  IF current_count >= p_max_count THEN RETURN false; END IF;
  INSERT INTO audit_logs (action, metadata) VALUES ('rate_limit_check', jsonb_build_object('rate_key', p_key));
  RETURN true;
END;
$$;

-- claim_next_scan RPC for scan-worker
CREATE OR REPLACE FUNCTION claim_next_scan(p_worker_id text)
RETURNS TABLE(scan_id uuid, repository_id uuid, organization_id uuid)
LANGUAGE plpgsql
AS $$
DECLARE
  claimed_scan scans%ROWTYPE;
BEGIN
  SELECT * INTO claimed_scan FROM scans
  WHERE status = 'queued'
  ORDER BY created_at ASC
  LIMIT 1
  FOR UPDATE SKIP LOCKED;

  IF NOT FOUND THEN RETURN; END IF;

  UPDATE scans SET status = 'running', worker_id = p_worker_id, started_at = NOW()
  WHERE id = claimed_scan.id;

  RETURN QUERY SELECT claimed_scan.id, claimed_scan.repo_id, claimed_scan.org_id;
END;
$$;

-- Enable realtime on new tables
ALTER PUBLICATION supabase_realtime ADD TABLE ai_usage;
