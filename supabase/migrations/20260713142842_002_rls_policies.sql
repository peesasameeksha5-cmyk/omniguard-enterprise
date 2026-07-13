-- RLS Policies for OmniGuard (anon access for API key auth pattern)

-- organizations: authenticated users read their own orgs
CREATE POLICY "select_own_orgs" ON organizations FOR SELECT
  TO authenticated USING (
    id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  );
CREATE POLICY "insert_orgs" ON organizations FOR INSERT
  TO authenticated WITH CHECK (true);
CREATE POLICY "update_own_orgs" ON organizations FOR UPDATE
  TO authenticated USING (
    id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))
  ) WITH CHECK (true);
CREATE POLICY "delete_own_orgs" ON organizations FOR DELETE
  TO authenticated USING (
    id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role = 'owner')
  );

-- user_profiles
CREATE POLICY "select_own_profile" ON user_profiles FOR SELECT
  TO authenticated USING (id = auth.uid());
CREATE POLICY "insert_own_profile" ON user_profiles FOR INSERT
  TO authenticated WITH CHECK (id = auth.uid());
CREATE POLICY "update_own_profile" ON user_profiles FOR UPDATE
  TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid());
CREATE POLICY "delete_own_profile" ON user_profiles FOR DELETE
  TO authenticated USING (id = auth.uid());

-- organization_members
CREATE POLICY "select_org_members" ON organization_members FOR SELECT
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  );
CREATE POLICY "insert_org_members" ON organization_members FOR INSERT
  TO authenticated WITH CHECK (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))
  );
CREATE POLICY "update_org_members" ON organization_members FOR UPDATE
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))
  ) WITH CHECK (true);
CREATE POLICY "delete_org_members" ON organization_members FOR DELETE
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))
  );

-- repositories
CREATE POLICY "select_repos" ON repositories FOR SELECT
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  );
CREATE POLICY "insert_repos" ON repositories FOR INSERT
  TO authenticated WITH CHECK (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  );
CREATE POLICY "update_repos" ON repositories FOR UPDATE
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin','engineer'))
  ) WITH CHECK (true);
CREATE POLICY "delete_repos" ON repositories FOR DELETE
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))
  );

-- scans
CREATE POLICY "select_scans" ON scans FOR SELECT
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  );
CREATE POLICY "insert_scans" ON scans FOR INSERT
  TO authenticated WITH CHECK (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  );
CREATE POLICY "update_scans" ON scans FOR UPDATE
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  ) WITH CHECK (true);
CREATE POLICY "delete_scans" ON scans FOR DELETE
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))
  );

-- findings
CREATE POLICY "select_findings" ON findings FOR SELECT
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  );
CREATE POLICY "insert_findings" ON findings FOR INSERT
  TO authenticated WITH CHECK (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  );
CREATE POLICY "update_findings" ON findings FOR UPDATE
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  ) WITH CHECK (true);
CREATE POLICY "delete_findings" ON findings FOR DELETE
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))
  );

-- api_keys
CREATE POLICY "select_api_keys" ON api_keys FOR SELECT
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid())
  );
CREATE POLICY "insert_api_keys" ON api_keys FOR INSERT
  TO authenticated WITH CHECK (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))
  );
CREATE POLICY "update_api_keys" ON api_keys FOR UPDATE
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))
  ) WITH CHECK (true);
CREATE POLICY "delete_api_keys" ON api_keys FOR DELETE
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin'))
  );

-- audit_logs
CREATE POLICY "select_audit_logs" ON audit_logs FOR SELECT
  TO authenticated USING (
    org_id IN (SELECT org_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin','auditor'))
  );
CREATE POLICY "insert_audit_logs" ON audit_logs FOR INSERT
  TO authenticated WITH CHECK (true);
CREATE POLICY "update_audit_logs" ON audit_logs FOR UPDATE
  TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "delete_audit_logs" ON audit_logs FOR DELETE
  TO authenticated USING (false);

-- notifications
CREATE POLICY "select_notifications" ON notifications FOR SELECT
  TO authenticated USING (user_id = auth.uid());
CREATE POLICY "insert_notifications" ON notifications FOR INSERT
  TO authenticated WITH CHECK (true);
CREATE POLICY "update_notifications" ON notifications FOR UPDATE
  TO authenticated USING (user_id = auth.uid()) WITH CHECK (true);
CREATE POLICY "delete_notifications" ON notifications FOR DELETE
  TO authenticated USING (user_id = auth.uid());
