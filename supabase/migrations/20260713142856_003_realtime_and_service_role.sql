-- Service role bypass for CLI daemon sync
-- The daemon uses the service role key for inserting scan results

-- Allow service role full access (bypasses RLS by default, but explicit for clarity)
-- Also allow anon inserts for scans/findings when using API key auth pattern
CREATE POLICY "service_role_scans" ON scans FOR ALL
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_findings" ON findings FOR ALL
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_audit" ON audit_logs FOR ALL
  TO service_role USING (true) WITH CHECK (true);

-- Realtime publication for dashboard updates
ALTER PUBLICATION supabase_realtime ADD TABLE scans;
ALTER PUBLICATION supabase_realtime ADD TABLE findings;
ALTER PUBLICATION supabase_realtime ADD TABLE notifications;
