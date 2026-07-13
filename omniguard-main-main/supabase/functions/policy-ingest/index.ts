import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";
import { callAI, getAIConfig, getEnvAIConfig } from "../_shared/ai.ts";

/**
 * Policy Ingest â€” processes uploaded documents (PDF, DOCX, MD, TXT, HTML)
 * into policy records with embeddings for RAG-based policy evaluation.
 *
 * POST with JSON: { policy_id, organization_id } â€” generates embeddings for existing policy
 * POST with FormData: file + organization_id â€” extracts text, creates policy + embeddings
 */

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey" };
const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { autoRefreshToken: false, persistSession: false } });

async function verifyAuth(h: string | null): Promise<{ valid: boolean; orgId?: string; userId?: string }> {
  if (!h?.startsWith("Bearer ")) return { valid: false };
  const t = h.slice(7);
  if (t.split(".").length === 3) {
    const { data: { user } } = await supa.auth.getUser(t);
    if (!user) return { valid: false };
    const { data: m } = await supa.from("organization_members").select("organization_id").eq("user_id", user.id).eq("status", "active").limit(1).maybeSingle();
    return { valid: true, orgId: m?.organization_id, userId: user.id };
  }
  return { valid: false };
}

function chunkText(text: string, chunkSize = 500, overlap = 100): string[] {
  const chunks: string[] = []; const words = text.split(/\s+/);
  for (let i = 0; i < words.length; i += chunkSize - overlap) {
    const chunk = words.slice(i, i + chunkSize).join(" ");
    if (chunk.trim().length > 50) chunks.push(chunk.trim());
  }
  return chunks;
}

async function generateEmbedding(text: string, aiCfg: ReturnType<typeof getAIConfig>): Promise<number[] | null> {
  // Use OpenAI embeddings if available
  const openaiKey = aiCfg.openai_api_key || Deno.env.get("OPENAI_API_KEY");
  if (openaiKey) {
    try {
      const r = await fetch("https://api.openai.com/v1/embeddings", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${openaiKey}` }, body: JSON.stringify({ model: "text-embedding-3-small", input: text.slice(0, 8000) }), signal: AbortSignal.timeout(15_000) });
      if (r.ok) { const d = await r.json(); return d.data?.[0]?.embedding || null }
    } catch { /* fall through */ }
  }
  return null; // No embedding provider available
}

async function generateStructuredPolicyRules(text: string, aiCfg: ReturnType<typeof getAIConfig>): Promise<Array<Record<string, unknown>>> {
  const prompt = `Extract enforceable application-security policy requirements from this document.
Return JSON only: {"rules":[{"id":"short-stable-id","title":"...","severity":"critical|high|medium|low|info","pattern":"case-insensitive regex that can match code/config evidence","file_glob":"optional path hint","remediation":"specific remediation","compliance":["OWASP","SOC2","ISO 27001","PCI DSS","HIPAA","GDPR","NIST","CIS"]}]}
Only include rules that can be evaluated against source code, dependencies, IaC, CI/CD, or configuration. Limit to 25 high-signal rules.

Document:
${text.slice(0, 18000)}`;
  const res = await callAI(aiCfg, prompt, "medium", { maxTokens: 1800, skipCache: true });
  if (!res?.text) return [];
  try {
    const match = res.text.match(/\{[\s\S]*\}/);
    const parsed = match ? JSON.parse(match[0]) : JSON.parse(res.text);
    return Array.isArray(parsed.rules) ? parsed.rules.filter((r: Record<string, unknown>) => typeof r.pattern === "string" && typeof r.title === "string") : [];
  } catch {
    return [];
  }
}

async function extractTextFromDocument(file: File): Promise<string> {
  const lower = file.name.toLowerCase();
  if (lower.endsWith(".pdf")) {
    const pdfParse = (await import("npm:pdf-parse@1.1.1")).default;
    const parsed = await pdfParse(new Uint8Array(await file.arrayBuffer()));
    return String(parsed.text ?? "").replace(/\s+/g, " ").trim();
  }
  if (lower.endsWith(".docx")) {
    const mammoth = await import("npm:mammoth@1.9.0");
    const parsed = await mammoth.extractRawText({ arrayBuffer: await file.arrayBuffer() });
    return String(parsed.value ?? "").replace(/\s+/g, " ").trim();
  }
  const text = await file.text();
  // Strip HTML tags
  if (lower.endsWith(".html") || lower.endsWith(".htm")) {
    return text.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  }
  // Markdown â€” strip formatting
  if (lower.endsWith(".md")) {
    return text.replace(/#{1,6}\s/g, "").replace(/\*{1,2}([^*]+)\*{1,2}/g, "$1").replace(/`{1,3}[^`]*`{1,3}/g, "").trim();
  }
  return text;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: cors });
  if (req.method !== "POST") return new Response(JSON.stringify({ error: "POST required" }), { status: 405, headers: { ...cors, "Content-Type": "application/json" } });

  const auth = await verifyAuth(req.headers.get("Authorization"));
  if (!auth.valid) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { ...cors, "Content-Type": "application/json" } });

  const orgId = auth.orgId!;
  const { data: org } = await supa.from("organizations").select("ai_config").eq("id", orgId).single();
  const aiCfg = Object.keys((org?.ai_config as Record<string, unknown>) || {}).length > 1 ? getAIConfig(org!.ai_config as Record<string, unknown>) : getEnvAIConfig();

  const contentType = req.headers.get("Content-Type") || "";

  // Handle FormData file upload
  if (contentType.includes("multipart/form-data")) {
    const fd = await req.formData();
    const file = fd.get("file") as File | null;
    if (!file) return new Response(JSON.stringify({ error: "file required" }), { status: 400, headers: { ...cors, "Content-Type": "application/json" } });

    // Extract text from document
    const text = await extractTextFromDocument(file);
    if (text.length < 50) return new Response(JSON.stringify({ error: "Could not extract text from document" }), { status: 400, headers: { ...cors, "Content-Type": "application/json" } });

    // Use AI to generate a title and summary
    const summaryRes = await callAI(aiCfg, `You are reading a security document titled "${file.name}". Summarize it in one sentence and suggest a policy title. Return JSON: {"title":"...","summary":"..."}`, "fast", { maxTokens: 200 });
    let title = file.name.replace(/\.\w+$/, ""); let description = "";
    if (summaryRes) { try { const p = JSON.parse(summaryRes.text.match(/\{[^}]+\}/)?.[0] || "{}"); title = p.title || title; description = p.summary || "" } catch { /* ok */ } }
    const structuredRules = await generateStructuredPolicyRules(text, aiCfg);
    const sourceType = file.name.split(".").pop()?.toLowerCase() || "txt";

    // Create policy record â€” using actual schema columns
    const { data: policy, error: pErr } = await supa.from("policies").insert({
      organization_id: orgId,
      created_by: auth.userId || null,
      name: title,
      description,
      content: JSON.stringify({ document_text: text.slice(0, 50000), rules: structuredRules }),
      policy_type: ["pdf", "docx", "html"].includes(sourceType) ? sourceType : sourceType === "md" ? "markdown" : "txt",
      source_document_type: sourceType,
      structured_rules: structuredRules,
      category: "governance",
      severity: "high",
      enabled: true,
      enforcement_mode: "audit",
      tags: [sourceType, "ingested", structuredRules.length > 0 ? "ai-rules" : "semantic-only"],
    }).select().single();
    if (pErr) return new Response(JSON.stringify({ error: pErr.message }), { status: 500, headers: { ...cors, "Content-Type": "application/json" } });

    // Generate and store chunks + embeddings
    const chunks = chunkText(text, 400, 80);
    const rows = [];
    for (let i = 0; i < chunks.length; i++) {
      const embedding = await generateEmbedding(chunks[i], aiCfg);
      rows.push({ organization_id: orgId, policy_id: policy.id, chunk_index: i, content: chunks[i], embedding });
    }
    if (rows.length > 0) await supa.from("policy_chunks").insert(rows);

    return new Response(JSON.stringify({ success: true, policy, chunks_created: rows.length, structured_rules_created: structuredRules.length }), { headers: { ...cors, "Content-Type": "application/json" } });
  }

  // Handle JSON â€” generate embeddings for existing policy
  const body = await req.json().catch(() => ({}));
  const { policy_id } = body;
  if (!policy_id) return new Response(JSON.stringify({ error: "policy_id required" }), { status: 400, headers: { ...cors, "Content-Type": "application/json" } });

  const { data: policy } = await supa.from("policies").select("id, content").eq("id", policy_id).eq("organization_id", orgId).maybeSingle();
  if (!policy) return new Response(JSON.stringify({ error: "Policy not found" }), { status: 404, headers: { ...cors, "Content-Type": "application/json" } });

  // Delete existing chunks for this policy
  await supa.from("policy_chunks").delete().eq("policy_id", policy_id);

  const chunks = chunkText(policy.content, 400, 80);
  const rows = [];
  for (let i = 0; i < chunks.length; i++) {
    const embedding = await generateEmbedding(chunks[i], aiCfg);
    rows.push({ organization_id: orgId, policy_id: policy.id, chunk_index: i, content: chunks[i], embedding });
  }
  if (rows.length > 0) await supa.from("policy_chunks").insert(rows);

  return new Response(JSON.stringify({ success: true, policy_id, chunks_created: rows.length }), { headers: { ...cors, "Content-Type": "application/json" } });
});
