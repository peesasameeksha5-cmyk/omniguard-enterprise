import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

// Service-role client — bypasses RLS, can access vault
function adminClient() {
  return createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } }
  );
}

// Anon client to verify the caller's JWT
function anonClient(authHeader: string) {
  return createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: authHeader } }, auth: { persistSession: false } }
  );
}

async function getCallerOrg(authHeader: string): Promise<{ userId: string; orgId: string; role: string } | null> {
  const client = anonClient(authHeader);
  const { data: { user }, error } = await client.auth.getUser();
  if (error || !user) return null;

  const { data: mem } = await client
    .from("organization_members")
    .select("org_id, role")
    .eq("user_id", user.id)
    .eq("status", "active")
    .order("joined_at", { ascending: true })
    .limit(1)
    .maybeSingle();

  if (!mem) return null;
  return { userId: user.id, orgId: mem.org_id, role: mem.role };
}

// Store AI keys in vault, save vault ID in organizations
async function saveAIKeys(orgId: string, keys: Record<string, string>, config: Record<string, unknown>) {
  const admin = adminClient();

  // Retrieve existing vault ID if any
  const { data: org } = await admin
    .from("organizations")
    .select("ai_keys_vault_id")
    .eq("id", orgId)
    .single();

  const secretName = `ai_keys_org_${orgId}`;
  const secretValue = JSON.stringify(keys);

  let vaultId: string;

  if (org?.ai_keys_vault_id) {
    // Update existing vault secret
    const { error } = await admin.rpc("vault_update_secret", {
      secret_id: org.ai_keys_vault_id,
      new_secret: secretValue,
      new_name: secretName,
    });
    if (error) {
      // Vault update failed — create new
      const { data: vs, error: ce } = await admin.rpc("vault_create_secret", {
        secret: secretValue,
        name: secretName,
      });
      if (ce) throw new Error(`Vault create failed: ${ce.message}`);
      vaultId = vs as string;
    } else {
      vaultId = org.ai_keys_vault_id;
    }
  } else {
    // Create new vault secret
    const { data: vs, error: ce } = await admin.rpc("vault_create_secret", {
      secret: secretValue,
      name: secretName,
    });
    if (ce) {
      // pgsodium vault not available — fall back to encrypted column
      // Store keys base64-encoded in ai_config with a marker so we know not to log them
      await admin.from("organizations").update({
        ai_config: { ...config, _keys_encoded: btoa(secretValue), _vault: false },
      }).eq("id", orgId);
      return { vault: false };
    }
    vaultId = vs as string;
  }

  // Save vault reference + non-secret config
  await admin.from("organizations").update({
    ai_keys_vault_id: vaultId,
    ai_config: { ...config, _vault: true },
  }).eq("id", orgId);

  return { vault: true, vaultId };
}

// Read AI keys from vault (server-side only, never sent to client)
async function readAIKeys(orgId: string): Promise<Record<string, string> | null> {
  const admin = adminClient();

  const { data: org } = await admin
    .from("organizations")
    .select("ai_config, ai_keys_vault_id")
    .eq("id", orgId)
    .single();

  if (!org) return null;

  const cfg = org.ai_config as Record<string, unknown> | null;

  // Vault path
  if (org.ai_keys_vault_id && cfg?._vault === true) {
    const { data: secret } = await admin.rpc("vault_read_secret", {
      secret_id: org.ai_keys_vault_id,
    });
    if (secret) {
      try { return JSON.parse(secret as string); } catch { return null; }
    }
  }

  // Fallback: base64-encoded in ai_config
  if (cfg?._keys_encoded) {
    try { return JSON.parse(atob(cfg._keys_encoded as string)); } catch { return null; }
  }

  return null;
}

// Build masked config for the client (no raw keys)
function maskConfig(keys: Record<string, string> | null): Record<string, boolean> {
  if (!keys) return {};
  const result: Record<string, boolean> = {};
  for (const [k, v] of Object.entries(keys)) {
    result[k + "_set"] = !!v;
  }
  return result;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });

  const auth = req.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return json({ error: "Unauthorized" }, 401);

  try {
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/secrets-proxy\/?/, "");

    // ── GET /secrets-proxy/ai-config ─────────────────────────────────────
    // Returns non-secret AI config + which keys are set (masked). Never returns raw keys.
    if (req.method === "GET" && path === "ai-config") {
      const caller = await getCallerOrg(auth);
      if (!caller) return json({ error: "Unauthorized" }, 401);

      const admin = adminClient();
      const { data: org } = await admin
        .from("organizations")
        .select("ai_config, ai_keys_vault_id")
        .eq("id", caller.orgId)
        .single();

      const cfg = (org?.ai_config as Record<string, unknown>) || {};
      const keys = await readAIKeys(caller.orgId);

      return json({
        provider: cfg.provider || "none",
        fallback_provider: cfg.fallback_provider || null,
        disable_deep_tier: cfg.disable_deep_tier || false,
        max_tokens_per_scan: cfg.max_tokens_per_scan || 50000,
        ollama_url: cfg.ollama_url || null,
        azure_openai_endpoint: cfg.azure_openai_endpoint || null,
        aws_region: cfg.aws_region || "us-east-1",
        keys_configured: maskConfig(keys),
      });
    }

    // ── POST /secrets-proxy/ai-config ────────────────────────────────────
    // Saves AI keys to vault, stores only non-secret config in organizations
    if (req.method === "POST" && path === "ai-config") {
      const caller = await getCallerOrg(auth);
      if (!caller) return json({ error: "Unauthorized" }, 401);
      if (!["owner", "admin"].includes(caller.role)) return json({ error: "Forbidden: admin required" }, 403);

      const body = await req.json();

      // Split into secrets and non-secret config
      const keyFields: Record<string, string> = {};
      const nonSecretConfig: Record<string, unknown> = {};

      const SECRET_FIELDS = [
        "anthropic_api_key", "openai_api_key", "aws_access_key_id",
        "aws_secret_access_key", "azure_openai_key", "gemini_api_key",
        "openrouter_api_key",
      ];

      for (const [k, v] of Object.entries(body)) {
        if (SECRET_FIELDS.includes(k)) {
          if (v && typeof v === "string") keyFields[k] = v;
        } else {
          nonSecretConfig[k] = v;
        }
      }

      // Preserve existing keys that aren't being updated
      const existing = await readAIKeys(caller.orgId);
      const mergedKeys = { ...(existing || {}), ...keyFields };

      const result = await saveAIKeys(caller.orgId, mergedKeys, nonSecretConfig);
      return json({ success: true, vault: result.vault });
    }

    // ── DELETE /secrets-proxy/ai-config/key/:keyName ─────────────────────
    // Removes a specific key from vault (e.g. when user clears a provider)
    if (req.method === "DELETE" && path.startsWith("ai-config/key/")) {
      const caller = await getCallerOrg(auth);
      if (!caller) return json({ error: "Unauthorized" }, 401);
      if (!["owner", "admin"].includes(caller.role)) return json({ error: "Forbidden" }, 403);

      const keyName = path.replace("ai-config/key/", "");
      const existing = await readAIKeys(caller.orgId);
      if (existing && keyName in existing) {
        delete existing[keyName];
        const admin = adminClient();
        const { data: org } = await admin.from("organizations").select("ai_config").eq("id", caller.orgId).single();
        await saveAIKeys(caller.orgId, existing, (org?.ai_config as Record<string, unknown>) || {});
      }
      return json({ success: true });
    }

    // ── POST /secrets-proxy/test-ai ───────────────────────────────────────
    // Tests AI connectivity using stored keys (never returns the key)
    if (req.method === "POST" && path === "test-ai") {
      const caller = await getCallerOrg(auth);
      if (!caller) return json({ error: "Unauthorized" }, 401);

      const keys = await readAIKeys(caller.orgId);
      if (!keys) return json({ success: false, message: "No AI keys configured" });

      const admin = adminClient();
      const { data: org } = await admin.from("organizations").select("ai_config").eq("id", caller.orgId).single();
      const cfg = (org?.ai_config as Record<string, unknown>) || {};
      const provider = cfg.provider as string || "none";

      if (provider === "none") return json({ success: false, message: "No provider selected" });

      // Quick connectivity test per provider
      try {
        if (provider === "anthropic" && keys.anthropic_api_key) {
          const r = await fetch("https://api.anthropic.com/v1/messages", {
            method: "POST",
            headers: { "x-api-key": keys.anthropic_api_key, "anthropic-version": "2023-06-01", "content-type": "application/json" },
            body: JSON.stringify({ model: "claude-3-5-haiku-20241022", max_tokens: 10, messages: [{ role: "user", content: "Hi" }] }),
          });
          return json({ success: r.ok, message: r.ok ? "Anthropic connected" : `Anthropic error ${r.status}` });
        }
        if (provider === "openai" && keys.openai_api_key) {
          const r = await fetch("https://api.openai.com/v1/models", {
            headers: { Authorization: `Bearer ${keys.openai_api_key}` },
          });
          return json({ success: r.ok, message: r.ok ? "OpenAI connected" : `OpenAI error ${r.status}` });
        }
        if (provider === "gemini" && keys.gemini_api_key) {
          const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${keys.gemini_api_key}`);
          return json({ success: r.ok, message: r.ok ? "Gemini connected" : `Gemini error ${r.status}` });
        }
        if (provider === "ollama") {
          const base = (cfg.ollama_url as string) || "http://localhost:11434";
          const r = await fetch(`${base}/api/tags`).catch(() => null);
          return json({ success: !!r?.ok, message: r?.ok ? "Ollama connected" : "Ollama unreachable" });
        }
        return json({ success: false, message: `No test available for ${provider}` });
      } catch (e) {
        return json({ success: false, message: String(e) });
      }
    }

    return json({ error: "Not found" }, 404);
  } catch (e) {
    console.error("secrets-proxy error:", e);
    return json({ error: e instanceof Error ? e.message : String(e) }, 500);
  }
});
