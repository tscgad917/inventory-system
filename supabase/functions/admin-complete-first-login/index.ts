// Supabase Edge Function: admin-complete-first-login
// Securely changes the current user's initial password and clears the server-managed app_metadata flag.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const ALLOWED_ORIGINS = new Set(["https://tscgad917.github.io"]);

const corsHeaders = (origin: string | null) => ({
  "Access-Control-Allow-Origin": origin && ALLOWED_ORIGINS.has(origin) ? origin : "https://tscgad917.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
  "Content-Type": "application/json; charset=utf-8",
});

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");
  const headers = corsHeaders(origin);
  if (req.method === "OPTIONS") return new Response("ok", { headers });
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return new Response(JSON.stringify({ error: "不允許的來源。" }), { status: 403, headers });
  }
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "僅接受 POST 請求。" }), { status: 405, headers });
  }
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE_KEY) {
    return new Response(JSON.stringify({ error: "伺服器尚未設定必要的 Supabase 環境變數。" }), { status: 500, headers });
  }

  try {
    const authorizationHeader = req.headers.get("Authorization");
    if (!authorizationHeader?.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "請先登入。" }), { status: 401, headers });
    }

    const callerClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: authorizationHeader } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: callerData, error: callerError } = await callerClient.auth.getUser();
    const caller = callerData?.user;
    if (callerError || !caller) {
      return new Response(JSON.stringify({ error: "登入狀態無效，請重新登入。" }), { status: 401, headers });
    }
    if (!(caller.app_metadata && caller.app_metadata.must_change_password === true)) {
      return new Response(JSON.stringify({ error: "此帳號目前不需要執行首次登入密碼變更。" }), { status: 400, headers });
    }

    const body = await req.json().catch(() => ({}));
    const password = typeof body.password === "string" ? body.password : "";
    if (password.length < 12) {
      return new Response(JSON.stringify({ error: "新密碼至少需要 12 個字元。" }), { status: 400, headers });
    }
    if (password === "00000000") {
      return new Response(JSON.stringify({ error: "請勿繼續使用初始密碼。" }), { status: 400, headers });
    }

    const adminClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const appMetadata = { ...(caller.app_metadata || {}), must_change_password: false };
    const { error: updateError } = await adminClient.auth.admin.updateUserById(caller.id, {
      password,
      app_metadata: appMetadata,
    });
    if (updateError) {
      return new Response(JSON.stringify({ error: "更新密碼失敗：" + updateError.message }), { status: 400, headers });
    }

    return new Response(JSON.stringify({
      success: true,
      message: "密碼已更新，首次登入限制已解除。",
    }), { status: 200, headers });
  } catch (error) {
    console.error("admin-complete-first-login error:", error);
    return new Response(JSON.stringify({ error: error instanceof Error ? error.message : "伺服器發生未知錯誤。" }), { status: 500, headers });
  }
});
