// Supabase Edge Function: admin-create-user
// Deploy this function in the Supabase project. Never place the service-role key in browser code.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const OWNER_EMAIL = "tscgad917@gmail.com";
const INITIAL_PASSWORD = "00000000";
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
      return new Response(JSON.stringify({ error: "請先以最高管理員身分登入。" }), { status: 401, headers });
    }

    const callerClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: authorizationHeader } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: callerData, error: callerError } = await callerClient.auth.getUser();
    const caller = callerData?.user;
    if (callerError || !caller || (caller.email || "").toLowerCase() !== OWNER_EMAIL) {
      return new Response(JSON.stringify({ error: "只有最高管理員可以建立管理人員帳號。" }), { status: 403, headers });
    }

    const adminClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: ownerAuth, error: ownerError } = await adminClient
      .from("admin_authorizations")
      .select("email, role, is_active")
      .eq("email", OWNER_EMAIL)
      .eq("is_active", true)
      .maybeSingle();

    if (ownerError || !ownerAuth || ownerAuth.role !== "owner") {
      return new Response(JSON.stringify({ error: "無法確認最高管理員授權。" }), { status: 403, headers });
    }

    const body = await req.json().catch(() => ({}));
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return new Response(JSON.stringify({ error: "請輸入有效的 Email。" }), { status: 400, headers });
    }
    if (email === OWNER_EMAIL) {
      return new Response(JSON.stringify({ error: "此信箱已是最高管理員。" }), { status: 400, headers });
    }

    const { data: targetAuth, error: targetError } = await adminClient
      .from("admin_authorizations")
      .select("email, role, is_active")
      .eq("email", email)
      .eq("is_active", true)
      .maybeSingle();

    if (targetError || !targetAuth || targetAuth.role !== "admin") {
      return new Response(JSON.stringify({ error: "此 Email 尚未列入啟用中的一般管理員授權名單，請先新增授權。" }), { status: 400, headers });
    }

    const { data: created, error: createError } = await adminClient.auth.admin.createUser({
      email,
      password: INITIAL_PASSWORD,
      email_confirm: true,
      user_metadata: { must_change_password: true },
    });

    if (createError) {
      const message = /already been registered|already exists|duplicate/i.test(createError.message)
        ? "此 Email 已有 Supabase 登入帳號。請使用密碼重設流程，不要重複建立。"
        : "建立帳號失敗：" + createError.message;
      return new Response(JSON.stringify({ error: message }), { status: 400, headers });
    }

    return new Response(JSON.stringify({
      success: true,
      email: created.user.email,
      message: "登入帳號已建立並確認信箱。初始密碼為 00000000；目前已標記為首次登入需更改密碼。",
    }), { status: 200, headers });
  } catch (error) {
    console.error("admin-create-user error:", error);
    return new Response(JSON.stringify({ error: error instanceof Error ? error.message : "伺服器發生未知錯誤。" }), { status: 500, headers });
  }
});
