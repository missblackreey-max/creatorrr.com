/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export interface Env {
  creatorrr_db: D1Database;
  JWT_SECRET: string;
}

// -------------------- CORS --------------------

function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("origin") || "*";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "authorization,content-type",
    "access-control-max-age": "86400",
    vary: "origin",
  };
}

function withCors(req: Request, res: Response): Response {
  const h = new Headers(res.headers);
  const cors = corsHeaders(req);
  for (const [k, v] of Object.entries(cors)) h.set(k, v);
  return new Response(res.body, { status: res.status, headers: h });
}

// -------------------- Helpers --------------------

function json(req: Request, data: any, status = 200) {
  const res = new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
  return withCors(req, res);
}

function bad(req: Request, msg: string, status = 400) {
  return json(req, { ok: false, error: msg }, status);
}

function nowIso() {
  return new Date().toISOString();
}

function uuid() {
  return crypto.randomUUID();
}

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function b64url(bytes: ArrayBufferLike) {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlText(s: string) {
  return b64url(new TextEncoder().encode(s).buffer);
}

async function hmacSha256(secret: string, data: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return b64url(sig);
}

async function jwtSign(secret: string, payload: any) {
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64urlText(JSON.stringify(header));
  const p = b64urlText(JSON.stringify(payload));
  const msg = `${h}.${p}`;
  const sig = await hmacSha256(secret, msg);
  return `${msg}.${sig}`;
}

async function jwtVerify(secret: string, token: string) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const msg = `${h}.${p}`;
  const expected = await hmacSha256(secret, msg);
  if (expected !== s) return null;
  const payloadJson = atob(p.replace(/-/g, "+").replace(/_/g, "/"));
  return JSON.parse(payloadJson);
}

function makeSalt() {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  let bin = "";
  for (const b of salt) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function pbkdf2(password: string, saltB64: string) {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256,
  );
  const bytes = new Uint8Array(bits);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function readJson<T = any>(req: Request): Promise<T | null> {
  try {
    return (await req.json()) as T;
  } catch {
    return null;
  }
}

function getBearer(req: Request) {
  const h = req.headers.get("authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

// -------------------- Worker --------------------

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    // Preflight for browser/webview fetch
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(req) });
    }

    if (req.method === "POST" && url.pathname === "/auth/register") {
      const body = await readJson<{ email?: string; password?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      const password = String(body.password || "");
      if (!email || password.length < 8) return bad(req, "invalid_input");

      const existing = await env.creatorrr_db
        .prepare("SELECT id FROM users WHERE email=?1")
        .bind(email)
        .first();

      if (existing) return bad(req, "email_exists", 409);

      const userId = uuid();
      const salt = makeSalt();
      const hash = await pbkdf2(password, salt);
      const now = nowIso();

      await env.creatorrr_db.batch([
        env.creatorrr_db
          .prepare(
            "INSERT INTO users (id,email,pass_salt,pass_hash,created_at) VALUES (?1,?2,?3,?4,?5)",
          )
          .bind(userId, email, salt, hash, now),

        // Default is FREE (exports allowed only with watermark on frontend policy)
        env.creatorrr_db
          .prepare(
            "INSERT INTO licenses (user_id,plan,status,notes,created_at,updated_at) VALUES (?1,'free','active','free user',?2,?2)",
          )
          .bind(userId, now),
      ]);

      return json(req, { ok: true });
    }

    if (req.method === "POST" && url.pathname === "/auth/login") {
      const body = await readJson<{ email?: string; password?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      const password = String(body.password || "");

      const user = await env.creatorrr_db
        .prepare("SELECT id, pass_salt, pass_hash FROM users WHERE email=?1")
        .bind(email)
        .first<any>();

      if (!user) return bad(req, "invalid_credentials", 401);

      const hash = await pbkdf2(password, user.pass_salt);
      if (hash !== user.pass_hash) return bad(req, "invalid_credentials", 401);

      const lic = await env.creatorrr_db
        .prepare("SELECT plan,status FROM licenses WHERE user_id=?1")
        .bind(user.id)
        .first<any>();

      if (!lic || lic.status !== "active") return bad(req, "no_license", 403);

      const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7;

      // Keep plan in JWT as a hint, but we won't trust it for gating.
      const token = await jwtSign(env.JWT_SECRET, {
        sub: user.id,
        plan: lic.plan,
        exp,
      });

      return json(req, { ok: true, token, plan: lic.plan, status: lic.status, expiresAt: exp });
    }

    if (req.method === "GET" && url.pathname === "/license/me") {
      const token = getBearer(req);
      if (!token) return bad(req, "missing_token", 401);

      const payload = await jwtVerify(env.JWT_SECRET, token);
      if (!payload) return bad(req, "invalid_token", 401);

      if (payload.exp < Math.floor(Date.now() / 1000)) {
        return bad(req, "token_expired", 401);
      }

      const userId = String(payload.sub || "");
      if (!userId) return bad(req, "invalid_token", 401);

      // ✅ Source of truth: DB (so upgrades/revokes apply immediately)
      const lic = await env.creatorrr_db
        .prepare("SELECT plan,status FROM licenses WHERE user_id=?1")
        .bind(userId)
        .first<any>();

      if (!lic) return bad(req, "no_license", 403);
      if (lic.status !== "active") return bad(req, "license_not_active", 403);

      return json(req, { ok: true, plan: lic.plan, status: lic.status });
    }

    return bad(req, "not_found", 404);
  },
};
