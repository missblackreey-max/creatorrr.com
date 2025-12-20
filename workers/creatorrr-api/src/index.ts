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

function json(data: any, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function bad(msg: string, status = 400) {
  return json({ ok: false, error: msg }, status);
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
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
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

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "POST" && url.pathname === "/auth/register") {
      const body = await readJson<{ email?: string; password?: string }>(req);
      if (!body) return bad("invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      const password = String(body.password || "");
      if (!email || password.length < 8) return bad("invalid_input");

      const existing = await env.creatorrr_db
        .prepare("SELECT id FROM users WHERE email=?1")
        .bind(email)
        .first();

      if (existing) return bad("email_exists", 409);

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

        env.creatorrr_db
          .prepare(
            "INSERT INTO licenses (user_id,plan,status,notes,created_at,updated_at) VALUES (?1,'beta','active','beta user',?2,?2)",
          )
          .bind(userId, now),
      ]);

      return json({ ok: true });
    }

    if (req.method === "POST" && url.pathname === "/auth/login") {
      const body = await readJson<{ email?: string; password?: string }>(req);
      if (!body) return bad("invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      const password = String(body.password || "");

      const user = await env.creatorrr_db
        .prepare("SELECT id, pass_salt, pass_hash FROM users WHERE email=?1")
        .bind(email)
        .first<any>();

      if (!user) return bad("invalid_credentials", 401);

      const hash = await pbkdf2(password, user.pass_salt);
      if (hash !== user.pass_hash) return bad("invalid_credentials", 401);

      const lic = await env.creatorrr_db
        .prepare("SELECT plan,status FROM licenses WHERE user_id=?1")
        .bind(user.id)
        .first<any>();

      if (!lic || lic.status !== "active") return bad("no_license", 403);

      const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7;

      const token = await jwtSign(env.JWT_SECRET, {
        sub: user.id,
        plan: lic.plan,
        exp,
      });

      return json({ ok: true, token, plan: lic.plan, expiresAt: exp });
    }

    if (req.method === "GET" && url.pathname === "/license/me") {
      const token = getBearer(req);
      if (!token) return bad("missing_token", 401);

      const payload = await jwtVerify(env.JWT_SECRET, token);
      if (!payload) return bad("invalid_token", 401);

      if (payload.exp < Math.floor(Date.now() / 1000)) {
        return bad("token_expired", 401);
      }

      return json({ ok: true, plan: payload.plan });
    }

    return bad("not_found", 404);
  },
};
