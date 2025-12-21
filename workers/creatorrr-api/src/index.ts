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

function bad(req: Request, msg: string, status = 400, extra?: Record<string, any>) {
  return json(req, { ok: false, error: msg, ...(extra || {}) }, status);
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

function isLikelyUuid(s: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s.trim());
}

function normalizeDeviceId(deviceId: string) {
  const v = deviceId.trim();
  if (!v) return "";
  if (v.length > 80) return "";
  return v;
}

// -------------------- DB helpers --------------------

async function ensureDeviceAllowed(env: Env, userId: string, deviceId: string): Promise<{ ok: boolean; reason?: string }> {
  const did = normalizeDeviceId(deviceId);
  if (!did) return { ok: false, reason: "invalid_device_id" };

  const existing = await env.creatorrr_db
    .prepare("SELECT device_id FROM user_devices WHERE user_id=?1 AND device_id=?2")
    .bind(userId, did)
    .first<any>();

  const now = nowIso();

  if (existing) {
    await env.creatorrr_db
      .prepare("UPDATE user_devices SET last_seen_at=?3 WHERE user_id=?1 AND device_id=?2")
      .bind(userId, did, now)
      .run();
    return { ok: true };
  }

  const countRow = await env.creatorrr_db
    .prepare("SELECT COUNT(*) as c FROM user_devices WHERE user_id=?1")
    .bind(userId)
    .first<any>();

  const c = Number(countRow?.c ?? 0);
  if (c >= 3) return { ok: false, reason: "device_limit_reached" };

  await env.creatorrr_db
    .prepare(
      "INSERT INTO user_devices (user_id,device_id,token_version,created_at,last_seen_at) VALUES (?1,?2,0,?3,?3)",
    )
    .bind(userId, did, now)
    .run();

  return { ok: true };
}

async function currentDeviceTokenVersion(env: Env, userId: string, deviceId: string): Promise<number | null> {
  const row = await env.creatorrr_db
    .prepare("SELECT token_version FROM user_devices WHERE user_id=?1 AND device_id=?2")
    .bind(userId, deviceId)
    .first<any>();
  if (!row) return null;
  const v = Number(row.token_version);
  return Number.isFinite(v) ? v : 0;
}

// -------------------- Worker --------------------

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(req) });
    }

    // ---------- AUTH REGISTER ----------
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

        env.creatorrr_db
          .prepare(
            "INSERT INTO licenses (user_id,plan,status,notes,created_at,updated_at) VALUES (?1,'free','active','free user',?2,?2)",
          )
          .bind(userId, now),
      ]);

      return json(req, { ok: true });
    }

    // ---------- AUTH LOGIN (device-limited) ----------
    if (req.method === "POST" && url.pathname === "/auth/login") {
      const body = await readJson<{ email?: string; password?: string; deviceId?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      const password = String(body.password || "");
      const deviceIdRaw = String(body.deviceId || "");
      const deviceId = normalizeDeviceId(deviceIdRaw);

      if (!email || !password) return bad(req, "invalid_input");
      if (!deviceId) return bad(req, "missing_device_id", 400);

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

      const allow = await ensureDeviceAllowed(env, user.id, deviceId);
      if (!allow.ok) return bad(req, allow.reason || "device_not_allowed", 403);

      const tv = await currentDeviceTokenVersion(env, user.id, deviceId);
      if (tv === null) return bad(req, "device_not_registered", 403);

      const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7;

      const token = await jwtSign(env.JWT_SECRET, {
        sub: user.id,
        plan: lic.plan,
        exp,
        did: deviceId,
        tv,
      });

      return json(req, {
        ok: true,
        token,
        plan: lic.plan,
        status: lic.status,
        expiresAt: exp,
      });
    }

    // ---------- AUTH LOGOUT (revokes this device token) ----------
    if (req.method === "POST" && url.pathname === "/auth/logout") {
      const token = getBearer(req);
      if (!token) return bad(req, "missing_token", 401);

      const payload = await jwtVerify(env.JWT_SECRET, token);
      if (!payload) return bad(req, "invalid_token", 401);

      const userId = String(payload.sub || "");
      const deviceId = String(payload.did || "");

      if (!userId || !deviceId) return bad(req, "invalid_token", 401);

      await env.creatorrr_db
        .prepare("UPDATE user_devices SET token_version = token_version + 1, last_seen_at=?3 WHERE user_id=?1 AND device_id=?2")
        .bind(userId, deviceId, nowIso())
        .run();

      return json(req, { ok: true });
    }

    // ---------- LICENSE ME ----------
    if (req.method === "GET" && url.pathname === "/license/me") {
      const token = getBearer(req);
      if (!token) return bad(req, "missing_token", 401);

      const payload = await jwtVerify(env.JWT_SECRET, token);
      if (!payload) return bad(req, "invalid_token", 401);

      if (payload.exp < Math.floor(Date.now() / 1000)) {
        return bad(req, "token_expired", 401);
      }

      const userId = String(payload.sub || "");
      const deviceId = String(payload.did || "");
      const tokenTv = Number(payload.tv);

      if (!userId) return bad(req, "invalid_token", 401);
      if (!deviceId) return bad(req, "invalid_token_device", 401);
      if (!Number.isFinite(tokenTv)) return bad(req, "invalid_token_version", 401);

      const row = await env.creatorrr_db
        .prepare("SELECT token_version FROM user_devices WHERE user_id=?1 AND device_id=?2")
        .bind(userId, deviceId)
        .first<any>();

      if (!row) return bad(req, "device_not_allowed", 403);

      const currentTv = Number(row.token_version);
      if (!Number.isFinite(currentTv)) return bad(req, "device_not_allowed", 403);
      if (currentTv !== tokenTv) return bad(req, "token_revoked", 401);

      await env.creatorrr_db
        .prepare("UPDATE user_devices SET last_seen_at=?3 WHERE user_id=?1 AND device_id=?2")
        .bind(userId, deviceId, nowIso())
        .run();

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
