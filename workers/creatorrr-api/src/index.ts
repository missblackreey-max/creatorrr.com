export interface Env {
  creatorrr_db: D1Database;
  JWT_SECRET: string;
  STRIPE_SECRET_KEY: string;
  STRIPE_PRICE_ID_MONTHLY: string;
  STRIPE_PRICE_ID_YEARLY: string;
  STRIPE_WEBHOOK_SECRET: string;
  SITE_URL: string;
  STRIPE_PORTAL_RETURN_URL?: string;
  RESEND_API_KEY?: string;
  RESEND_FROM_EMAIL?: string;
  RESEND_FROM_NAME?: string;
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

function isoNow() {
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

async function hmacSha256Hex(secret: string, data: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const bytes = new Uint8Array(sig);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(data: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  const bytes = new Uint8Array(digest);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
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

function normalizeDeviceId(deviceId: string) {
  const v = deviceId.trim();
  if (!v) return "";
  if (v.length > 80) return "";
  return v;
}

function parseIsoMs(v: unknown): number | null {
  if (typeof v !== "string" || !v.trim()) return null;
  const ms = Date.parse(v);
  return Number.isFinite(ms) ? ms : null;
}

function normalizeSiteUrl(v: string): string {
  return (v || "").trim().replace(/\/+$/, "");
}

function escapeHtml(v: string): string {
  return v
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function sendPasswordResetEmail(env: Env, toEmail: string, resetUrl: string): Promise<boolean> {
  const apiKey = String(env.RESEND_API_KEY || "").trim();
  const fromEmail = String(env.RESEND_FROM_EMAIL || "").trim();
  const fromName = String(env.RESEND_FROM_NAME || "Creatorrr").trim() || "Creatorrr";
  if (!apiKey || !fromEmail) return false;

  const safeUrl = escapeHtml(resetUrl);
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: `${fromName} <${fromEmail}>`,
      to: [toEmail],
      subject: "Reset your Creatorrr password",
      html: [
        "<p>You requested a password reset for your Creatorrr account.</p>",
        `<p><a href=\"${safeUrl}\">Reset your password</a></p>`,
        "<p>This link expires in 30 minutes. If you did not request this, you can ignore this email.</p>",
      ].join(""),
    }),
  });

  return response.ok;
}

function unixToIso(v: unknown): string | null {
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) return null;
  return new Date(v * 1000).toISOString();
}

function timingSafeEqualStr(a: string, b: string): boolean {
  const aa = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa[i] ^ bb[i];
  return diff === 0;
}

function parseStripeSignature(header: string | null): { t: string | null; v1: string[] } {
  if (!header) return { t: null, v1: [] };

  const parts = header.split(",").map((s) => s.trim()).filter(Boolean);
  let t: string | null = null;
  const v1: string[] = [];

  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx);
    const v = part.slice(idx + 1);
    if (k === "t") t = v;
    if (k === "v1") v1.push(v);
  }

  return { t, v1 };
}

async function verifyStripeWebhookSignature(
  secret: string,
  rawBody: string,
  sigHeader: string | null,
): Promise<boolean> {
  const parsed = parseStripeSignature(sigHeader);
  if (!parsed.t || parsed.v1.length === 0) return false;

  const signedPayload = `${parsed.t}.${rawBody}`;
  const expected = await hmacSha256Hex(secret, signedPayload);

  return parsed.v1.some((sig) => timingSafeEqualStr(sig, expected));
}

function asRecord(v: unknown): Record<string, any> {
  return v && typeof v === "object" ? (v as Record<string, any>) : {};
}

function makeOpaqueToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return b64url(bytes.buffer);
}

function addMinutesIso(minutes: number): string {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function isExpiredIso(v: string | null | undefined): boolean {
  if (!v) return true;
  const ms = Date.parse(v);
  return !Number.isFinite(ms) || ms <= Date.now();
}

// -------------------- Types --------------------

type LicenseRow = {
  user_id: string;
  plan: string;
  status: string;
  notes?: string | null;
  created_at: string;
  updated_at: string;
  stripe_customer_id?: string | null;
  stripe_subscription_id?: string | null;
  stripe_price_id?: string | null;
  billing_interval?: string | null;
  current_period_start?: string | null;
  current_period_end?: string | null;
  trial_start_at?: string | null;
  trial_end_at?: string | null;
  cancel_at_period_end?: number | null;
  canceled_at?: string | null;
  ended_at?: string | null;
};

type UserRow = {
  id: string;
  email: string;
  pass_salt: string;
  pass_hash: string;
  created_at: string;
  email_verified_at?: string | null;
  password_reset_token_hash?: string | null;
  password_reset_expires_at?: string | null;
  email_verify_token_hash?: string | null;
  email_verify_expires_at?: string | null;
  updated_at?: string | null;
};

type EntitlementView = {
  plan: string;
  status: string;
  entitled: boolean;
  entitled_until: string | null;
  in_trial: boolean;
  cancel_at_period_end: boolean;
};

type AuthContext = {
  userId: string;
  deviceId: string;
  tokenVersion: number;
};

type StripeCheckoutSessionResponse = {
  id: string;
  url?: string | null;
};

type StripePortalSessionResponse = {
  url?: string | null;
};

type StripeSubscriptionLike = {
  id: string;
  customer?: string | null;
  status?: string | null;
  cancel_at_period_end?: boolean | null;
  canceled_at?: number | null;
  ended_at?: number | null;
  current_period_start?: number | null;
  current_period_end?: number | null;
  trial_start?: number | null;
  trial_end?: number | null;
  metadata?: Record<string, string>;
  items?: {
    data?: Array<{
      price?: {
        id?: string | null;
        recurring?: {
          interval?: string | null;
        } | null;
      } | null;
    }>;
  } | null;
};

// -------------------- Entitlement --------------------

function computeEntitlement(lic: LicenseRow | null): EntitlementView {
  if (!lic) {
    return {
      plan: "none",
      status: "none",
      entitled: false,
      entitled_until: null,
      in_trial: false,
      cancel_at_period_end: false,
    };
  }

  const nowMs = Date.now();
  const status = String(lic.status || "").toLowerCase().trim();
  const plan = String(lic.plan || "").toLowerCase().trim();

  const trialEndMs = parseIsoMs(lic.trial_end_at);
  const periodEndMs = parseIsoMs(lic.current_period_end);

  const inTrial =
    (status === "trialing" || plan === "trial" || plan === "free") &&
    trialEndMs !== null &&
    trialEndMs > nowMs;

  const subscriptionActive =
    (status === "active" || status === "past_due" || status === "canceling") &&
    periodEndMs !== null &&
    periodEndMs > nowMs;

  const entitled = inTrial || subscriptionActive;

  let entitledUntil: string | null = null;
  if (inTrial && lic.trial_end_at) entitledUntil = lic.trial_end_at;
  if (!inTrial && subscriptionActive && lic.current_period_end) entitledUntil = lic.current_period_end;

  return {
    plan,
    status,
    entitled,
    entitled_until: entitledUntil,
    in_trial: inTrial,
    cancel_at_period_end: Number(lic.cancel_at_period_end || 0) === 1,
  };
}

async function getLicenseRow(env: Env, userId: string): Promise<LicenseRow | null> {
  return await env.creatorrr_db
    .prepare(`
      SELECT
        user_id,
        plan,
        status,
        notes,
        created_at,
        updated_at,
        stripe_customer_id,
        stripe_subscription_id,
        stripe_price_id,
        billing_interval,
        current_period_start,
        current_period_end,
        trial_start_at,
        trial_end_at,
        cancel_at_period_end,
        canceled_at,
        ended_at
      FROM licenses
      WHERE user_id=?1
    `)
    .bind(userId)
    .first<LicenseRow>();
}

// -------------------- DB helpers --------------------

async function ensureDeviceAllowed(
  env: Env,
  userId: string,
  deviceId: string,
): Promise<{ ok: boolean; reason?: string }> {
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

async function currentDeviceTokenVersion(
  env: Env,
  userId: string,
  deviceId: string,
): Promise<number | null> {
  const row = await env.creatorrr_db
    .prepare("SELECT token_version FROM user_devices WHERE user_id=?1 AND device_id=?2")
    .bind(userId, deviceId)
    .first<any>();

  if (!row) return null;
  const v = Number(row.token_version);
  return Number.isFinite(v) ? v : 0;
}

async function revokeCurrentDevice(env: Env, userId: string, deviceId: string): Promise<void> {
  await env.creatorrr_db
    .prepare(
      "UPDATE user_devices SET token_version = token_version + 1, last_seen_at=?3 WHERE user_id=?1 AND device_id=?2",
    )
    .bind(userId, deviceId, nowIso())
    .run();
}

async function revokeAllUserDevices(env: Env, userId: string): Promise<void> {
  await env.creatorrr_db
    .prepare("UPDATE user_devices SET token_version = token_version + 1, last_seen_at=?2 WHERE user_id=?1")
    .bind(userId, nowIso())
    .run();
}

async function requireAuth(
  req: Request,
  env: Env,
): Promise<{ ok: true; ctx: AuthContext } | { ok: false; response: Response }> {
  const token = getBearer(req);
  if (!token) return { ok: false, response: bad(req, "missing_token", 401) };

  const payload = await jwtVerify(env.JWT_SECRET, token);
  if (!payload) return { ok: false, response: bad(req, "invalid_token", 401) };

  if (payload.exp < Math.floor(Date.now() / 1000)) {
    return { ok: false, response: bad(req, "token_expired", 401) };
  }

  const userId = String(payload.sub || "");
  const deviceId = String(payload.did || "");
  const tokenTv = Number(payload.tv);

  if (!userId) return { ok: false, response: bad(req, "invalid_token", 401) };
  if (!deviceId) return { ok: false, response: bad(req, "invalid_token_device", 401) };
  if (!Number.isFinite(tokenTv)) return { ok: false, response: bad(req, "invalid_token_version", 401) };

  const row = await env.creatorrr_db
    .prepare("SELECT token_version FROM user_devices WHERE user_id=?1 AND device_id=?2")
    .bind(userId, deviceId)
    .first<any>();

  if (!row) return { ok: false, response: bad(req, "device_not_allowed", 403) };

  const currentTv = Number(row.token_version);
  if (!Number.isFinite(currentTv)) return { ok: false, response: bad(req, "device_not_allowed", 403) };
  if (currentTv !== tokenTv) return { ok: false, response: bad(req, "token_revoked", 401) };

  await env.creatorrr_db
    .prepare("UPDATE user_devices SET last_seen_at=?3 WHERE user_id=?1 AND device_id=?2")
    .bind(userId, deviceId, nowIso())
    .run();

  return {
    ok: true,
    ctx: {
      userId,
      deviceId,
      tokenVersion: tokenTv,
    },
  };
}

async function getUserById(env: Env, userId: string): Promise<UserRow | null> {
  return await env.creatorrr_db
    .prepare(`
      SELECT
        id,
        email,
        pass_salt,
        pass_hash,
        created_at,
        email_verified_at,
        password_reset_token_hash,
        password_reset_expires_at,
        email_verify_token_hash,
        email_verify_expires_at,
        updated_at
      FROM users
      WHERE id=?1
    `)
    .bind(userId)
    .first<UserRow>();
}

async function getUserByEmail(env: Env, email: string): Promise<UserRow | null> {
  return await env.creatorrr_db
    .prepare(`
      SELECT
        id,
        email,
        pass_salt,
        pass_hash,
        created_at,
        email_verified_at,
        password_reset_token_hash,
        password_reset_expires_at,
        email_verify_token_hash,
        email_verify_expires_at,
        updated_at
      FROM users
      WHERE email=?1
    `)
    .bind(email)
    .first<UserRow>();
}

async function getUserEmail(env: Env, userId: string): Promise<string | null> {
  const row = await env.creatorrr_db
    .prepare("SELECT email FROM users WHERE id=?1")
    .bind(userId)
    .first<{ email: string }>();

  if (!row?.email) return null;
  return normalizeEmail(row.email);
}

function makeAccountView(user: UserRow, lic: LicenseRow | null) {
  const entitlement = computeEntitlement(lic);
  return {
    user: {
      id: user.id,
      email: user.email,
      created_at: user.created_at,
      updated_at: user.updated_at || user.created_at,
      email_verified: !!user.email_verified_at,
      email_verified_at: user.email_verified_at || null,
    },
    license: {
      plan: entitlement.plan,
      status: entitlement.status,
      entitled: entitlement.entitled,
      entitled_until: entitlement.entitled_until,
      in_trial: entitlement.in_trial,
      cancel_at_period_end: entitlement.cancel_at_period_end,
      billing_interval: lic?.billing_interval || null,
      current_period_end: lic?.current_period_end || null,
      trial_end_at: lic?.trial_end_at || null,
    },
  };
}

// -------------------- Stripe helpers --------------------

function requireStripeCheckoutConfig(req: Request, env: Env): Response | null {
  if (!env.STRIPE_SECRET_KEY?.trim()) return bad(req, "missing_stripe_secret", 500);
  if (!env.STRIPE_PRICE_ID_MONTHLY?.trim()) return bad(req, "missing_monthly_price_id", 500);
  if (!env.STRIPE_PRICE_ID_YEARLY?.trim()) return bad(req, "missing_yearly_price_id", 500);
  if (!env.SITE_URL?.trim()) return bad(req, "missing_site_url", 500);
  return null;
}

function requireStripePortalConfig(req: Request, env: Env): Response | null {
  if (!env.STRIPE_SECRET_KEY?.trim()) return bad(req, "missing_stripe_secret", 500);
  if (!env.SITE_URL?.trim()) return bad(req, "missing_site_url", 500);
  return null;
}

function getPriceIdForInterval(env: Env, interval: string): string | null {
  if (interval === "month") return env.STRIPE_PRICE_ID_MONTHLY;
  if (interval === "year") return env.STRIPE_PRICE_ID_YEARLY;
  return null;
}

async function stripePostForm<T>(env: Env, path: string, form: URLSearchParams): Promise<T> {
  const res = await fetch(`https://api.stripe.com${path}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });

  const text = await res.text();
  let data: any = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`stripe_invalid_json:${res.status}:${text}`);
  }

  if (!res.ok) {
    const msg = data?.error?.message || data?.error?.code || `stripe_error_${res.status}`;
    throw new Error(msg);
  }

  return data as T;
}

async function createStripeCheckoutSession(
  env: Env,
  userId: string,
  email: string,
  interval: "month" | "year",
  withTrial: boolean,
): Promise<StripeCheckoutSessionResponse> {
  const priceId = getPriceIdForInterval(env, interval);
  if (!priceId) throw new Error("invalid_interval");

  const siteUrl = normalizeSiteUrl(env.SITE_URL);
  const successUrl = `${siteUrl}/billing/success?session_id={CHECKOUT_SESSION_ID}`;
  const cancelUrl = `${siteUrl}/get-started.html?intent=${interval === "year" ? "yearly" : "monthly"}&checkout=canceled`;

  const form = new URLSearchParams();
  form.set("mode", "subscription");

  form.set("line_items[0][price]", priceId);
  form.set("line_items[0][quantity]", "1");

  if (withTrial) {
    form.set("payment_method_collection", "if_required");
    form.set("subscription_data[trial_period_days]", "3");
    form.set("subscription_data[trial_settings][end_behavior][missing_payment_method]", "cancel");
  }

  form.set("client_reference_id", userId);
  form.set("customer_email", email);

  form.set("metadata[user_id]", userId);
  form.set("metadata[interval]", interval);
  form.set("metadata[with_trial]", withTrial ? "true" : "false");

  form.set("subscription_data[metadata][user_id]", userId);
  form.set("subscription_data[metadata][interval]", interval);
  form.set("subscription_data[metadata][with_trial]", withTrial ? "true" : "false");

  form.set("success_url", successUrl);
  form.set("cancel_url", cancelUrl);

  return await stripePostForm<StripeCheckoutSessionResponse>(
    env,
    "/v1/checkout/sessions",
    form,
  );
}

async function createStripePortalSession(
  env: Env,
  customerId: string,
): Promise<StripePortalSessionResponse> {
  const siteUrl = normalizeSiteUrl(env.SITE_URL);
  const returnUrl = normalizeSiteUrl(env.STRIPE_PORTAL_RETURN_URL || "") || `${siteUrl}/get-started.html?intent=login`;

  const form = new URLSearchParams();
  form.set("customer", customerId);
  form.set("return_url", returnUrl);

  return await stripePostForm<StripePortalSessionResponse>(
    env,
    "/v1/billing_portal/sessions",
    form,
  );
}

function mapStripeStatus(subscription: StripeSubscriptionLike): string {
  const raw = String(subscription.status || "").trim().toLowerCase();
  const cancelAtPeriodEnd = Boolean(subscription.cancel_at_period_end);

  if ((raw === "active" || raw === "trialing" || raw === "past_due") && cancelAtPeriodEnd) {
    return "canceling";
  }

  return raw || "unknown";
}

function extractRecurringInterval(subscription: StripeSubscriptionLike): string | null {
  const interval = subscription.items?.data?.[0]?.price?.recurring?.interval;
  if (interval === "month" || interval === "year") return interval;
  return null;
}

function extractPriceId(subscription: StripeSubscriptionLike): string | null {
  return subscription.items?.data?.[0]?.price?.id || null;
}

async function findUserIdForStripeSubscription(
  env: Env,
  subscription: StripeSubscriptionLike,
): Promise<string | null> {
  const metaUserId = subscription.metadata?.user_id;
  if (metaUserId) return String(metaUserId);

  const customerId = subscription.customer ? String(subscription.customer) : "";
  if (!customerId) return null;

  const row = await env.creatorrr_db
    .prepare("SELECT user_id FROM licenses WHERE stripe_customer_id=?1")
    .bind(customerId)
    .first<{ user_id: string }>();

  return row?.user_id || null;
}

async function upsertLicenseFromStripeSubscription(
  env: Env,
  subscription: StripeSubscriptionLike,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const userId = await findUserIdForStripeSubscription(env, subscription);
  if (!userId) return { ok: false, reason: "user_not_found_for_subscription" };

  const stripeCustomerId = subscription.customer ? String(subscription.customer) : null;
  const stripeSubscriptionId = subscription.id ? String(subscription.id) : null;
  const stripePriceId = extractPriceId(subscription);
  const billingInterval = extractRecurringInterval(subscription);
  const status = mapStripeStatus(subscription);
  const currentPeriodStart = unixToIso(subscription.current_period_start);
  const currentPeriodEnd = unixToIso(subscription.current_period_end);
  const trialStartAt = unixToIso(subscription.trial_start);
  const trialEndAt = unixToIso(subscription.trial_end);
  const canceledAt = unixToIso(subscription.canceled_at);
  const endedAt = unixToIso(subscription.ended_at);
  const cancelAtPeriodEnd = subscription.cancel_at_period_end ? 1 : 0;
  const now = nowIso();

  await env.creatorrr_db
    .prepare(`
      INSERT INTO licenses (
        user_id,
        plan,
        status,
        notes,
        created_at,
        updated_at,
        stripe_customer_id,
        stripe_subscription_id,
        stripe_price_id,
        billing_interval,
        current_period_start,
        current_period_end,
        trial_start_at,
        trial_end_at,
        cancel_at_period_end,
        canceled_at,
        ended_at
      ) VALUES (
        ?1,
        'pro',
        ?2,
        'stripe subscription',
        ?3,
        ?3,
        ?4,
        ?5,
        ?6,
        ?7,
        ?8,
        ?9,
        ?10,
        ?11,
        ?12,
        ?13,
        ?14
      )
      ON CONFLICT(user_id) DO UPDATE SET
        plan='pro',
        status=excluded.status,
        notes='stripe subscription',
        updated_at=excluded.updated_at,
        stripe_customer_id=excluded.stripe_customer_id,
        stripe_subscription_id=excluded.stripe_subscription_id,
        stripe_price_id=excluded.stripe_price_id,
        billing_interval=excluded.billing_interval,
        current_period_start=excluded.current_period_start,
        current_period_end=excluded.current_period_end,
        trial_start_at=excluded.trial_start_at,
        trial_end_at=excluded.trial_end_at,
        cancel_at_period_end=excluded.cancel_at_period_end,
        canceled_at=excluded.canceled_at,
        ended_at=excluded.ended_at
    `)
    .bind(
      userId,
      status,
      now,
      stripeCustomerId,
      stripeSubscriptionId,
      stripePriceId,
      billingInterval,
      currentPeriodStart,
      currentPeriodEnd,
      trialStartAt,
      trialEndAt,
      cancelAtPeriodEnd,
      canceledAt,
      endedAt,
    )
    .run();

  return { ok: true };
}

async function handleCheckoutSessionCompleted(env: Env, session: Record<string, any>): Promise<void> {
  const userId =
    (typeof session.client_reference_id === "string" && session.client_reference_id) ||
    (typeof session.metadata?.user_id === "string" && session.metadata.user_id) ||
    "";

  const customerId = typeof session.customer === "string" ? session.customer : "";

  if (!userId || !customerId) return;

  await env.creatorrr_db
    .prepare(`
      UPDATE licenses
      SET stripe_customer_id=?2, updated_at=?3
      WHERE user_id=?1
    `)
    .bind(userId, customerId, nowIso())
    .run();
}

// -------------------- Worker --------------------

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(req) });
    }

    // ---------- STRIPE WEBHOOK ----------
    if (req.method === "POST" && url.pathname === "/stripe/webhook") {
      if (!env.STRIPE_WEBHOOK_SECRET?.trim()) return bad(req, "missing_webhook_secret", 500);

      const sig = req.headers.get("Stripe-Signature");
      const rawBody = await req.text();

      const valid = await verifyStripeWebhookSignature(env.STRIPE_WEBHOOK_SECRET, rawBody, sig);
      if (!valid) return bad(req, "invalid_stripe_signature", 400);

      let event: any;
      try {
        event = rawBody ? JSON.parse(rawBody) : null;
      } catch {
        return bad(req, "invalid_json", 400);
      }

      const eventType = String(event?.type || "");
      const obj = asRecord(event?.data?.object);

      try {
        if (eventType === "checkout.session.completed") {
          await handleCheckoutSessionCompleted(env, obj);
        } else if (
          eventType === "customer.subscription.created" ||
          eventType === "customer.subscription.updated" ||
          eventType === "customer.subscription.deleted"
        ) {
          const result = await upsertLicenseFromStripeSubscription(
            env,
            obj as unknown as StripeSubscriptionLike,
          );
          if (!result.ok) {
            return json(req, { ok: true, ignored: true, reason: result.reason });
          }
        }

        return json(req, { ok: true, received: true });
      } catch (err) {
        const message = err instanceof Error ? err.message : "webhook_processing_failed";
        return bad(req, "webhook_processing_failed", 500, { message, eventType });
      }
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
      const now = isoNow();

      await env.creatorrr_db.batch([
        env.creatorrr_db
          .prepare(
            `INSERT INTO users (
              id,
              email,
              pass_salt,
              pass_hash,
              created_at,
              updated_at,
              email_verified_at,
              password_reset_token_hash,
              password_reset_expires_at,
              email_verify_token_hash,
              email_verify_expires_at
            ) VALUES (?1,?2,?3,?4,?5,?5,NULL,NULL,NULL,NULL,NULL)`
          )
          .bind(userId, email, salt, hash, now),

        env.creatorrr_db
          .prepare(
            `INSERT INTO licenses (
              user_id,
              plan,
              status,
              notes,
              created_at,
              updated_at,
              billing_interval,
              trial_start_at,
              trial_end_at,
              cancel_at_period_end
            ) VALUES (?1,'none','none','registered_no_license',?2,?2,NULL,NULL,NULL,0)`
          )
          .bind(userId, now),
      ]);

      return json(req, {
        ok: true,
        userId,
        email,
      });
    }

    // ---------- AUTH LOGIN ----------
    if (req.method === "POST" && url.pathname === "/auth/login") {
      const body = await readJson<{ email?: string; password?: string; deviceId?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      const password = String(body.password || "");
      const deviceIdRaw = String(body.deviceId || "");
      const deviceId = normalizeDeviceId(deviceIdRaw);

      if (!email || !password) return bad(req, "invalid_input");
      if (!deviceId) return bad(req, "missing_device_id", 400);

      const user = await getUserByEmail(env, email);
      if (!user) return bad(req, "invalid_credentials", 401);

      const hash = await pbkdf2(password, user.pass_salt);
      if (hash !== user.pass_hash) return bad(req, "invalid_credentials", 401);

      const allow = await ensureDeviceAllowed(env, user.id, deviceId);
      if (!allow.ok) return bad(req, allow.reason || "device_not_allowed", 403);

      const tv = await currentDeviceTokenVersion(env, user.id, deviceId);
      if (tv === null) return bad(req, "device_not_registered", 403);

      const lic = await getLicenseRow(env, user.id);
      const entitlement = computeEntitlement(lic);

      const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7;

      const token = await jwtSign(env.JWT_SECRET, {
        sub: user.id,
        exp,
        did: deviceId,
        tv,
      });

      return json(req, {
        ok: true,
        token,
        entitlement,
        expiresAt: exp,
        user: {
          id: user.id,
          email: user.email,
          email_verified: !!user.email_verified_at,
          email_verified_at: user.email_verified_at || null,
          created_at: user.created_at,
          updated_at: user.updated_at || user.created_at,
        },
      });
    }

    // ---------- AUTH LOGOUT ----------
    if (req.method === "POST" && url.pathname === "/auth/logout") {
      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      await revokeCurrentDevice(env, auth.ctx.userId, auth.ctx.deviceId);
      return json(req, { ok: true });
    }

    // ---------- AUTH FORGOT PASSWORD ----------
    if (req.method === "POST" && url.pathname === "/auth/forgot-password") {
      const body = await readJson<{ email?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      if (!email) return bad(req, "invalid_input");

      const user = await getUserByEmail(env, email);

      if (!user) {
        return json(req, {
          ok: true,
          sent: true,
        });
      }

      const rawToken = makeOpaqueToken();
      const tokenHash = await sha256Hex(rawToken);
      const expiresAt = addMinutesIso(30);
      const now = nowIso();

      await env.creatorrr_db
        .prepare(`
          UPDATE users
          SET
            password_reset_token_hash=?2,
            password_reset_expires_at=?3,
            updated_at=?4
          WHERE id=?1
        `)
        .bind(user.id, tokenHash, expiresAt, now)
        .run();

      const siteUrl = normalizeSiteUrl(env.SITE_URL);
      const resetUrl = `${siteUrl}/reset-password.html?token=${encodeURIComponent(rawToken)}`;
      const mailed = await sendPasswordResetEmail(env, user.email, resetUrl).catch(() => false);

      return json(req, {
        ok: true,
        sent: true,
        delivery: mailed ? "email" : "link",
        reset_url: mailed ? undefined : resetUrl,
        expires_at: expiresAt,
      });
    }

    // ---------- AUTH RESET PASSWORD ----------
    if (req.method === "POST" && url.pathname === "/auth/reset-password") {
      const body = await readJson<{ token?: string; password?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const rawToken = String(body.token || "").trim();
      const newPassword = String(body.password || "");

      if (!rawToken || !newPassword || newPassword.length < 8) {
        return bad(req, "invalid_input");
      }

      const tokenHash = await sha256Hex(rawToken);

      const user = await env.creatorrr_db
        .prepare(`
          SELECT
            id,
            email,
            pass_salt,
            pass_hash,
            created_at,
            email_verified_at,
            password_reset_token_hash,
            password_reset_expires_at,
            email_verify_token_hash,
            email_verify_expires_at,
            updated_at
          FROM users
          WHERE password_reset_token_hash=?1
        `)
        .bind(tokenHash)
        .first<UserRow>();

      if (!user) return bad(req, "invalid_or_expired_reset_token", 400);
      if (isExpiredIso(user.password_reset_expires_at || null)) {
        return bad(req, "invalid_or_expired_reset_token", 400);
      }

      const newSalt = makeSalt();
      const newHash = await pbkdf2(newPassword, newSalt);
      const now = nowIso();

      await env.creatorrr_db
        .prepare(`
          UPDATE users
          SET
            pass_salt=?2,
            pass_hash=?3,
            password_reset_token_hash=NULL,
            password_reset_expires_at=NULL,
            updated_at=?4
          WHERE id=?1
        `)
        .bind(user.id, newSalt, newHash, now)
        .run();

      await revokeAllUserDevices(env, user.id);

      return json(req, {
        ok: true,
        reset: true,
      });
    }

    // ---------- ACCOUNT ME ----------
    if (req.method === "GET" && url.pathname === "/account/me") {
      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const user = await getUserById(env, auth.ctx.userId);
      if (!user) return bad(req, "user_not_found", 404);

      const lic = await getLicenseRow(env, auth.ctx.userId);

      return json(req, {
        ok: true,
        ...makeAccountView(user, lic),
      });
    }

    // ---------- LICENSE ME ----------
    if (req.method === "GET" && url.pathname === "/license/me") {
      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const lic = await getLicenseRow(env, auth.ctx.userId);
      const entitlement = computeEntitlement(lic);

      return json(req, {
        ok: true,
        ...entitlement,
      });
    }

    // ---------- STRIPE CHECKOUT ----------
    if (req.method === "POST" && url.pathname === "/stripe/checkout") {
      const cfgErr = requireStripeCheckoutConfig(req, env);
      if (cfgErr) return cfgErr;

      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const body = await readJson<{ interval?: string; withTrial?: boolean }>(req);
      if (!body) return bad(req, "invalid_json");

      const interval = String(body.interval || "").trim().toLowerCase();
      if (interval !== "month" && interval !== "year") {
        return bad(req, "invalid_interval", 400, { allowed: ["month", "year"] });
      }

      const withTrial = body.withTrial === true;

      const email = await getUserEmail(env, auth.ctx.userId);
      if (!email) return bad(req, "user_email_not_found", 404);

      try {
        const session = await createStripeCheckoutSession(
          env,
          auth.ctx.userId,
          email,
          interval as "month" | "year",
          withTrial,
        );

        if (!session.url) {
          return bad(req, "stripe_checkout_url_missing", 502);
        }

        return json(req, {
          ok: true,
          url: session.url,
          sessionId: session.id,
          withTrial,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : "stripe_checkout_failed";
        return bad(req, "stripe_checkout_failed", 502, { message });
      }
    }

    // ---------- STRIPE PORTAL ----------
    if (req.method === "POST" && url.pathname === "/stripe/portal") {
      const cfgErr = requireStripePortalConfig(req, env);
      if (cfgErr) return cfgErr;

      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const lic = await getLicenseRow(env, auth.ctx.userId);
      const customerId = String(lic?.stripe_customer_id || "").trim();

      if (!customerId) {
        return bad(req, "no_stripe_customer", 400);
      }

      try {
        const session = await createStripePortalSession(env, customerId);

        if (!session.url) {
          return bad(req, "stripe_portal_url_missing", 502);
        }

        return json(req, {
          ok: true,
          url: session.url,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : "stripe_portal_failed";
        return bad(req, "stripe_portal_failed", 502, { message });
      }
    }

    return bad(req, "not_found", 404);
  },
};
