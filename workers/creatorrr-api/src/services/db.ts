import { bad } from "../lib/http";
import { getBearer, normalizeDeviceId, normalizeEmail, nowIso } from "../lib/utils";
import { jwtVerify } from "../lib/crypto";
import type { AuthContext, Env, LicenseRow, UserRow } from "../types";

export async function ensureDeviceAllowed(
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

export async function currentDeviceTokenVersion(
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

export async function revokeCurrentDevice(env: Env, userId: string, deviceId: string): Promise<void> {
  await env.creatorrr_db
    .prepare(
      "UPDATE user_devices SET token_version = token_version + 1, last_seen_at=?3 WHERE user_id=?1 AND device_id=?2",
    )
    .bind(userId, deviceId, nowIso())
    .run();
}

export async function revokeAllUserDevices(env: Env, userId: string): Promise<void> {
  await env.creatorrr_db
    .prepare("UPDATE user_devices SET token_version = token_version + 1, last_seen_at=?2 WHERE user_id=?1")
    .bind(userId, nowIso())
    .run();
}

export async function requireAuth(
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

  const user = await env.creatorrr_db
    .prepare("SELECT email_verified_at FROM users WHERE id=?1")
    .bind(userId)
    .first<{ email_verified_at?: string | null }>();

  if (!user) return { ok: false, response: bad(req, "user_not_found", 404) };
  if (!user.email_verified_at) {
    return { ok: false, response: bad(req, "email_not_verified", 403) };
  }

  return {
    ok: true,
    ctx: {
      userId,
      deviceId,
      tokenVersion: tokenTv,
    },
  };
}

export async function getLicenseRow(env: Env, userId: string): Promise<LicenseRow | null> {
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
        scheduled_billing_interval,
        scheduled_change_at,
        cancel_at,
        canceled_at,
        ended_at
      FROM licenses
      WHERE user_id=?1
    `)
    .bind(userId)
    .first<LicenseRow>();
}

const USER_SELECT = `
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
`;

export async function getUserById(env: Env, userId: string): Promise<UserRow | null> {
  return await env.creatorrr_db
    .prepare(`${USER_SELECT} WHERE id=?1`)
    .bind(userId)
    .first<UserRow>();
}

export async function getUserByEmail(env: Env, email: string): Promise<UserRow | null> {
  return await env.creatorrr_db
    .prepare(`${USER_SELECT} WHERE email=?1`)
    .bind(email)
    .first<UserRow>();
}

export async function getUserByVerifyTokenHash(env: Env, tokenHash: string): Promise<UserRow | null> {
  return await env.creatorrr_db
    .prepare(`${USER_SELECT} WHERE email_verify_token_hash=?1`)
    .bind(tokenHash)
    .first<UserRow>();
}

export async function getUserByResetTokenHash(env: Env, tokenHash: string): Promise<UserRow | null> {
  return await env.creatorrr_db
    .prepare(`${USER_SELECT} WHERE password_reset_token_hash=?1`)
    .bind(tokenHash)
    .first<UserRow>();
}

export async function getUserEmail(env: Env, userId: string): Promise<string | null> {
  const row = await env.creatorrr_db
    .prepare("SELECT email FROM users WHERE id=?1")
    .bind(userId)
    .first<{ email: string }>();

  if (!row?.email) return null;
  return normalizeEmail(row.email);
}
