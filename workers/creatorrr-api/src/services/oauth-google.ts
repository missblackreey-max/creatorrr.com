import type { Env, GoogleIdTokenInfo } from "../types";
import { safeSiteUrl } from "../lib/utils";
import { currentDeviceTokenVersion, ensureDeviceAllowed } from "./db";
import { jwtSign } from "../lib/crypto";

export async function getGoogleIdTokenInfo(idToken: string): Promise<GoogleIdTokenInfo | null> {
  const res = await fetch(
    `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`,
  );
  if (!res.ok) return null;
  const obj = (await res.json()) as Record<string, any>;
  const sub = String(obj.sub || "").trim();
  if (!sub) return null;
  return {
    sub,
    email: typeof obj.email === "string" ? obj.email : undefined,
    email_verified: typeof obj.email_verified === "string" ? obj.email_verified : undefined,
  };
}

export async function getUserIdByGoogleSub(env: Env, sub: string): Promise<string | null> {
  const row = await env.creatorrr_db
    .prepare("SELECT user_id FROM user_identities WHERE provider='google' AND provider_user_id=?1")
    .bind(sub)
    .first<{ user_id?: string }>();
  const id = String(row?.user_id || "").trim();
  return id || null;
}

export async function issueWebToken(env: Env, userId: string, deviceId: string) {
  const allow = await ensureDeviceAllowed(env, userId, deviceId);
  if (!allow.ok) return { ok: false as const, reason: allow.reason || "device_not_allowed" };

  const tv = await currentDeviceTokenVersion(env, userId, deviceId);
  if (tv === null) return { ok: false as const, reason: "device_not_registered" };

  const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7;
  const token = await jwtSign(env.JWT_SECRET, {
    sub: userId,
    exp,
    did: deviceId,
    tv,
  });

  return { ok: true as const, token, exp };
}

export function oauthRedirectToSite(env: Env, intent: string, extras?: Record<string, string>) {
  const site = safeSiteUrl(env);
  const query = new URLSearchParams();
  query.set("intent", intent || "trial");
  if (extras) {
    for (const [k, v] of Object.entries(extras)) query.set(k, v);
  }
  return `${site}/account.html?${query.toString()}`;
}
