import { bad, corsHeaders, json, redirect, redirectWithHeaders } from "./lib/http";
import {
  addMinutesIso,
  asRecord,
  getCookieValue,
  isExpiredIso,
  normalizeClientNonce,
  normalizeDeviceId,
  normalizeEmail,
  nowIso,
  readJson,
  safeSiteUrl,
  uuid,
} from "./lib/utils";
import { jwtSign, makeOpaqueSecret, makeOpaqueToken, makeSalt, pbkdf2, sha256Hex } from "./lib/crypto";
import type { Env, LegalAcceptancePayload, StripeSubscriptionLike, UserRow } from "./types";
import { computeEntitlement } from "./services/entitlement";
import {
  currentDeviceTokenVersion,
  createLegalAcceptance,
  CURRENT_PRIVACY_VERSION,
  CURRENT_REFUND_VERSION,
  CURRENT_TERMS_VERSION,
  ensureDeviceAllowed,
  getLicenseRow,
  hasAcceptedCurrentLegalVersions,
  getUserByEmail,
  getUserById,
  getUserByResetTokenHash,
  getUserByVerifyTokenHash,
  getUserEmail,
  requireAuth,
  revokeAllUserDevices,
  revokeCurrentDevice,
  revokeOtherUserDevices,
} from "./services/db";
import {
  createStripeCheckoutSession,
  createStripePortalSession,
  scheduleStripeSubscriptionIntervalChange,
  findLiveStripeSubscriptionForLicense,
  handleCheckoutSessionCompleted,
  recoverStripeCustomerId,
  requireStripeCheckoutConfig,
  requireStripePortalConfig,
  refreshLicenseFromStripe,
  updateStripeSubscriptionAutoRenew,
  upsertLicenseFromStripeSubscription,
  verifyStripeWebhookSignature,
} from "./services/stripe";
import { getGoogleIdTokenInfo, getUserIdByGoogleSub, issueWebToken, oauthRedirectToSite } from "./services/oauth-google";
import { isEmailDeliveryConfigured, issueEmailVerification, issuePasswordReset } from "./services/email";

export function makeAccountView(
  user: UserRow,
  lic: Awaited<ReturnType<typeof getLicenseRow>>,
  legal: { hasAcceptedCurrentVersions: boolean } = { hasAcceptedCurrentVersions: false },
) {
  const entitlement = computeEntitlement(lic);

  const status = String(lic?.status || "").trim().toLowerCase();
  const billingInterval = String(lic?.billing_interval || "").trim().toLowerCase();
  const scheduledBillingInterval = String(lic?.scheduled_billing_interval || "").trim().toLowerCase();
  const freeAccessActive = entitlement.entitled && entitlement.plan === "free";
  const accessEnded = status === "canceled" && !entitlement.entitled;

  const hasRecurringPlan = !freeAccessActive && (billingInterval === "month" || billingInterval === "year");
  const autoRenewEnabled = hasRecurringPlan && entitlement.entitled && status !== "canceling" && !lic?.cancel_at;
  const endedAt = freeAccessActive
    ? null
    : accessEnded
    ? (
        lic?.ended_at ||
        lic?.canceled_at ||
        lic?.cancel_at ||
        lic?.current_period_end ||
        null
      )
    : (lic?.ended_at || null);
  const currentPeriodEnd = freeAccessActive ? null : (accessEnded ? null : (lic?.current_period_end || null));
  const cancelAt = freeAccessActive ? null : (accessEnded ? null : entitlement.cancel_at);

  const nextBillingInterval =
    autoRenewEnabled
      ? (scheduledBillingInterval === "month" || scheduledBillingInterval === "year"
          ? scheduledBillingInterval
          : billingInterval || null)
      : null;

  const nextPaymentAt =
    autoRenewEnabled
      ? (lic?.scheduled_change_at || lic?.current_period_end || null)
      : null;

  const subscriptionEndsAt =
    autoRenewEnabled
      ? null
      : (accessEnded ? null : (lic?.cancel_at || lic?.current_period_end || entitlement.entitled_until || null));

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
      cancel_at: cancelAt,
      ended_at: endedAt,

      billing_interval: freeAccessActive ? null : (lic?.billing_interval || null),
      current_period_end: currentPeriodEnd,
      trial_start_at: lic?.trial_start_at || null,
      trial_end_at: lic?.trial_end_at || null,

      scheduled_billing_interval: freeAccessActive ? null : (lic?.scheduled_billing_interval || null),
      scheduled_change_at: freeAccessActive ? null : (lic?.scheduled_change_at || null),

      auto_renew_enabled: autoRenewEnabled,

      next_billing_interval: nextBillingInterval,
      next_payment_at: nextPaymentAt,
      subscription_ends_at: freeAccessActive ? null : subscriptionEndsAt,

      can_manage_subscription: false,
    },
    legal: {
      has_accepted_current_versions: legal.hasAcceptedCurrentVersions,
      current_terms_version: CURRENT_TERMS_VERSION,
      current_privacy_version: CURRENT_PRIVACY_VERSION,
      current_refund_version: CURRENT_REFUND_VERSION,
    },
  };
}

function getRequestIpAddress(req: Request): string | null {
  const value = String(req.headers.get("CF-Connecting-IP") || req.headers.get("x-forwarded-for") || "").trim();
  if (!value) return null;
  return value.slice(0, 255);
}

function getRequestUserAgent(req: Request): string | null {
  const value = String(req.headers.get("user-agent") || "").trim();
  if (!value) return null;
  return value.slice(0, 1024);
}

function hasMatchingCurrentLegalVersions(acceptance: LegalAcceptancePayload | null | undefined): boolean {
  return (
    acceptance?.accepted === true &&
    String(acceptance?.terms_version || "").trim() === CURRENT_TERMS_VERSION &&
    String(acceptance?.privacy_version || "").trim() === CURRENT_PRIVACY_VERSION &&
    String(acceptance?.refund_version || "").trim() === CURRENT_REFUND_VERSION
  );
}

async function ensureCurrentLegalAcceptance(
  req: Request,
  env: Env,
  userId: string,
  acceptanceContext: string,
  legalAcceptance: LegalAcceptancePayload | null | undefined,
): Promise<{ ok: true; hasAcceptedCurrentVersions: boolean } | { ok: false; response: Response }> {
  const alreadyAccepted = await hasAcceptedCurrentLegalVersions(env, userId);
  if (alreadyAccepted) {
    return { ok: true, hasAcceptedCurrentVersions: true };
  }

  if (!legalAcceptance || legalAcceptance.accepted !== true) {
    return {
      ok: false,
      response: bad(req, "legal_acceptance_required", 400, {
        message: "You must accept the current Terms of Use, Privacy Policy, and Refund Policy before continuing.",
        current_terms_version: CURRENT_TERMS_VERSION,
        current_privacy_version: CURRENT_PRIVACY_VERSION,
        current_refund_version: CURRENT_REFUND_VERSION,
      }),
    };
  }

  if (!hasMatchingCurrentLegalVersions(legalAcceptance)) {
    return {
      ok: false,
      response: bad(req, "invalid_legal_acceptance_version", 400, {
        message: "Legal acceptance versions must exactly match the current Terms of Use, Privacy Policy, and Refund Policy versions.",
        current_terms_version: CURRENT_TERMS_VERSION,
        current_privacy_version: CURRENT_PRIVACY_VERSION,
        current_refund_version: CURRENT_REFUND_VERSION,
      }),
    };
  }

  await createLegalAcceptance(env, {
    userId,
    acceptanceContext,
    acceptedAt: nowIso(),
    ipAddress: getRequestIpAddress(req),
    userAgent: getRequestUserAgent(req),
  });

  return { ok: true, hasAcceptedCurrentVersions: true };
}

function isGoogleOAuthEnabled(env: Env): boolean {
  return String(env.GOOGLE_OAUTH_ENABLED || "").trim().toLowerCase() === "true";
}

function getDashboardOwnerEmails(env: Env): string[] {
  const raw = String(env.DASHBOARD_OWNER_EMAILS || "");
  return raw
    .split(",")
    .map((value) => normalizeEmail(value))
    .filter(Boolean);
}

function getDashboardHiddenUserIds(env: Env): string[] {
  const defaultHiddenIds = [
    "99055ec5-9c39-405e-84c6-3dd2bf1bb63e",
    "280b3bac-977d-41a4-985b-347bbb03221b",
  ];
  const raw = String(env.DASHBOARD_HIDDEN_USER_IDS || defaultHiddenIds.join(","));
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
}

async function requireDashboardOwner(
  req: Request,
  env: Env,
): Promise<{ ok: true; userId: string; email: string } | { ok: false; response: Response }> {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return auth;

  const user = await getUserById(env, auth.ctx.userId);
  if (!user) return { ok: false, response: bad(req, "user_not_found", 404) };

  const userEmail = normalizeEmail(String(user.email || ""));
  if (!userEmail) return { ok: false, response: bad(req, "access_denied", 403) };

  const owners = new Set(getDashboardOwnerEmails(env));
  if (owners.size === 0) return { ok: false, response: bad(req, "dashboard_owner_not_configured", 403) };
  if (!owners.has(userEmail)) return { ok: false, response: bad(req, "access_denied", 403) };

  return { ok: true, userId: user.id, email: userEmail };
}

function dashboardPriceUsd(raw: string | undefined, fallback: number): number {
  const n = Number(String(raw || "").trim());
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function getCountryCode(req: Request): string {
  const country = String((req as Request & { cf?: { country?: string } }).cf?.country || "").trim().toUpperCase();
  if (!country || country.length > 3) return "ZZ";
  return country;
}

function detectLikelyBot(req: Request): { isBot: boolean; botScore: number | null } {
  const cf = (req as Request & { cf?: { botManagement?: { score?: number; verifiedBot?: boolean } } }).cf;
  const verifiedBot = !!cf?.botManagement?.verifiedBot;
  const scoreRaw = Number(cf?.botManagement?.score);
  const botScore = Number.isFinite(scoreRaw) ? scoreRaw : null;
  if (verifiedBot) return { isBot: true, botScore };
  if (botScore !== null) return { isBot: botScore < 30, botScore };

  const ua = String(req.headers.get("user-agent") || "").toLowerCase();
  const uaLooksBot = /(bot|crawler|spider|curl|wget|headless)/i.test(ua);
  return { isBot: uaLooksBot, botScore: null };
}

const ANALYTICS_ALLOWED_EVENTS = new Set(["download_click"]);

function normalizeAnalyticsField(value: unknown, maxLength: number): string | null {
  const text = String(value || "").trim();
  if (!text) return null;
  return text.slice(0, maxLength);
}

function isSafeAnalyticsToken(value: string): boolean {
  return /^[a-z0-9][a-z0-9._-]{0,63}$/i.test(value);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(req) });
    }

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
          const result = await upsertLicenseFromStripeSubscription(env, obj as unknown as StripeSubscriptionLike);
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

    if (req.method === "GET" && (url.pathname === "/auth/google/start" || url.pathname === "/auth/google")) {
      if (!isGoogleOAuthEnabled(env)) return bad(req, "not_found", 404);

      const clientId = String(env.GOOGLE_CLIENT_ID || "").trim();
      const clientSecret = String(env.GOOGLE_CLIENT_SECRET || "").trim();
      if (!clientId || !clientSecret) return bad(req, "google_oauth_not_configured", 500);

      const deviceId = normalizeDeviceId(String(url.searchParams.get("deviceId") || ""));
      if (!deviceId) return bad(req, "missing_device_id", 400);

      const intentRaw = String(url.searchParams.get("intent") || "trial").trim().toLowerCase();
      const intent = ["trial", "monthly", "yearly", "login"].includes(intentRaw) ? intentRaw : "trial";
      const clientNonce = normalizeClientNonce(String(url.searchParams.get("clientNonce") || ""));
      if (!clientNonce) return bad(req, "missing_client_nonce", 400);

      const state = makeOpaqueToken();
      const browserNonce = makeOpaqueToken();
      const browserNonceHash = await sha256Hex(browserNonce);
      const now = nowIso();
      const expires = addMinutesIso(10);

      await env.creatorrr_db
        .prepare(
          `INSERT INTO oauth_states (
            state,
            provider,
            device_id,
            intent,
            created_at,
            expires_at,
            browser_nonce_hash,
            client_nonce
          ) VALUES (?1, 'google', ?2, ?3, ?4, ?5, ?6, ?7)`,
        )
        .bind(state, deviceId, intent, now, expires, browserNonceHash, clientNonce)
        .run();

      const redirectUri = `${url.origin}/auth/google/callback`;
      const gp = new URLSearchParams();
      gp.set("client_id", clientId);
      gp.set("redirect_uri", redirectUri);
      gp.set("response_type", "code");
      gp.set("scope", "openid email profile");
      gp.set("state", state);
      gp.set("access_type", "online");
      gp.set("include_granted_scopes", "true");
      gp.set("prompt", "select_account");

      return redirectWithHeaders(req, `https://accounts.google.com/o/oauth2/v2/auth?${gp.toString()}`, 302, {
        "set-cookie": `creatorrr_google_oauth_nonce=${browserNonce}; Path=/auth/google/callback; Max-Age=600; HttpOnly; Secure; SameSite=Lax`,
      });
    }

    if (req.method === "GET" && url.pathname === "/auth/google/callback") {
      if (!isGoogleOAuthEnabled(env)) {
        return redirect(req, oauthRedirectToSite(env, "login", { oauth_error: "not_found" }));
      }

      const clientId = String(env.GOOGLE_CLIENT_ID || "").trim();
      const clientSecret = String(env.GOOGLE_CLIENT_SECRET || "").trim();
      if (!clientId || !clientSecret) {
        return redirect(req, oauthRedirectToSite(env, "login", { oauth_error: "google_oauth_not_configured" }));
      }

      const oauthErr = String(url.searchParams.get("error") || "").trim();
      if (oauthErr) {
        return redirect(req, oauthRedirectToSite(env, "login", { oauth_error: oauthErr }));
      }

      const state = String(url.searchParams.get("state") || "").trim();
      const code = String(url.searchParams.get("code") || "").trim();
      if (!state || !code) {
        return redirect(req, oauthRedirectToSite(env, "login", { oauth_error: "invalid_oauth_callback" }));
      }

      const saved = await env.creatorrr_db
        .prepare(
          `SELECT state, provider, device_id, intent, expires_at, browser_nonce_hash, client_nonce
           FROM oauth_states
           WHERE state=?1 AND provider='google'`,
        )
        .bind(state)
        .first<{
          state: string;
          provider: string;
          device_id: string;
          intent: string;
          expires_at: string;
          browser_nonce_hash?: string | null;
          client_nonce?: string | null;
        }>();

      await env.creatorrr_db.prepare("DELETE FROM oauth_states WHERE state=?1").bind(state).run();

      const cookieNonce = getCookieValue(req, "creatorrr_google_oauth_nonce");
      const cookieNonceHash = cookieNonce ? await sha256Hex(cookieNonce) : "";

      if (
        !saved ||
        isExpiredIso(saved.expires_at) ||
        !saved.browser_nonce_hash ||
        cookieNonceHash !== saved.browser_nonce_hash
      ) {
        return redirect(req, oauthRedirectToSite(env, "login", { oauth_error: "oauth_state_expired" }));
      }

      const deviceId = normalizeDeviceId(String(saved.device_id || ""));
      const intent = String(saved.intent || "trial").trim().toLowerCase();
      if (!deviceId) {
        return redirect(req, oauthRedirectToSite(env, "login", { oauth_error: "missing_device_id" }));
      }

      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: `${url.origin}/auth/google/callback`,
          grant_type: "authorization_code",
        }).toString(),
      });

      if (!tokenRes.ok) {
        return redirect(req, oauthRedirectToSite(env, intent, { oauth_error: "google_token_exchange_failed" }));
      }

      const tokenData = (await tokenRes.json()) as Record<string, any>;
      const idToken = String(tokenData.id_token || "").trim();
      if (!idToken) {
        return redirect(req, oauthRedirectToSite(env, intent, { oauth_error: "google_id_token_missing" }));
      }

      const idInfo = await getGoogleIdTokenInfo(idToken);
      if (!idInfo) {
        return redirect(req, oauthRedirectToSite(env, intent, { oauth_error: "google_id_token_invalid" }));
      }

      const email = normalizeEmail(String(idInfo.email || ""));
      if (!email) {
        return redirect(req, oauthRedirectToSite(env, intent, { oauth_error: "google_email_missing" }));
      }

      let userId = await getUserIdByGoogleSub(env, idInfo.sub);

      if (!userId) {
        const existing = await getUserByEmail(env, email);
        if (existing) {
          return redirectWithHeaders(
            req,
            oauthRedirectToSite(env, intent, {
              oauth_error: "email_already_exists_use_password",
              oauth_client_nonce: String(saved.client_nonce || ""),
            }),
            302,
            {
              "set-cookie": "creatorrr_google_oauth_nonce=; Path=/auth/google/callback; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
            },
          );
        }

        userId = uuid();
        const now = nowIso();
        const salt = makeSalt();
        const hash = await pbkdf2(makeOpaqueSecret(), salt);
        const emailVerifiedAt = idInfo.email_verified === "true" ? now : null;

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
              ) VALUES (?1,?2,?3,?4,?5,?5,?6,NULL,NULL,NULL,NULL)`,
            )
            .bind(userId, email, salt, hash, now, emailVerifiedAt),
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
                cancel_at
              ) VALUES (?1,'none','none','registered_no_license',?2,?2,NULL,NULL,NULL,NULL)`,
            )
            .bind(userId, now),
          env.creatorrr_db
            .prepare(
              `INSERT INTO user_identities (
                user_id,
                provider,
                provider_user_id,
                provider_email,
                created_at,
                updated_at
              ) VALUES (?1, 'google', ?2, ?3, ?4, ?4)`,
            )
            .bind(userId, idInfo.sub, email, now),
        ]);
      }

      const issued = await issueWebToken(env, userId, deviceId);
      if (!issued.ok) {
        return redirect(req, oauthRedirectToSite(env, intent, { oauth_error: issued.reason }));
      }

      const target = `${oauthRedirectToSite(env, intent, {
        oauth_client_nonce: String(saved.client_nonce || ""),
      })}#web_token=${encodeURIComponent(issued.token)}`;
      return redirectWithHeaders(req, target, 302, {
        "set-cookie": "creatorrr_google_oauth_nonce=; Path=/auth/google/callback; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
      });
    }

    if (req.method === "POST" && url.pathname === "/auth/register") {
      const body = await readJson<{ email?: string; password?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      const password = String(body.password || "");
      if (!email || password.length < 8) return bad(req, "invalid_input");

      const existing = await env.creatorrr_db.prepare("SELECT id FROM users WHERE email=?1").bind(email).first();
      if (existing) return bad(req, "email_exists", 409);

      const userId = uuid();
      const salt = makeSalt();
      const hash = await pbkdf2(password, salt);
      const now = nowIso();

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
            ) VALUES (?1,?2,?3,?4,?5,?5,NULL,NULL,NULL,NULL,NULL)`,
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
              cancel_at
            ) VALUES (?1,'none','none','registered_no_license',?2,?2,NULL,NULL,NULL,NULL)`,
          )
          .bind(userId, now),
      ]);

      const emailVerification = await issueEmailVerification(env, userId, email);

      return json(req, {
        ok: true,
        userId,
        email,
        email_verification_sent: emailVerification.sent,
        email_delivery_configured: isEmailDeliveryConfigured(env),
      });
    }

    if (req.method === "POST" && url.pathname === "/auth/verify-email") {
      const body = await readJson<{ token?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const rawToken = String(body.token || "").trim();
      if (!rawToken) return bad(req, "invalid_input");

      const tokenHash = await sha256Hex(rawToken);
      const user = await getUserByVerifyTokenHash(env, tokenHash);

      if (!user) return bad(req, "invalid_or_expired_verify_token", 400);
      if (isExpiredIso(user.email_verify_expires_at || null)) {
        return bad(req, "invalid_or_expired_verify_token", 400);
      }

      const now = nowIso();
      await env.creatorrr_db
        .prepare(
          `
            UPDATE users
            SET
              email_verified_at=COALESCE(email_verified_at, ?2),
              email_verify_token_hash=NULL,
              email_verify_expires_at=NULL,
              updated_at=?2
            WHERE id=?1
          `,
        )
        .bind(user.id, now)
        .run();

      return json(req, { ok: true, verified: true, email: user.email });
    }

    if (req.method === "POST" && url.pathname === "/auth/resend-verification") {
      const body = await readJson<{ email?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      if (!email) return bad(req, "invalid_input");

      const user = await getUserByEmail(env, email);
      if (!user || user.email_verified_at) return json(req, { ok: true, sent: true });

      const result = await issueEmailVerification(env, user.id, user.email);
      return json(req, {
        ok: true,
        sent: result.sent,
        expires_at: result.expires_at,
        email_delivery_configured: isEmailDeliveryConfigured(env),
      });
    }

    if (req.method === "POST" && url.pathname === "/auth/login") {
      const body = await readJson<{ email?: string; password?: string; deviceId?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      const password = String(body.password || "");
      const deviceId = normalizeDeviceId(String(body.deviceId || ""));

      if (!email || !password) return bad(req, "invalid_input");
      if (!deviceId) return bad(req, "missing_device_id", 400);

      const user = await getUserByEmail(env, email);
      if (!user) return bad(req, "invalid_credentials", 401);

      const hash = await pbkdf2(password, user.pass_salt);
      if (hash !== user.pass_hash) return bad(req, "invalid_credentials", 401);

      if (!user.email_verified_at) {
        return bad(req, "email_not_verified", 403, {
          email_delivery_configured: isEmailDeliveryConfigured(env),
        });
      }

      const allow = await ensureDeviceAllowed(env, user.id, deviceId);
      if (!allow.ok) return bad(req, allow.reason || "device_not_allowed", 403);

      const tv = await currentDeviceTokenVersion(env, user.id, deviceId);
      if (tv === null) return bad(req, "device_not_registered", 403);

      const lic = await getLicenseRow(env, user.id);
      const entitlement = computeEntitlement(lic);

      const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7;
      const token = await jwtSign(env.JWT_SECRET, { sub: user.id, exp, did: deviceId, tv });

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

    if (req.method === "POST" && url.pathname === "/auth/logout") {
      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;
      await revokeCurrentDevice(env, auth.ctx.userId, auth.ctx.deviceId);
      return json(req, { ok: true });
    }

    if (req.method === "POST" && url.pathname === "/auth/logout-other-devices") {
      const body = await readJson<{ email?: string; password?: string; deviceId?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      const password = String(body.password || "");
      const deviceId = normalizeDeviceId(String(body.deviceId || ""));

      if (!email || !password) return bad(req, "invalid_input");
      if (!deviceId) return bad(req, "missing_device_id", 400);

      const user = await getUserByEmail(env, email);
      if (!user) return bad(req, "invalid_credentials", 401);

      const hash = await pbkdf2(password, user.pass_salt);
      if (hash !== user.pass_hash) return bad(req, "invalid_credentials", 401);

      if (!user.email_verified_at) {
        return bad(req, "email_not_verified", 403, {
          email_delivery_configured: isEmailDeliveryConfigured(env),
        });
      }

      await revokeOtherUserDevices(env, user.id, deviceId);

      return json(req, { ok: true, device_id: deviceId });
    }

    if (req.method === "POST" && url.pathname === "/auth/forgot-password") {
      const body = await readJson<{ email?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const email = normalizeEmail(String(body.email || ""));
      if (!email) return bad(req, "invalid_input");

      const user = await getUserByEmail(env, email);
      if (!user) return json(req, { ok: true, sent: true });

      return json(req, {
        ok: true,
        ...(await issuePasswordReset(env, user.id, user.email)),
      });
    }

    if (req.method === "POST" && url.pathname === "/auth/reset-password") {
      const body = await readJson<{ token?: string; password?: string }>(req);
      if (!body) return bad(req, "invalid_json");

      const rawToken = String(body.token || "").trim();
      const newPassword = String(body.password || "");
      if (!rawToken || !newPassword || newPassword.length < 8) return bad(req, "invalid_input");

      const tokenHash = await sha256Hex(rawToken);
      const user = await getUserByResetTokenHash(env, tokenHash);

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
      return json(req, { ok: true, reset: true });
    }

    if (req.method === "GET" && url.pathname === "/account/me") {
      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const user = await getUserById(env, auth.ctx.userId);
      if (!user) return bad(req, "user_not_found", 404);

      let lic = await getLicenseRow(env, auth.ctx.userId);
      let stripeSyncError: string | null = null;

      if (env.STRIPE_SECRET_KEY?.trim()) {
        try {
          lic = await refreshLicenseFromStripe(env, auth.ctx.userId, lic);
        } catch (err) {
          stripeSyncError = err instanceof Error ? err.message : "stripe_sync_error";
          console.error("[account/me] stripe sync failed", {
            userId: auth.ctx.userId,
            error: stripeSyncError,
          });
        }
      }

      const hasAcceptedCurrentVersions = await hasAcceptedCurrentLegalVersions(env, auth.ctx.userId);

      return json(req, {
        ok: true,
        ...makeAccountView(user, lic, { hasAcceptedCurrentVersions }),
        stripe_sync_error: stripeSyncError,
      });
    }

    if (req.method === "GET" && url.pathname === "/license/me") {
      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const lic = await getLicenseRow(env, auth.ctx.userId);
      return json(req, { ok: true, ...computeEntitlement(lic) });
    }

    if (req.method === "POST" && url.pathname === "/analytics/pageview") {
      const body = await readJson<{
        path?: string;
        query?: string;
        referrer?: string | null;
        title?: string | null;
        tz?: string | null;
        screen?: string | null;
        lang?: string | null;
      }>(req);

      if (!body) return bad(req, "invalid_json");

      const path = String(body.path || "").trim();
      if (!path.startsWith("/")) return bad(req, "invalid_path");

      const ip = getRequestIpAddress(req);
      const ipHash = ip ? await sha256Hex(ip) : null;
      const { isBot, botScore } = detectLikelyBot(req);
      const visitId = uuid();

      await env.creatorrr_db.prepare(
        `INSERT INTO analytics_pageviews (
          id, created_at, path, query, referrer, title, country, user_agent, ip_hash, is_bot, bot_score, timezone, screen, language
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)`,
      ).bind(
        visitId,
        nowIso(),
        path.slice(0, 512),
        String(body.query || "").slice(0, 1024),
        body.referrer ? String(body.referrer).slice(0, 1024) : null,
        body.title ? String(body.title).slice(0, 512) : null,
        getCountryCode(req),
        getRequestUserAgent(req),
        ipHash,
        isBot ? 1 : 0,
        botScore,
        body.tz ? String(body.tz).slice(0, 128) : null,
        body.screen ? String(body.screen).slice(0, 64) : null,
        body.lang ? String(body.lang).slice(0, 64) : null,
      ).run();

      return json(req, { ok: true });
    }

    if (req.method === "POST" && url.pathname === "/analytics/event") {
      const body = await readJson<{
        event?: string;
        item_id?: string | null;
        item_version?: string | null;
        item_variant?: string | null;
        path?: string | null;
      }>(req);
      if (!body) return bad(req, "invalid_json");

      const eventName = String(body.event || "").trim().toLowerCase();
      if (!ANALYTICS_ALLOWED_EVENTS.has(eventName)) return bad(req, "invalid_event");

      const itemId = normalizeAnalyticsField(body.item_id, 256);
      const itemVersion = normalizeAnalyticsField(body.item_version, 64);
      const itemVariant = normalizeAnalyticsField(body.item_variant, 64);
      const path = normalizeAnalyticsField(body.path, 512);

      if (!itemId || !itemVersion || !itemVariant) {
        return bad(req, "invalid_event_payload");
      }
      if (!isSafeAnalyticsToken(itemId) || !isSafeAnalyticsToken(itemVersion) || !isSafeAnalyticsToken(itemVariant)) {
        return bad(req, "invalid_event_payload");
      }
      if (path && !path.startsWith("/")) return bad(req, "invalid_event_payload");

      const ip = getRequestIpAddress(req);
      const ipHash = ip ? await sha256Hex(ip) : null;
      const { isBot, botScore } = detectLikelyBot(req);

      await env.creatorrr_db
        .prepare(
          `INSERT INTO analytics_events (
            id, created_at, event_name, item_id, item_version, item_variant, path, country, user_agent, ip_hash, is_bot, bot_score
          ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`,
        )
        .bind(
          uuid(),
          nowIso(),
          eventName.slice(0, 64),
          itemId,
          itemVersion,
          itemVariant,
          path,
          getCountryCode(req),
          getRequestUserAgent(req),
          ipHash,
          isBot ? 1 : 0,
          botScore,
        )
        .run();

      return json(req, { ok: true });
    }

    if (req.method === "GET" && url.pathname === "/dashboard/overview") {
      const owner = await requireDashboardOwner(req, env);
      if (!owner.ok) return owner.response;

      const hiddenUserIds = getDashboardHiddenUserIds(env);
      const hiddenPlaceholders = hiddenUserIds.map((_, idx) => `?${idx + 1}`).join(", ");
      const userExclusionClause = hiddenUserIds.length > 0 ? ` WHERE id NOT IN (${hiddenPlaceholders})` : "";
      const licenseExclusionClause = hiddenUserIds.length > 0 ? ` AND user_id NOT IN (${hiddenPlaceholders})` : "";

      const countValue = async (sql: string, bindValues: string[] = []): Promise<number> => {
        const row = await env.creatorrr_db.prepare(sql).bind(...bindValues).first<{ c?: number | string | null }>();
        const n = Number(row?.c ?? 0);
        return Number.isFinite(n) ? n : 0;
      };

      const totalUsers = await countValue(`SELECT COUNT(*) AS c FROM users${userExclusionClause}`, hiddenUserIds);
      const verifiedUsers = await countValue(
        `SELECT COUNT(*) AS c FROM users WHERE email_verified_at IS NOT NULL${hiddenUserIds.length > 0 ? ` AND id NOT IN (${hiddenPlaceholders})` : ""}`,
        hiddenUserIds,
      );
      const usersLast7Days = await countValue(`
        SELECT COUNT(*) AS c
        FROM users
        WHERE julianday(created_at) >= julianday('now', '-7 days')
        ${hiddenUserIds.length > 0 ? `AND id NOT IN (${hiddenPlaceholders})` : ""}
      `, hiddenUserIds);
      const payingSubscribers = await countValue(`
        SELECT COUNT(*) AS c
        FROM licenses
        WHERE status IN ('active', 'past_due', 'unpaid', 'canceling')
          AND plan <> 'free'
          ${licenseExclusionClause}
      `, hiddenUserIds);
      const trialingUsers = await countValue(
        `SELECT COUNT(*) AS c FROM licenses WHERE status='trialing'${licenseExclusionClause}`,
        hiddenUserIds,
      );
      const cancelingUsers = await countValue(
        `SELECT COUNT(*) AS c FROM licenses WHERE status='canceling'${licenseExclusionClause}`,
        hiddenUserIds,
      );
      const paymentRisk = await countValue(
        `SELECT COUNT(*) AS c FROM licenses WHERE status IN ('past_due','unpaid')${licenseExclusionClause}`,
        hiddenUserIds,
      );
      const monthSubs = await countValue(`
        SELECT COUNT(*) AS c
        FROM licenses
        WHERE status IN ('active', 'trialing', 'past_due', 'unpaid', 'canceling')
          AND billing_interval='month'
          AND plan <> 'free'
          ${licenseExclusionClause}
      `, hiddenUserIds);
      const yearSubs = await countValue(`
        SELECT COUNT(*) AS c
        FROM licenses
        WHERE status IN ('active', 'trialing', 'past_due', 'unpaid', 'canceling')
          AND billing_interval='year'
          AND plan <> 'free'
          ${licenseExclusionClause}
      `, hiddenUserIds);

      const monthlyPriceUsd = dashboardPriceUsd(env.DASHBOARD_MONTHLY_PRICE_USD, 29.9);
      const yearlyPriceUsd = dashboardPriceUsd(env.DASHBOARD_YEARLY_PRICE_USD, 239);
      const estimatedMrr = (monthSubs * monthlyPriceUsd) + ((yearSubs * yearlyPriceUsd) / 12);
      const verificationRate = totalUsers > 0 ? verifiedUsers / totalUsers : 0;

      return json(req, {
        ok: true,
        owner_email: owner.email,
        generated_at: nowIso(),
        metrics: {
          total_users: totalUsers,
          verified_users: verifiedUsers,
          verification_rate: verificationRate,
          new_users_last_7_days: usersLast7Days,
          paying_subscribers: payingSubscribers,
          trialing_users: trialingUsers,
          canceling_users: cancelingUsers,
          payment_risk_users: paymentRisk,
          month_subscribers: monthSubs,
          year_subscribers: yearSubs,
          monthly_price_usd: monthlyPriceUsd,
          yearly_price_usd: yearlyPriceUsd,
          estimated_mrr_usd: Number(estimatedMrr.toFixed(2)),
        },
      });
    }

    if (req.method === "GET" && url.pathname === "/dashboard/traffic") {
      const owner = await requireDashboardOwner(req, env);
      if (!owner.ok) return owner.response;

      const totalsRow = await env.creatorrr_db.prepare(`
        SELECT
          COUNT(*) AS pageviews_30d,
          COUNT(DISTINCT ip_hash) AS unique_visitors_30d,
          SUM(CASE WHEN is_bot=1 THEN 1 ELSE 0 END) AS bot_pageviews_30d,
          SUM(CASE WHEN is_bot=0 THEN 1 ELSE 0 END) AS human_pageviews_30d
        FROM analytics_pageviews
        WHERE julianday(created_at) >= julianday('now', '-30 days')
      `).first<{
        pageviews_30d?: number | string | null;
        unique_visitors_30d?: number | string | null;
        bot_pageviews_30d?: number | string | null;
        human_pageviews_30d?: number | string | null;
      }>();

      const countryRows = await env.creatorrr_db.prepare(`
        SELECT country, COUNT(*) AS visits
        FROM analytics_pageviews
        WHERE julianday(created_at) >= julianday('now', '-30 days')
        GROUP BY country
        ORDER BY visits DESC
        LIMIT 10
      `).all<{ country?: string | null; visits?: number | string | null }>();

      const pathRows = await env.creatorrr_db.prepare(`
        SELECT path, COUNT(*) AS visits
        FROM analytics_pageviews
        WHERE julianday(created_at) >= julianday('now', '-30 days')
        GROUP BY path
        ORDER BY visits DESC
        LIMIT 10
      `).all<{ path?: string | null; visits?: number | string | null }>();

      const numberOrZero = (value: unknown): number => {
        const n = Number(value ?? 0);
        return Number.isFinite(n) ? n : 0;
      };

      const downloadRows = await env.creatorrr_db.prepare(`
        SELECT
          item_id,
          item_version,
          item_variant,
          COUNT(*) AS downloads
        FROM analytics_events
        WHERE event_name='download_click'
          AND julianday(created_at) >= julianday('now', '-30 days')
          AND is_bot=0
        GROUP BY item_id, item_version, item_variant
        ORDER BY downloads DESC
        LIMIT 30
      `).all<{
        item_id?: string | null;
        item_version?: string | null;
        item_variant?: string | null;
        downloads?: number | string | null;
      }>();

      return json(req, {
        ok: true,
        generated_at: nowIso(),
        window_days: 30,
        totals: {
          pageviews: numberOrZero(totalsRow?.pageviews_30d),
          unique_visitors: numberOrZero(totalsRow?.unique_visitors_30d),
          bot_pageviews: numberOrZero(totalsRow?.bot_pageviews_30d),
          human_pageviews: numberOrZero(totalsRow?.human_pageviews_30d),
        },
        countries: (countryRows.results || []).map((row) => ({
          country: String(row.country || "ZZ"),
          visits: numberOrZero(row.visits),
        })),
        top_pages: (pathRows.results || []).map((row) => ({
          path: String(row.path || "/"),
          visits: numberOrZero(row.visits),
        })),
        downloads: (downloadRows.results || []).map((row) => ({
          item_id: String(row.item_id || "unknown"),
          item_version: String(row.item_version || "-"),
          item_variant: String(row.item_variant || "-"),
          downloads: numberOrZero(row.downloads),
        })),
      });
    }


    if (req.method === "POST" && url.pathname === "/license/trial/start") {
      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const body = await readJson<{ legal_acceptance?: LegalAcceptancePayload }>(req);
      if (!body) return bad(req, "invalid_json");

      const lic = await getLicenseRow(env, auth.ctx.userId);

      const currentStatus = String(lic?.status || "").trim().toLowerCase();
      const billingInterval = String(lic?.billing_interval || "").trim().toLowerCase();
      const currentPeriodEndMs = Date.parse(String(lic?.current_period_end || ""));
      const trialEndMs = Date.parse(String(lic?.trial_end_at || ""));

      const hasRecurringSubscription =
        (billingInterval === "month" || billingInterval === "year") &&
        Number.isFinite(currentPeriodEndMs) &&
        currentPeriodEndMs > Date.now() &&
        ["active", "trialing", "past_due", "canceling"].includes(currentStatus);

      if (hasRecurringSubscription) {
        return bad(req, "subscription_already_active", 409, {
          message: "You already have an active paid subscription.",
        });
      }

      const hasUsedTrial = Boolean(String(lic?.trial_start_at || "").trim() || String(lic?.trial_end_at || "").trim() || String(lic?.stripe_customer_id || "").trim() || String(lic?.stripe_subscription_id || "").trim());
      const hasLiveTrial = Number.isFinite(trialEndMs) && trialEndMs > Date.now() && (currentStatus === "trialing" || currentStatus === "active");

      if (hasLiveTrial) {
        const user = await getUserById(env, auth.ctx.userId);
        if (!user) return bad(req, "user_not_found", 404);
        const hasAcceptedCurrentVersions = await hasAcceptedCurrentLegalVersions(env, auth.ctx.userId);
        return json(req, {
          ok: true,
          ...makeAccountView(user, lic, {
            hasAcceptedCurrentVersions,
          }),
        });
      }

      if (hasUsedTrial) {
        return bad(req, "trial_already_used", 409, {
          message: "Free trial already used on this account.",
        });
      }

      const legalAcceptance = await ensureCurrentLegalAcceptance(
        req,
        env,
        auth.ctx.userId,
        "license_trial_start",
        body.legal_acceptance,
      );
      if (!legalAcceptance.ok) return legalAcceptance.response;

      const now = nowIso();
      const trialEndAt = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();

      await env.creatorrr_db
        .prepare(
          `
            INSERT INTO licenses (
              user_id,
              plan,
              status,
              notes,
              created_at,
              updated_at,
              billing_interval,
              current_period_start,
              current_period_end,
              trial_start_at,
              trial_end_at,
              cancel_at,
              canceled_at,
              ended_at,
              stripe_customer_id,
              stripe_subscription_id,
              stripe_price_id
            )
            VALUES (?1, 'trial', 'trialing', 'local free trial', ?2, ?2, NULL, NULL, NULL, ?2, ?3, NULL, NULL, NULL, NULL, NULL, NULL)
            ON CONFLICT(user_id) DO UPDATE SET
              plan='trial',
              status='trialing',
              notes='local free trial',
              updated_at=excluded.updated_at,
              billing_interval=NULL,
              current_period_start=NULL,
              current_period_end=NULL,
              trial_start_at=excluded.trial_start_at,
              trial_end_at=excluded.trial_end_at,
              scheduled_billing_interval=NULL,
              scheduled_change_at=NULL,
              cancel_at=NULL,
              canceled_at=NULL,
              ended_at=NULL,
              stripe_customer_id=NULL,
              stripe_subscription_id=NULL,
              stripe_price_id=NULL
          `,
        )
        .bind(auth.ctx.userId, now, trialEndAt)
        .run();

      const user = await getUserById(env, auth.ctx.userId);
      if (!user) return bad(req, "user_not_found", 404);

      const updatedLic = await getLicenseRow(env, auth.ctx.userId);
      return json(req, {
        ok: true,
        ...makeAccountView(user, updatedLic, {
          hasAcceptedCurrentVersions: legalAcceptance.hasAcceptedCurrentVersions,
        }),
      });
    }

    if (req.method === "POST" && url.pathname === "/stripe/checkout") {
      const cfgErr = requireStripeCheckoutConfig(req, env);
      if (cfgErr) return cfgErr;

      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const body = await readJson<{ interval?: string; legal_acceptance?: LegalAcceptancePayload }>(req);
      if (!body) return bad(req, "invalid_json");

      const interval = String(body.interval || "").trim().toLowerCase();
      if (interval !== "month" && interval !== "year") {
        return bad(req, "invalid_interval", 400, { allowed: ["month", "year"] });
      }

      let lic = await getLicenseRow(env, auth.ctx.userId);
      if (env.STRIPE_SECRET_KEY?.trim()) {
        try {
          lic = await refreshLicenseFromStripe(env, auth.ctx.userId, lic);
        } catch (err) {
          console.error("[checkout] stripe sync failed", {
            userId: auth.ctx.userId,
            error: err instanceof Error ? err.message : "stripe_sync_error",
          });
        }
      }

      const currentInterval = String(lic?.billing_interval || "").trim().toLowerCase();
      const currentStatus = String(lic?.status || "").trim().toLowerCase();
      const currentPeriodEndMs = Date.parse(String(lic?.current_period_end || ""));
      const hasLocalRecurringAccess =
        (currentInterval === "month" || currentInterval === "year") &&
        Number.isFinite(currentPeriodEndMs) &&
        currentPeriodEndMs > Date.now() &&
        ["active", "trialing", "past_due", "canceling"].includes(currentStatus);

      let liveSubscription: StripeSubscriptionLike | null = null;
      try {
        liveSubscription = await findLiveStripeSubscriptionForLicense(env, lic);
      } catch (err) {
        console.error("[checkout] live subscription lookup failed", {
          userId: auth.ctx.userId,
          error: err instanceof Error ? err.message : "stripe_lookup_error",
        });
      }

      const liveInterval = String(
        liveSubscription?.items?.data?.[0]?.price?.recurring?.interval ||
        currentInterval
      ).trim().toLowerCase();
      const hasLiveRecurringSubscription = Boolean(liveSubscription) || hasLocalRecurringAccess;

      if (hasLiveRecurringSubscription) {
        if (liveInterval === interval) {
          return bad(req, "already_on_plan", 409, {
            message: "You already have this plan. Manage renewal from your account instead of buying it again.",
          });
        }

        return bad(req, "existing_subscription_conflict", 409, {
          message: currentInterval === "month"
            ? "You already have monthly access. Use Renew yearly from your account."
            : "You already have yearly access. Use Renew monthly from your account.",
        });
      }

      const legalAcceptanceCheck = await ensureCurrentLegalAcceptance(
        req,
        env,
        auth.ctx.userId,
        "stripe_checkout",
        body.legal_acceptance,
      );
      if (!legalAcceptanceCheck.ok) return legalAcceptanceCheck.response;

      const email = await getUserEmail(env, auth.ctx.userId);
      if (!email) return bad(req, "user_email_not_found", 404);

      try {
        const session = await createStripeCheckoutSession(
          env,
          auth.ctx.userId,
          email,
          interval as "month" | "year",
        );

        if (!session.url) return bad(req, "stripe_checkout_url_missing", 502);

        return json(req, {
          ok: true,
          url: session.url,
          sessionId: session.id,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : "stripe_checkout_failed";
        return bad(req, "stripe_checkout_failed", 502, { message });
      }
    }

    if (req.method === "POST" && url.pathname === "/stripe/subscription/upgrade-yearly") {
      const cfgErr = requireStripeCheckoutConfig(req, env);
      if (cfgErr) return cfgErr;

      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      let lic = await getLicenseRow(env, auth.ctx.userId);

      if (env.STRIPE_SECRET_KEY?.trim()) {
        try {
          lic = await refreshLicenseFromStripe(env, auth.ctx.userId, lic);
        } catch (err) {
          console.error("[upgrade-yearly] stripe sync failed", {
            userId: auth.ctx.userId,
            error: err instanceof Error ? err.message : "stripe_sync_error",
          });
        }
      }

      const currentInterval = String(lic?.billing_interval || "").trim().toLowerCase();
      const currentStatus = String(lic?.status || "").trim().toLowerCase();
      const currentPeriodEndMs = Date.parse(String(lic?.current_period_end || ""));
      const trialEndMs = Date.parse(String(lic?.trial_end_at || ""));
      const hasFutureMonthlyAccess =
        (Number.isFinite(currentPeriodEndMs) && currentPeriodEndMs > Date.now()) ||
        (currentStatus === "trialing" && Number.isFinite(trialEndMs) && trialEndMs > Date.now());
      const isMonthlyActive =
        currentInterval === "month" &&
        hasFutureMonthlyAccess &&
        ["active", "trialing", "past_due", "canceling"].includes(currentStatus);

      if (!isMonthlyActive) {
        return bad(req, "monthly_subscription_required", 409, {
          message: "Monthly subscription required for yearly upgrade.",
        });
      }

      try {
        const updated = await scheduleStripeSubscriptionIntervalChange(env, auth.ctx.userId, lic, "year");
        if (!updated.ok) {
          return bad(req, updated.reason, 400, {
            message: "Could not schedule yearly renewal.",
          });
        }

        let freshLic = await getLicenseRow(env, auth.ctx.userId);
        if (env.STRIPE_SECRET_KEY?.trim()) {
          try {
            freshLic = await refreshLicenseFromStripe(env, auth.ctx.userId, freshLic);
          } catch (err) {
            console.error("[upgrade-yearly] post-upgrade stripe sync failed", {
              userId: auth.ctx.userId,
              error: err instanceof Error ? err.message : "stripe_sync_error",
            });
          }
        }
        const user = await getUserById(env, auth.ctx.userId);
        if (!user) return bad(req, "user_not_found", 404);

        return json(req, { ok: true, ...makeAccountView(user, freshLic) });
      } catch (err) {
        const message = err instanceof Error ? err.message : "stripe_upgrade_failed";
        return bad(req, "stripe_upgrade_failed", 502, { message });
      }
    }

    if (req.method === "POST" && url.pathname === "/stripe/subscription/downgrade-monthly") {
      const cfgErr = requireStripeCheckoutConfig(req, env);
      if (cfgErr) return cfgErr;

      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      let lic = await getLicenseRow(env, auth.ctx.userId);

      if (env.STRIPE_SECRET_KEY?.trim()) {
        try {
          lic = await refreshLicenseFromStripe(env, auth.ctx.userId, lic);
        } catch (err) {
          console.error("[downgrade-monthly] stripe sync failed", {
            userId: auth.ctx.userId,
            error: err instanceof Error ? err.message : "stripe_sync_error",
          });
        }
      }

      const currentInterval = String(lic?.billing_interval || "").trim().toLowerCase();
      const scheduledInterval = String(lic?.scheduled_billing_interval || "").trim().toLowerCase();
      const currentStatus = String(lic?.status || "").trim().toLowerCase();
      const currentPeriodEndMs = Date.parse(String(lic?.current_period_end || ""));

      const hasFuturePaidAccess =
        Number.isFinite(currentPeriodEndMs) &&
        currentPeriodEndMs > Date.now() &&
        ["active", "trialing", "past_due", "canceling"].includes(currentStatus);

      const canSwitchRenewalToMonthly =
        hasFuturePaidAccess &&
        (
          currentInterval === "year" ||
          scheduledInterval === "year"
        );

      if (!canSwitchRenewalToMonthly) {
        return bad(req, "monthly_renewal_change_not_allowed", 409, {
          message: "A paid subscription with yearly billing or yearly renewal is required.",
        });
      }

      try {
        const updated = await scheduleStripeSubscriptionIntervalChange(env, auth.ctx.userId, lic, "month");
        if (!updated.ok) {
          return bad(req, updated.reason, 400, {
            message: "Could not schedule monthly renewal.",
          });
        }

        let freshLic = await getLicenseRow(env, auth.ctx.userId);
        if (env.STRIPE_SECRET_KEY?.trim()) {
          try {
            freshLic = await refreshLicenseFromStripe(env, auth.ctx.userId, freshLic);
          } catch (err) {
            console.error("[downgrade-monthly] post-downgrade stripe sync failed", {
              userId: auth.ctx.userId,
              error: err instanceof Error ? err.message : "stripe_sync_error",
            });
          }
        }

        const user = await getUserById(env, auth.ctx.userId);
        if (!user) return bad(req, "user_not_found", 404);

        return json(req, { ok: true, ...makeAccountView(user, freshLic) });
      } catch (err) {
        const message = err instanceof Error ? err.message : "stripe_schedule_change_failed";
        return bad(req, "stripe_schedule_change_failed", 502, { message });
      }
    }

    if (req.method === "POST" && url.pathname === "/stripe/portal") {
      const cfgErr = requireStripePortalConfig(req, env);
      if (cfgErr) return cfgErr;

      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      let lic = await getLicenseRow(env, auth.ctx.userId);

      if (env.STRIPE_SECRET_KEY?.trim()) {
        try {
          lic = await refreshLicenseFromStripe(env, auth.ctx.userId, lic);
        } catch (err) {
          console.error("[portal] stripe sync failed", {
            userId: auth.ctx.userId,
            error: err instanceof Error ? err.message : "stripe_sync_error",
          });
        }
      }

      let customerId: string | null = null;
      try {
        customerId = await recoverStripeCustomerId(env, auth.ctx.userId, lic);
      } catch (err) {
        console.error("[portal] stripe customer recovery failed", {
          userId: auth.ctx.userId,
          error: err instanceof Error ? err.message : "stripe_customer_recovery_failed",
        });
      }

      if (!customerId) {
        return bad(req, "no_stripe_customer", 400, {
          message: "No Stripe subscription found for this account yet. Start a paid plan first, then use Manage subscription.",
        });
      }

      try {
        const session = await createStripePortalSession(env, customerId);
        if (!session.url) return bad(req, "stripe_portal_url_missing", 502);
        return json(req, { ok: true, url: session.url });
      } catch (err) {
        const message = err instanceof Error ? err.message : "stripe_portal_failed";
        return bad(req, "stripe_portal_failed", 502, { message });
      }
    }

if (req.method === "POST" && url.pathname === "/stripe/subscription/auto-renew") {
  if (!env.STRIPE_SECRET_KEY?.trim()) return bad(req, "missing_stripe_secret", 500);

  const auth = await requireAuth(req, env);
  if (!auth.ok) return auth.response;

  const body = await readJson<{ enabled?: boolean }>(req);
  if (!body || typeof body.enabled !== "boolean") return bad(req, "invalid_input", 400);

  let lic = await getLicenseRow(env, auth.ctx.userId);

  console.log("[auto-renew] start", {
    userId: auth.ctx.userId,
    requestedEnabled: body.enabled,
    lic,
  });

  try {
    lic = await refreshLicenseFromStripe(env, auth.ctx.userId, lic);
  } catch (err) {
    console.error("[auto-renew] pre-refresh failed", {
      userId: auth.ctx.userId,
      error: err instanceof Error ? err.message : "stripe_sync_error",
    });
  }

  try {
    const updated = await updateStripeSubscriptionAutoRenew(env, auth.ctx.userId, lic, body.enabled);

    if (!updated.ok) {
      console.error("[auto-renew] update failed", {
        userId: auth.ctx.userId,
        reason: updated.reason,
      });

      return bad(req, updated.reason, 400, {
        message:
          updated.reason === "no_stripe_subscription"
            ? "No Stripe subscription found yet for this account."
            : updated.reason === "missing_current_period_end"
              ? "Current billing period end could not be determined."
              : "Could not update auto-renew.",
      });
    }

    let freshLic = await getLicenseRow(env, auth.ctx.userId);

    try {
      freshLic = await refreshLicenseFromStripe(env, auth.ctx.userId, freshLic);
    } catch (err) {
      console.error("[auto-renew] post-refresh failed", {
        userId: auth.ctx.userId,
        error: err instanceof Error ? err.message : "stripe_sync_error",
      });
    }

    const user = await getUserById(env, auth.ctx.userId);
    if (!user) return bad(req, "user_not_found", 404);

    return json(req, { ok: true, ...makeAccountView(user, freshLic) });
  } catch (err) {
    const message = err instanceof Error ? err.message : "stripe_auto_renew_failed";

    console.error("[auto-renew] exception", {
      userId: auth.ctx.userId,
      message,
    });

    return bad(req, "stripe_auto_renew_failed", 502, { message });
  }
}

    return bad(req, "not_found", 404);
  },
};
