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
import type { Env, StripeSubscriptionLike, UserRow } from "./types";
import { computeEntitlement } from "./services/entitlement";
import {
  currentDeviceTokenVersion,
  ensureDeviceAllowed,
  getLicenseRow,
  getUserByEmail,
  getUserById,
  getUserByResetTokenHash,
  getUserByVerifyTokenHash,
  getUserEmail,
  requireAuth,
  revokeAllUserDevices,
  revokeCurrentDevice,
} from "./services/db";
import {
  createStripeCheckoutSession,
  createStripePortalSession,
  handleCheckoutSessionCompleted,
  recoverStripeCustomerId,
  requireStripeCheckoutConfig,
  requireStripePortalConfig,
  refreshLicenseFromStripe,
  updateStripeSubscriptionAutoRenew,
  upgradeStripeSubscriptionToYearly,
  upsertLicenseFromStripeSubscription,
  verifyStripeWebhookSignature,
} from "./services/stripe";
import { getGoogleIdTokenInfo, getUserIdByGoogleSub, issueWebToken, oauthRedirectToSite } from "./services/oauth-google";
import { isEmailDeliveryConfigured, issueEmailVerification, issuePasswordReset } from "./services/email";

function makeAccountView(user: UserRow, lic: Awaited<ReturnType<typeof getLicenseRow>>) {
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
      can_manage_subscription: Boolean(lic?.stripe_customer_id || lic?.stripe_subscription_id),
      billing_interval: lic?.billing_interval || null,
      current_period_end: lic?.current_period_end || null,
      trial_start_at: lic?.trial_start_at || null,
      trial_end_at: lic?.trial_end_at || null,
    },
  };
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
                cancel_at_period_end
              ) VALUES (?1,'none','none','registered_no_license',?2,?2,NULL,NULL,NULL,0)`,
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
              cancel_at_period_end
            ) VALUES (?1,'none','none','registered_no_license',?2,?2,NULL,NULL,NULL,0)`,
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
        const emailVerification = await issueEmailVerification(env, user.id, user.email);
        return bad(req, "email_not_verified", 403, {
          email_verification_sent: emailVerification.sent,
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

      return json(req, { ok: true, ...makeAccountView(user, lic), stripe_sync_error: stripeSyncError });
    }

    if (req.method === "GET" && url.pathname === "/license/me") {
      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const lic = await getLicenseRow(env, auth.ctx.userId);
      return json(req, { ok: true, ...computeEntitlement(lic) });
    }

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
      if (withTrial && interval !== "month") {
        return bad(req, "trial_only_on_monthly", 400, {
          message: "Free trial is available only on monthly plans.",
        });
      }

      const lic = await getLicenseRow(env, auth.ctx.userId);
      const currentInterval = String(lic?.billing_interval || "").trim().toLowerCase();
      const currentPeriodEndMs = Date.parse(String(lic?.current_period_end || ""));
      const hasLiveRecurringSubscription =
        (currentInterval === "month" || currentInterval === "year") &&
        Number.isFinite(currentPeriodEndMs) &&
        currentPeriodEndMs > Date.now() &&
        ["active", "trialing", "past_due", "canceling"].includes(String(lic?.status || "").trim().toLowerCase());

      if (hasLiveRecurringSubscription) {
        if (currentInterval === interval) {
          return bad(req, "already_on_plan", 409, {
            message: "You already have an active subscription on this plan.",
          });
        }

        return bad(req, "existing_subscription_conflict", 409, {
          message: "You already have an active subscription. Upgrade from monthly to yearly from your account, or wait until your current period ends.",
        });
      }

      if (withTrial) {
        const hasUsedTrial = Boolean(String(lic?.trial_start_at || "").trim() || String(lic?.trial_end_at || "").trim());
        if (hasUsedTrial) {
          return bad(req, "trial_already_used", 409, {
            message: "Free trial already used on this account.",
          });
        }
      }

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

        if (!session.url) return bad(req, "stripe_checkout_url_missing", 502);

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
      const isMonthlyActive =
        currentInterval === "month" &&
        ["active", "trialing", "past_due", "canceling"].includes(String(lic?.status || "").trim().toLowerCase());

      if (!isMonthlyActive) {
        return bad(req, "monthly_subscription_required", 409, {
          message: "Monthly subscription required for yearly upgrade.",
        });
      }

      try {
        const updated = await upgradeStripeSubscriptionToYearly(env, auth.ctx.userId, lic);
        if (!updated.ok) {
          return bad(req, updated.reason, 400, {
            message: "Could not upgrade subscription to yearly.",
          });
        }

        const freshLic = await getLicenseRow(env, auth.ctx.userId);
        const user = await getUserById(env, auth.ctx.userId);
        if (!user) return bad(req, "user_not_found", 404);

        return json(req, { ok: true, ...makeAccountView(user, freshLic) });
      } catch (err) {
        const message = err instanceof Error ? err.message : "stripe_upgrade_failed";
        return bad(req, "stripe_upgrade_failed", 502, { message });
      }
    }

    if (req.method === "POST" && url.pathname === "/stripe/portal") {
      const cfgErr = requireStripePortalConfig(req, env);
      if (cfgErr) return cfgErr;

      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const lic = await getLicenseRow(env, auth.ctx.userId);
      const customerId = await recoverStripeCustomerId(env, auth.ctx.userId, lic);

      if (!customerId) {
        return bad(req, "no_stripe_customer", 400, {
          message: "No Stripe subscription found for this account yet. Start a plan first, then use Manage subscription.",
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
      const cfgErr = requireStripePortalConfig(req, env);
      if (cfgErr) return cfgErr;

      const auth = await requireAuth(req, env);
      if (!auth.ok) return auth.response;

      const body = await readJson<{ enabled?: boolean }>(req);
      if (!body || typeof body.enabled !== "boolean") return bad(req, "invalid_input", 400);

      const lic = await getLicenseRow(env, auth.ctx.userId);
      const updated = await updateStripeSubscriptionAutoRenew(env, auth.ctx.userId, lic, body.enabled);

      if (!updated.ok) {
        return bad(req, updated.reason, 400, {
          message: "No Stripe subscription found yet for this account.",
        });
      }

      const freshLic = await getLicenseRow(env, auth.ctx.userId);
      const user = await getUserById(env, auth.ctx.userId);
      if (!user) return bad(req, "user_not_found", 404);

      return json(req, { ok: true, ...makeAccountView(user, freshLic) });
    }

    return bad(req, "not_found", 404);
  },
};
