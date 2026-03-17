import type {
  Env,
  LicenseRow,
  StripeCheckoutSessionResponse,
  StripePortalSessionResponse,
  StripeSubscriptionLike,
} from "../types";
import { bad } from "../lib/http";
import { hmacSha256Hex, timingSafeEqualStr } from "../lib/crypto";
import { normalizeSiteUrl, nowIso, unixToIso } from "../lib/utils";

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

export async function verifyStripeWebhookSignature(
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

export function requireStripeCheckoutConfig(req: Request, env: Env): Response | null {
  if (!env.STRIPE_SECRET_KEY?.trim()) return bad(req, "missing_stripe_secret", 500);
  if (!env.STRIPE_PRICE_ID_MONTHLY?.trim()) return bad(req, "missing_monthly_price_id", 500);
  if (!env.STRIPE_PRICE_ID_YEARLY?.trim()) return bad(req, "missing_yearly_price_id", 500);
  if (!env.SITE_URL?.trim()) return bad(req, "missing_site_url", 500);
  return null;
}

export function requireStripePortalConfig(req: Request, env: Env): Response | null {
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

async function stripeGetJson<T>(env: Env, path: string): Promise<T> {
  const res = await fetch(`https://api.stripe.com${path}`, {
    method: "GET",
    headers: {
      authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
    },
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

async function stripeGetSubscriptionById(
  env: Env,
  subscriptionId: string,
): Promise<StripeSubscriptionLike | null> {
  try {
    return await stripeGetJson<StripeSubscriptionLike>(
      env,
      `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "";
    if (message.includes("No such subscription") || message.includes("resource_missing")) {
      return null;
    }
    throw err;
  }
}

function isLiveStripeStatus(statusRaw: string): boolean {
  const s = String(statusRaw || "").trim().toLowerCase();
  return s === "trialing" || s === "active" || s === "past_due" || s === "unpaid";
}

function subscriptionRank(sub: StripeSubscriptionLike): number {
  const status = String(sub.status || "").trim().toLowerCase();
  const cancelAtPeriodEnd = Boolean(sub.cancel_at_period_end);
  const periodEnd = Number(sub.current_period_end || 0);

  if ((status === "trialing" || status === "active" || status === "past_due" || status === "unpaid") && !cancelAtPeriodEnd) {
    return 4000000000 + periodEnd;
  }

  if ((status === "trialing" || status === "active" || status === "past_due" || status === "unpaid") && cancelAtPeriodEnd) {
    return 3000000000 + periodEnd;
  }

  if (status === "canceled") {
    return 2000000000 + periodEnd;
  }

  return 1000000000 + periodEnd;
}

function pickBestSubscription(items: Array<StripeSubscriptionLike | null | undefined>): StripeSubscriptionLike | null {
  const valid = items.filter((x): x is StripeSubscriptionLike => Boolean(x?.id));
  if (!valid.length) return null;
  valid.sort((a, b) => subscriptionRank(b) - subscriptionRank(a));
  return valid[0] || null;
}

export async function recoverStripeCustomerId(env: Env, userId: string, lic: LicenseRow | null): Promise<string | null> {
  const customerId = String(lic?.stripe_customer_id || "").trim();
  if (customerId) return customerId;

  const subscriptionId = String(lic?.stripe_subscription_id || "").trim();
  if (!subscriptionId) return null;

  const subscription = await stripeGetJson<StripeSubscriptionLike>(
    env,
    `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
  );

  const recoveredCustomerId = String(subscription?.customer || "").trim();
  if (!recoveredCustomerId) return null;

  await env.creatorrr_db
    .prepare(`
      UPDATE licenses
      SET stripe_customer_id=?1, updated_at=?2
      WHERE user_id=?3
    `)
    .bind(recoveredCustomerId, nowIso(), userId)
    .run();

  return recoveredCustomerId;
}

export async function createStripeCheckoutSession(
  env: Env,
  userId: string,
  email: string,
  interval: "month" | "year",
): Promise<StripeCheckoutSessionResponse> {
  const priceId = getPriceIdForInterval(env, interval);
  if (!priceId) throw new Error("invalid_interval");

  const siteUrl = normalizeSiteUrl(env.SITE_URL);
  const successUrl = `${siteUrl}/billing/success?session_id={CHECKOUT_SESSION_ID}`;
  const cancelUrl = `${siteUrl}/account.html?intent=${interval === "year" ? "yearly" : "monthly"}&checkout=canceled`;

  const form = new URLSearchParams();
  form.set("mode", "subscription");
  form.set("line_items[0][price]", priceId);
  form.set("line_items[0][quantity]", "1");

  form.set("client_reference_id", userId);
  form.set("customer_email", email);

  form.set("metadata[user_id]", userId);
  form.set("metadata[interval]", interval);

  form.set("subscription_data[metadata][user_id]", userId);
  form.set("subscription_data[metadata][interval]", interval);

  form.set("success_url", successUrl);
  form.set("cancel_url", cancelUrl);

  return await stripePostForm<StripeCheckoutSessionResponse>(
    env,
    "/v1/checkout/sessions",
    form,
  );
}

export async function createStripePortalSession(
  env: Env,
  customerId: string,
): Promise<StripePortalSessionResponse> {
  const siteUrl = normalizeSiteUrl(env.SITE_URL);
  const returnUrl =
    normalizeSiteUrl(env.STRIPE_PORTAL_RETURN_URL || "") ||
    `${siteUrl}/account.html?portal=returned`;

  const form = new URLSearchParams();
  form.set("customer", customerId);
  form.set("return_url", returnUrl);

  return await stripePostForm<StripePortalSessionResponse>(
    env,
    "/v1/billing_portal/sessions",
    form,
  );
}

async function findBestSubscriptionForCustomer(env: Env, customerId: string): Promise<StripeSubscriptionLike | null> {
  const data = await stripeGetJson<{ data?: Array<StripeSubscriptionLike | null> }>(
    env,
    `/v1/subscriptions?customer=${encodeURIComponent(customerId)}&status=all&limit=10`,
  );

  return pickBestSubscription(data?.data || []);
}

async function findLatestSubscriptionIdForCustomer(env: Env, customerId: string): Promise<string | null> {
  const best = await findBestSubscriptionForCustomer(env, customerId);
  const id = String(best?.id || "").trim();
  return id || null;
}


export async function findLiveStripeSubscriptionForLicense(
  env: Env,
  lic: LicenseRow | null,
): Promise<StripeSubscriptionLike | null> {
  const subscriptionId = String(lic?.stripe_subscription_id || "").trim();
  if (subscriptionId) {
    const subscription = await stripeGetSubscriptionById(env, subscriptionId);
    if (subscription && isLiveStripeStatus(String(subscription.status || ""))) {
      return subscription;
    }
    return null;
  }

  const customerId = String(lic?.stripe_customer_id || "").trim();
  if (!customerId) return null;

  const best = await findBestSubscriptionForCustomer(env, customerId);
  if (!best) return null;
  if (!isLiveStripeStatus(String(best.status || ""))) return null;

  return best;
}

export async function refreshLicenseFromStripe(
  env: Env,
  userId: string,
  lic: LicenseRow | null,
): Promise<LicenseRow | null> {
  const customerId = String(lic?.stripe_customer_id || "").trim();
  let subscriptionId = String(lic?.stripe_subscription_id || "").trim();

  if (!customerId && !subscriptionId) {
    return lic;
  }

  let subscription: StripeSubscriptionLike | null = null;

  if (subscriptionId) {
    subscription = await stripeGetSubscriptionById(env, subscriptionId);
    if (!subscription) {
      return lic;
    }
  } else if (customerId) {
    const best = await findBestSubscriptionForCustomer(env, customerId);
    const bestId = String(best?.id || "").trim();
    if (!bestId) {
      return lic;
    }
    subscriptionId = bestId;
    subscription = await stripeGetSubscriptionById(env, subscriptionId);
  }

  if (!subscription) {
    return lic;
  }

  const upsertResult = await upsertLicenseFromStripeSubscription(env, subscription);
  if (!upsertResult.ok) {
    throw new Error(`stripe_upsert_failed:${upsertResult.reason}`);
  }

  const refreshed = await env.creatorrr_db
    .prepare("SELECT * FROM licenses WHERE user_id=?1")
    .bind(userId)
    .first<LicenseRow>();

  return refreshed || lic;
}

export async function upgradeStripeSubscriptionToYearly(
  env: Env,
  userId: string,
  lic: LicenseRow | null,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  let subscriptionId = String(lic?.stripe_subscription_id || "").trim();
  const customerId = String(lic?.stripe_customer_id || "").trim();

  if (!subscriptionId && customerId) {
    subscriptionId = (await findLatestSubscriptionIdForCustomer(env, customerId)) || "";
  }

  if (!subscriptionId) return { ok: false, reason: "no_stripe_subscription" };

  const subscription = await stripeGetJson<StripeSubscriptionLike>(
    env,
    `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
  );

  const itemId = String(subscription.items?.data?.[0]?.id || "").trim();
  if (!itemId) return { ok: false, reason: "subscription_item_missing" };
  if (!env.STRIPE_PRICE_ID_YEARLY?.trim()) return { ok: false, reason: "missing_yearly_price_id" };

  const form = new URLSearchParams();
  form.set("items[0][id]", itemId);
  form.set("items[0][price]", env.STRIPE_PRICE_ID_YEARLY);
  form.set("cancel_at_period_end", "false");

  const status = String(subscription.status || "").trim().toLowerCase();
  const trialEnd = Number(subscription.trial_end || 0);
  const nowSeconds = Math.floor(Date.now() / 1000);

  if (status === "trialing" && trialEnd > nowSeconds) {
    form.set("proration_behavior", "none");
    form.set("trial_end", String(trialEnd));
  } else {
    form.set("proration_behavior", "create_prorations");
    form.set("billing_cycle_anchor", "now");
  }

  const updated = await stripePostForm<StripeSubscriptionLike>(
    env,
    `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
    form,
  );

  const upsertResult = await upsertLicenseFromStripeSubscription(env, updated);
  if (!upsertResult.ok) return { ok: false, reason: upsertResult.reason };

  await env.creatorrr_db
    .prepare(`
      UPDATE licenses
      SET stripe_subscription_id=?2, updated_at=?3
      WHERE user_id=?1
    `)
    .bind(userId, subscriptionId, nowIso())
    .run();

  return { ok: true };
}


export async function downgradeStripeSubscriptionToMonthly(
  env: Env,
  userId: string,
  lic: LicenseRow | null,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  let subscriptionId = String(lic?.stripe_subscription_id || "").trim();
  const customerId = String(lic?.stripe_customer_id || "").trim();

  if (!subscriptionId && customerId) {
    subscriptionId = (await findLatestSubscriptionIdForCustomer(env, customerId)) || "";
  }

  if (!subscriptionId) return { ok: false, reason: "no_stripe_subscription" };

  const subscription = await stripeGetJson<StripeSubscriptionLike>(
    env,
    `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
  );

  const itemId = String(subscription.items?.data?.[0]?.id || "").trim();
  if (!itemId) return { ok: false, reason: "subscription_item_missing" };
  if (!env.STRIPE_PRICE_ID_MONTHLY?.trim()) return { ok: false, reason: "missing_monthly_price_id" };

  const form = new URLSearchParams();
  form.set("items[0][id]", itemId);
  form.set("items[0][price]", env.STRIPE_PRICE_ID_MONTHLY);
  form.set("cancel_at_period_end", "false");
  form.set("proration_behavior", "none");
  form.set("billing_cycle_anchor", "unchanged");

  const updated = await stripePostForm<StripeSubscriptionLike>(
    env,
    `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
    form,
  );

  const upsertResult = await upsertLicenseFromStripeSubscription(env, updated);
  if (!upsertResult.ok) return { ok: false, reason: upsertResult.reason };

  await env.creatorrr_db
    .prepare(`
      UPDATE licenses
      SET stripe_subscription_id=?2, updated_at=?3
      WHERE user_id=?1
    `)
    .bind(userId, subscriptionId, nowIso())
    .run();

  return { ok: true };
}

export async function updateStripeSubscriptionAutoRenew(
  env: Env,
  userId: string,
  lic: LicenseRow | null,
  enabled: boolean,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  let subscriptionId = String(lic?.stripe_subscription_id || "").trim();
  const customerId = String(lic?.stripe_customer_id || "").trim();

  if (!subscriptionId && customerId) {
    subscriptionId = (await findLatestSubscriptionIdForCustomer(env, customerId)) || "";
  }

  if (!subscriptionId) return { ok: false, reason: "no_stripe_subscription" };

  const form = new URLSearchParams();
  form.set("cancel_at_period_end", enabled ? "false" : "true");

  const subscription = await stripePostForm<StripeSubscriptionLike>(
    env,
    `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
    form,
  );

  const upsertResult = await upsertLicenseFromStripeSubscription(env, subscription);
  if (!upsertResult.ok) return { ok: false, reason: upsertResult.reason };

  await env.creatorrr_db
    .prepare(`
      UPDATE licenses
      SET stripe_subscription_id=?2, updated_at=?3
      WHERE user_id=?1
    `)
    .bind(userId, subscriptionId, nowIso())
    .run();

  return { ok: true };
}

function mapStripeStatus(subscription: StripeSubscriptionLike): string {
  const raw = String(subscription.status || "").trim().toLowerCase();
  const cancelAtPeriodEnd = Boolean(subscription.cancel_at_period_end);

  if (isLiveStripeStatus(raw) && cancelAtPeriodEnd) {
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

export async function upsertLicenseFromStripeSubscription(
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

export async function handleCheckoutSessionCompleted(env: Env, session: Record<string, any>): Promise<void> {
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

  const subscriptionId = typeof session.subscription === "string" ? session.subscription.trim() : "";
  if (!subscriptionId) return;

  const subscription = await stripeGetJson<StripeSubscriptionLike>(
    env,
    `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
  );

  await upsertLicenseFromStripeSubscription(env, subscription);
}
