import type {
  Env,
  LicenseRow,
  StripeCheckoutSessionResponse,
  StripePortalSessionResponse,
  StripeSubscriptionScheduleLike,
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

async function stripePostForm<T>(
  env: Env,
  path: string,
  form: URLSearchParams,
  options?: { apiVersion?: string },
): Promise<T> {
  const body = form.toString();

  console.log("[stripePostForm] request", {
    path,
    form: Object.fromEntries(form.entries()),
  });

  const res = await fetch(`https://api.stripe.com${path}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "content-type": "application/x-www-form-urlencoded",
      ...(options?.apiVersion ? { "Stripe-Version": options.apiVersion } : {}),
    },
    body,
  });

  const text = await res.text();

  console.log("[stripePostForm] response", {
    path,
    status: res.status,
    ok: res.ok,
    body: text,
  });

  let data: any = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    console.error("[stripePostForm] invalid_json", {
      path,
      status: res.status,
      body: text,
    });
    throw new Error(`stripe_invalid_json:${res.status}:${text}`);
  }

  if (!res.ok) {
    const msg = data?.error?.message || data?.error?.code || `stripe_error_${res.status}`;
    console.error("[stripePostForm] stripe_error", {
      path,
      status: res.status,
      message: msg,
      error: data?.error || null,
    });
    throw new Error(msg);
  }

  return data as T;
}

async function stripeGetJson<T>(
  env: Env,
  path: string,
  options?: { apiVersion?: string },
): Promise<T> {
  console.log("[stripeGetJson] request", { path });

  const res = await fetch(`https://api.stripe.com${path}`, {
    method: "GET",
    headers: {
      authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      ...(options?.apiVersion ? { "Stripe-Version": options.apiVersion } : {}),
    },
  });

  const text = await res.text();

  console.log("[stripeGetJson] response", {
    path,
    status: res.status,
    ok: res.ok,
    body: text,
  });

  let data: any = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    console.error("[stripeGetJson] invalid_json", {
      path,
      status: res.status,
      body: text,
    });
    throw new Error(`stripe_invalid_json:${res.status}:${text}`);
  }

  if (!res.ok) {
    const msg = data?.error?.message || data?.error?.code || `stripe_error_${res.status}`;
    console.error("[stripeGetJson] stripe_error", {
      path,
      status: res.status,
      message: msg,
      error: data?.error || null,
    });
    throw new Error(msg);
  }

  return data as T;
}

function extractSubscriptionItemUnix(
  subscription: StripeSubscriptionLike,
  key: "current_period_start" | "current_period_end",
): number | null {
  const firstItem = subscription.items?.data?.[0];
  if (!firstItem) return null;

  const raw = (firstItem as Record<string, unknown>)[key];
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;

  return null;
}

function extractCurrentPeriodStartUnix(subscription: StripeSubscriptionLike): number | null {
  if (typeof subscription.current_period_start === "number" && Number.isFinite(subscription.current_period_start)) {
    return subscription.current_period_start;
  }

  return extractSubscriptionItemUnix(subscription, "current_period_start");
}

function extractCurrentPeriodEndUnix(subscription: StripeSubscriptionLike): number | null {
  if (typeof subscription.current_period_end === "number" && Number.isFinite(subscription.current_period_end)) {
    return subscription.current_period_end;
  }

  return extractSubscriptionItemUnix(subscription, "current_period_end");
}

async function stripeGetSubscriptionById(
  env: Env,
  subscriptionId: string,
  options?: { apiVersion?: string },
): Promise<StripeSubscriptionLike | null> {
  try {
    return await stripeGetJson<StripeSubscriptionLike>(
      env,
      `/v1/subscriptions/${encodeURIComponent(subscriptionId)}?expand[]=items.data.price`,
      options,
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


function hasStripeSubscriptionCancelAt(subscription: Pick<StripeSubscriptionLike, "cancel_at">): boolean {
  return typeof subscription.cancel_at === "number" && Number.isFinite(subscription.cancel_at);
}

export function makeStripeAutoRenewUpdateForm(
  subscription: StripeSubscriptionLike,
  enabled: boolean,
): URLSearchParams | null {
  const form = new URLSearchParams();

  if (enabled) {
    form.set("cancel_at", "");
    return form;
  }

  const currentPeriodEnd = extractCurrentPeriodEndUnix(subscription);
  if (!currentPeriodEnd) {
    return null;
  }

  form.set("cancel_at", String(currentPeriodEnd));
  return form;
}

function subscriptionRank(sub: StripeSubscriptionLike): number {
  const status = String(sub.status || "").trim().toLowerCase();
  const hasCancelAt = hasStripeSubscriptionCancelAt(sub);
  const periodEnd = Number(extractCurrentPeriodEndUnix(sub) || 0);

  if ((status === "trialing" || status === "active" || status === "past_due" || status === "unpaid") && !hasCancelAt) {
    return 4000000000 + periodEnd;
  }

  if ((status === "trialing" || status === "active" || status === "past_due" || status === "unpaid") && hasCancelAt) {
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

  const subscription = await stripeGetSubscriptionById(env, subscriptionId);
  if (!subscription) return null;

  const recoveredCustomerId = String(subscription.customer || "").trim();
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
  const successUrl = `${siteUrl}/billing/success?session_id={CHECKOUT_SESSION_ID}&mode=${interval}`;
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
    `/v1/subscriptions?customer=${encodeURIComponent(customerId)}&status=all&limit=10&expand[]=data.items.data.price`,
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

function extractScheduleId(subscription: StripeSubscriptionLike): string {
  if (typeof subscription.schedule === "string") return subscription.schedule.trim();
  if (subscription.schedule && typeof subscription.schedule === "object") {
    return String(subscription.schedule.id || "").trim();
  }
  return "";
}

async function stripeGetSubscriptionScheduleById(
  env: Env,
  scheduleId: string,
): Promise<StripeSubscriptionScheduleLike | null> {
  try {
    return await stripeGetJson<StripeSubscriptionScheduleLike>(
      env,
      `/v1/subscription_schedules/${encodeURIComponent(scheduleId)}`,
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "";
    if (message.includes("No such subscription schedule") || message.includes("resource_missing")) {
      return null;
    }
    throw err;
  }
}

async function createStripeSubscriptionScheduleFromSubscription(
  env: Env,
  subscriptionId: string,
): Promise<StripeSubscriptionScheduleLike> {
  const form = new URLSearchParams();
  form.set("from_subscription", subscriptionId);

  return await stripePostForm<StripeSubscriptionScheduleLike>(
    env,
    "/v1/subscription_schedules",
    form,
  );
}

export function makeStripeSubscriptionScheduleUpdateForm(
  currentPhase: { startDate: number; endDate: number; currentPriceId: string; quantity: number },
  nextPriceId: string,
): URLSearchParams {
  const form = new URLSearchParams();
  form.set("end_behavior", "release");
  form.set("proration_behavior", "none");
  form.set("phases[0][start_date]", String(currentPhase.startDate));
  form.set("phases[0][end_date]", String(currentPhase.endDate));
  form.set("phases[0][items][0][price]", currentPhase.currentPriceId);
  form.set("phases[0][items][0][quantity]", String(currentPhase.quantity));
  form.set("phases[0][proration_behavior]", "none");
  form.set("phases[1][start_date]", String(currentPhase.endDate));
  form.set("phases[1][items][0][price]", nextPriceId);
  form.set("phases[1][items][0][quantity]", String(currentPhase.quantity));
  form.set("phases[1][proration_behavior]", "none");
  form.set("phases[1][billing_cycle_anchor]", "phase_start");
  return form;
}

export async function scheduleStripeSubscriptionIntervalChange(
  env: Env,
  userId: string,
  lic: LicenseRow | null,
  nextInterval: "month" | "year",
): Promise<{ ok: true } | { ok: false; reason: string }> {
  let subscriptionId = String(lic?.stripe_subscription_id || "").trim();
  const customerId = String(lic?.stripe_customer_id || "").trim();

  console.log("[schedule-plan-change] start", {
    userId,
    license: lic,
    nextInterval,
  });

  if (!subscriptionId && customerId) {
    subscriptionId = (await findLatestSubscriptionIdForCustomer(env, customerId)) || "";
  }

  if (!subscriptionId) {
    console.error("[schedule-plan-change] no subscription id", { userId, customerId, nextInterval });
    return { ok: false, reason: "no_stripe_subscription" };
  }

  let subscription = await stripeGetSubscriptionById(env, subscriptionId);
  if (!subscription) {
    console.error("[schedule-plan-change] subscription not found", { userId, subscriptionId, nextInterval });
    return { ok: false, reason: "no_stripe_subscription" };
  }

  const currentPriceId = String(subscription.items?.data?.[0]?.price?.id || "").trim();
  const currentQuantity = Number(subscription.items?.data?.[0]?.quantity || 1) || 1;
  const currentInterval = String(subscription.items?.data?.[0]?.price?.recurring?.interval || "").trim().toLowerCase();
  const currentPeriodStart = extractCurrentPeriodStartUnix(subscription);
  const currentPeriodEnd = extractCurrentPeriodEndUnix(subscription);
  const nextPriceId = getPriceIdForInterval(env, nextInterval);

  if (!currentPriceId) return { ok: false, reason: "subscription_item_missing" };
  if (!nextPriceId) return { ok: false, reason: nextInterval === "year" ? "missing_yearly_price_id" : "missing_monthly_price_id" };
  if (!currentPeriodStart || !currentPeriodEnd) return { ok: false, reason: "missing_current_period_bounds" };

  if (hasStripeSubscriptionCancelAt(subscription)) {
    const resumeForm = new URLSearchParams();
    resumeForm.set("cancel_at", "");
    subscription = await stripePostForm<StripeSubscriptionLike>(
      env,
      `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
      resumeForm,
    );

    const upsertResumed = await upsertLicenseFromStripeSubscription(env, subscription);
    if (!upsertResumed.ok) return { ok: false, reason: upsertResumed.reason };
  }

  const existingScheduleId = extractScheduleId(subscription);
  let schedule = existingScheduleId
    ? await stripeGetSubscriptionScheduleById(env, existingScheduleId)
    : await createStripeSubscriptionScheduleFromSubscription(env, subscriptionId);

  if (!schedule?.id && existingScheduleId) {
    schedule = await createStripeSubscriptionScheduleFromSubscription(env, subscriptionId);
  }

  if (!schedule?.id) {
    return { ok: false, reason: "subscription_schedule_missing" };
  }

  schedule = await stripePostForm<StripeSubscriptionScheduleLike>(
    env,
    `/v1/subscription_schedules/${encodeURIComponent(schedule.id)}`,
    makeStripeSubscriptionScheduleUpdateForm(
      {
        startDate: currentPeriodStart,
        endDate: currentPeriodEnd,
        currentPriceId,
        quantity: currentQuantity,
      },
      nextPriceId,
    ),
  );

  await env.creatorrr_db
    .prepare(`
      UPDATE licenses
      SET scheduled_billing_interval=?2,
          scheduled_change_at=?3,
          cancel_at=NULL,
          updated_at=?4
      WHERE user_id=?1
    `)
    .bind(userId, nextInterval === currentInterval ? null : nextInterval, unixToIso(currentPeriodEnd), nowIso())
    .run();

  return { ok: true };
}

async function releaseStripeSubscriptionSchedule(
  env: Env,
  scheduleId: string,
): Promise<void> {
  await stripePostForm<Record<string, unknown>>(
    env,
    `/v1/subscription_schedules/${encodeURIComponent(scheduleId)}/release`,
    new URLSearchParams(),
  );
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

  let currentSubscription = await stripeGetSubscriptionById(env, subscriptionId);
  if (!currentSubscription) return { ok: false, reason: "no_stripe_subscription" };

  const scheduleId = extractScheduleId(currentSubscription);

  if (!enabled) {
    if (scheduleId) {
      await releaseStripeSubscriptionSchedule(env, scheduleId);

      currentSubscription = await stripeGetSubscriptionById(env, subscriptionId);
      if (!currentSubscription) return { ok: false, reason: "no_stripe_subscription" };
    }

    const disableForm = makeStripeAutoRenewUpdateForm(currentSubscription, false);
    if (!disableForm) return { ok: false, reason: "missing_current_period_end" };

    const updatedSubscription = await stripePostForm<StripeSubscriptionLike>(
      env,
      `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
      disableForm,
    );

    const upsertResult = await upsertLicenseFromStripeSubscription(env, updatedSubscription);
    if (!upsertResult.ok) return { ok: false, reason: upsertResult.reason };

    await env.creatorrr_db
      .prepare(`
        UPDATE licenses
        SET stripe_subscription_id=?2,
            scheduled_billing_interval=NULL,
            scheduled_change_at=NULL,
            updated_at=?3
        WHERE user_id=?1
      `)
      .bind(userId, subscriptionId, nowIso())
      .run();

    return { ok: true };
  }

  if (hasStripeSubscriptionCancelAt(currentSubscription)) {
    const enableForm = makeStripeAutoRenewUpdateForm(currentSubscription, true);
    if (!enableForm) return { ok: false, reason: "missing_current_period_end" };

    const updatedSubscription = await stripePostForm<StripeSubscriptionLike>(
      env,
      `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
      enableForm,
    );

    const upsertResult = await upsertLicenseFromStripeSubscription(env, updatedSubscription);
    if (!upsertResult.ok) return { ok: false, reason: upsertResult.reason };

    await env.creatorrr_db
      .prepare(`
        UPDATE licenses
        SET stripe_subscription_id=?2, updated_at=?3
        WHERE user_id=?1
      `)
      .bind(userId, subscriptionId, nowIso())
      .run();
  }

  return { ok: true };
}

function mapStripeStatus(subscription: StripeSubscriptionLike): string {
  const raw = String(subscription.status || "").trim().toLowerCase();
  const cancelsAt = hasStripeSubscriptionCancelAt(subscription);

  if (isLiveStripeStatus(raw) && cancelsAt) {
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

  const existing = await env.creatorrr_db
    .prepare(`
      SELECT
        stripe_price_id,
        billing_interval,
        current_period_start,
        current_period_end,
        scheduled_billing_interval,
        scheduled_change_at
      FROM licenses
      WHERE user_id=?1
    `)
    .bind(userId)
    .first<
      Pick<
        LicenseRow,
        | "stripe_price_id"
        | "billing_interval"
        | "current_period_start"
        | "current_period_end"
        | "scheduled_billing_interval"
        | "scheduled_change_at"
      >
    >();

  const stripeCustomerId = subscription.customer ? String(subscription.customer) : null;
  const stripeSubscriptionId = subscription.id ? String(subscription.id) : null;
  const stripePriceId = extractPriceId(subscription);
  const billingInterval = extractRecurringInterval(subscription);
  const status = mapStripeStatus(subscription);
  const currentPeriodStart = unixToIso(extractCurrentPeriodStartUnix(subscription));
  const currentPeriodEnd = unixToIso(extractCurrentPeriodEndUnix(subscription));
  const trialStartAt = unixToIso(subscription.trial_start);
  const trialEndAt = unixToIso(subscription.trial_end);
  const canceledAt = unixToIso(subscription.canceled_at);
  const endedAt = unixToIso(subscription.ended_at);
  const cancelAt = unixToIso(subscription.cancel_at);
  const now = nowIso();

  const sameCurrentPeriod =
    Boolean(existing?.current_period_start) &&
    Boolean(existing?.current_period_end) &&
    existing?.current_period_start === currentPeriodStart &&
    existing?.current_period_end === currentPeriodEnd;

  const preserveDisplayedCurrentInterval =
    Boolean(existing?.scheduled_billing_interval) &&
    sameCurrentPeriod &&
    Boolean(existing?.billing_interval) &&
    Boolean(billingInterval) &&
    existing?.billing_interval !== billingInterval;

  const persistedStripePriceId = preserveDisplayedCurrentInterval
    ? existing?.stripe_price_id || stripePriceId
    : stripePriceId;

  const persistedBillingInterval = preserveDisplayedCurrentInterval
    ? existing?.billing_interval || billingInterval
    : billingInterval;

  let scheduledBillingInterval = existing?.scheduled_billing_interval || null;
  let scheduledChangeAt = existing?.scheduled_change_at || null;

  // Important:
  // Do NOT clear scheduled renewal just because cancel_at is set.
  // We want auto-renew OFF to keep the user's chosen future renewal plan in app state.
  // Only clear it once the scheduled plan has actually become the active plan.
  if (
    !preserveDisplayedCurrentInterval &&
    scheduledBillingInterval &&
    scheduledBillingInterval === billingInterval
  ) {
    scheduledBillingInterval = null;
    scheduledChangeAt = null;
  }

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
        scheduled_billing_interval,
        scheduled_change_at,
        cancel_at,
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
        ?14,
        ?15,
        ?16
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
        scheduled_billing_interval=excluded.scheduled_billing_interval,
        scheduled_change_at=excluded.scheduled_change_at,
        cancel_at=excluded.cancel_at,
        canceled_at=excluded.canceled_at,
        ended_at=excluded.ended_at
    `)
    .bind(
      userId,
      status,
      now,
      stripeCustomerId,
      stripeSubscriptionId,
      persistedStripePriceId,
      persistedBillingInterval,
      currentPeriodStart,
      currentPeriodEnd,
      trialStartAt,
      trialEndAt,
      scheduledBillingInterval,
      scheduledChangeAt,
      cancelAt,
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

  const subscription = await stripeGetSubscriptionById(env, subscriptionId);
  if (!subscription) return;

  await upsertLicenseFromStripeSubscription(env, subscription);
}
