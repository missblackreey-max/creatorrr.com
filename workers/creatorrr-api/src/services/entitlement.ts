import type { EntitlementView, LicenseRow } from "../types";
import { parseIsoMs } from "../lib/utils";

type CanonicalPlan = "free" | "free_pass" | "pro";
type BillingInterval = "month" | "year" | null;
type ProBillingInterval = "month" | "year";

const ACTIVE_FREE_PASS_STATUS = "active";

const ACTIVE_PRO_STATUSES = new Set([
  "active",
  "past_due",
  "canceling",
]);

function normalizePlan(value: unknown): CanonicalPlan {
  const plan = String(value || "").toLowerCase().trim();

  if (plan === "free") return "free";
  if (plan === "free_pass") return "free_pass";
  if (plan === "pro") return "pro";

  // Legacy values must never leak to API output.
  if (plan === "trial") return "free";
  if (plan === "beta") return "free";

  return "free";
}

function normalizeBillingInterval(
  plan: CanonicalPlan,
  value: unknown
): BillingInterval {
  if (plan !== "pro") return null;

  const billingInterval = String(value || "").toLowerCase().trim();

  if (billingInterval === "month") return "month";
  if (billingInterval === "year") return "year";

  return null;
}

function normalizeStatus(value: unknown): string {
  return String(value || "").toLowerCase().trim();
}

function isActiveFreePassLicense(lic: LicenseRow): boolean {
  const plan = normalizePlan(lic.plan);
  const status = normalizeStatus(lic.status);

  return plan === "free_pass" && status === ACTIVE_FREE_PASS_STATUS;
}

function isActiveProLicense(
  lic: LicenseRow,
  billingInterval: ProBillingInterval
): boolean {
  const plan = normalizePlan(lic.plan);
  const status = normalizeStatus(lic.status);

  if (plan !== "pro") return false;
  if (!ACTIVE_PRO_STATUSES.has(status)) return false;

  const periodEndMs = parseIsoMs(lic.current_period_end);

  if (periodEndMs === null) return false;

  return periodEndMs > Date.now();
}

function freeEntitlement(): EntitlementView {
  return {
    plan: "free",
    billing_interval: null,
    entitled: false,
    entitled_until: null,
    subscription_ends_at: null,
  };
}

function freePassEntitlement(): EntitlementView {
  return {
    plan: "free_pass",
    billing_interval: null,
    entitled: true,
    entitled_until: null,
    subscription_ends_at: null,
  };
}

function proEntitlement(
  billingInterval: ProBillingInterval,
  currentPeriodEnd: string | null | undefined
): EntitlementView {
  return {
    plan: "pro",
    billing_interval: billingInterval,
    entitled: true,
    entitled_until: currentPeriodEnd || null,
    subscription_ends_at: currentPeriodEnd || null,
  };
}

export function isActiveFreeLicense(
  lic: Pick<LicenseRow, "plan" | "status"> | null | undefined
): boolean {
  if (!lic) return false;

  const plan = normalizePlan(lic.plan);
  const status = normalizeStatus(lic.status);

  return plan === "free_pass" && status === ACTIVE_FREE_PASS_STATUS;
}

export function computeEntitlement(lic: LicenseRow | null): EntitlementView {
  if (!lic) return freeEntitlement();

  const plan = normalizePlan(lic.plan);
  const billingInterval = normalizeBillingInterval(plan, lic.billing_interval);

  if (isActiveFreePassLicense(lic)) {
    return freePassEntitlement();
  }

  if (
    billingInterval !== null &&
    isActiveProLicense(lic, billingInterval)
  ) {
    return proEntitlement(
      billingInterval,
      lic.current_period_end
    );
  }

  return freeEntitlement();
}