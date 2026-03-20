import type { EntitlementView, LicenseRow } from "../types";
import { parseIsoMs } from "../lib/utils";

export function isActiveFreeLicense(lic: Pick<LicenseRow, "plan" | "status"> | null | undefined): boolean {
  if (!lic) return false;

  const status = String(lic.status || "").toLowerCase().trim();
  const plan = String(lic.plan || "").toLowerCase().trim();

  return plan === "free" && status === "active";
}

export function computeEntitlement(lic: LicenseRow | null): EntitlementView {
  if (!lic) {
    return {
      plan: "none",
      status: "none",
      entitled: false,
      entitled_until: null,
      in_trial: false,
      cancel_at: null,
    };
  }

  const nowMs = Date.now();
  const status = String(lic.status || "").toLowerCase().trim();
  const plan = String(lic.plan || "").toLowerCase().trim();
  const billingInterval = String(lic.billing_interval || "").toLowerCase().trim();

  const trialEndMs = parseIsoMs(lic.trial_end_at);
  const periodEndMs = parseIsoMs(lic.current_period_end);

  const hasLiveTrialWindow = trialEndMs !== null && trialEndMs > nowMs;
  const hasLiveSubscriptionWindow = periodEndMs !== null && periodEndMs > nowMs;
  const isRecurring = billingInterval === "month" || billingInterval === "year";

  const freeAccessActive = isActiveFreeLicense(lic);

  const inTrial =
    hasLiveTrialWindow &&
    (
      status === "trialing" ||
      status === "canceling" ||
      plan === "trial" ||
      plan === "free"
    );

  const subscriptionActive =
    hasLiveSubscriptionWindow &&
    (
      status === "active" ||
      status === "past_due" ||
      status === "canceling" ||
      status === "trialing"
    ) &&
    isRecurring;

  const entitled = freeAccessActive || inTrial || subscriptionActive;

  let entitledUntil: string | null = null;
  if (inTrial && lic.trial_end_at) entitledUntil = lic.trial_end_at;
  if (!inTrial && subscriptionActive && lic.current_period_end) entitledUntil = lic.current_period_end;

  return {
    plan,
    status,
    entitled,
    entitled_until: entitledUntil,
    in_trial: inTrial,
    cancel_at: lic.cancel_at || null,
  };
}