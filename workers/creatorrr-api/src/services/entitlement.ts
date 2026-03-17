import type { EntitlementView, LicenseRow } from "../types";
import { parseIsoMs } from "../lib/utils";

export function computeEntitlement(lic: LicenseRow | null): EntitlementView {
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
