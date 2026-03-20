import { describe, expect, it } from "vitest";
import { computeEntitlement, isActiveFreeLicense } from "../src/services/entitlement";

describe("free access entitlement", () => {
  it("treats active free licenses as entitled without an expiry", () => {
    const result = computeEntitlement({
      user_id: "user_free",
      plan: "free",
      status: "active",
      created_at: "2026-03-20T00:00:00.000Z",
      updated_at: "2026-03-20T00:00:00.000Z",
      billing_interval: null,
      current_period_start: null,
      current_period_end: null,
      trial_start_at: null,
      trial_end_at: null,
      cancel_at: null,
      canceled_at: null,
      ended_at: null,
    });

    expect(result.entitled).toBe(true);
    expect(result.entitled_until).toBeNull();
    expect(result.in_trial).toBe(false);
  });

  it("does not treat inactive free licenses as entitled", () => {
    expect(isActiveFreeLicense({ plan: "free", status: "none" } as any)).toBe(false);
  });
});
