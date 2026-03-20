import { describe, expect, it } from "vitest";
import { makeAccountView } from "../src/worker";

describe("makeAccountView", () => {
  it("does not expose future period-end access fields for canceled subscriptions that are no longer entitled", () => {
    const result = makeAccountView(
      {
        id: "user_123",
        email: "user@example.com",
        pass_salt: "salt",
        pass_hash: "hash",
        created_at: "2026-03-19T12:49:18.879Z",
        updated_at: "2026-03-19T12:49:34.770Z",
        email_verified_at: "2026-03-19T12:49:34.770Z",
      },
      {
        user_id: "user_123",
        plan: "pro",
        status: "canceled",
        created_at: "2026-03-19T12:49:18.879Z",
        updated_at: "2026-03-19T12:49:34.770Z",
        billing_interval: "year",
        current_period_end: "2027-03-19T12:53:08.000Z",
        cancel_at: "2027-03-19T12:53:08.000Z",
        canceled_at: "2026-03-19T16:46:10.000Z",
        ended_at: "2027-03-19T12:53:08.000Z",
      },
    );

    expect(result.license.entitled).toBe(false);
    expect(result.license.status).toBe("canceled");
    expect(result.license.auto_renew_enabled).toBe(false);
    expect(result.license.current_period_end).toBeNull();
    expect(result.license.cancel_at).toBeNull();
    expect(result.license.subscription_ends_at).toBeNull();
    expect(result.license.ended_at).toBe("2027-03-19T12:53:08.000Z");
  });
  it("shows free access as an entitled non-renewing plan", () => {
    const result = makeAccountView(
      {
        id: "user_free",
        email: "ben@creatorrr.com",
        pass_salt: "salt",
        pass_hash: "hash",
        created_at: "2026-03-20T00:00:00.000Z",
        updated_at: "2026-03-20T00:00:00.000Z",
        email_verified_at: "2026-03-20T00:00:00.000Z",
      },
      {
        user_id: "user_free",
        plan: "free",
        status: "active",
        created_at: "2026-03-20T00:00:00.000Z",
        updated_at: "2026-03-20T00:00:00.000Z",
        billing_interval: null,
        current_period_end: null,
        cancel_at: null,
        canceled_at: null,
        ended_at: null,
      },
    );

    expect(result.license.plan).toBe("free");
    expect(result.license.entitled).toBe(true);
    expect(result.license.auto_renew_enabled).toBe(false);
    expect(result.license.current_period_end).toBeNull();
    expect(result.license.subscription_ends_at).toBeNull();
  });

});
