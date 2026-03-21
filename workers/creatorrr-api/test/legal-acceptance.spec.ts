import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { jwtSign, makeSalt, pbkdf2 } from "../src/lib/crypto";

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;
const TEST_JWT_SECRET = "test-jwt-secret";

async function ensureTestSchema() {
  await env.creatorrr_db.batch([
    env.creatorrr_db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        pass_salt TEXT NOT NULL,
        pass_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        email_verified_at TEXT,
        password_reset_token_hash TEXT,
        password_reset_expires_at TEXT,
        email_verify_token_hash TEXT,
        email_verify_expires_at TEXT,
        updated_at TEXT
      )
    `),
    env.creatorrr_db.prepare(`
      CREATE TABLE IF NOT EXISTS user_devices (
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        token_version INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (user_id, device_id)
      )
    `),
    env.creatorrr_db.prepare(`
      CREATE TABLE IF NOT EXISTS licenses (
        user_id TEXT PRIMARY KEY,
        plan TEXT NOT NULL,
        status TEXT NOT NULL,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        stripe_price_id TEXT,
        billing_interval TEXT,
        current_period_start TEXT,
        current_period_end TEXT,
        trial_start_at TEXT,
        trial_end_at TEXT,
        cancel_at TEXT,
        canceled_at TEXT,
        ended_at TEXT,
        scheduled_billing_interval TEXT,
        scheduled_change_at TEXT
      )
    `),
    env.creatorrr_db.prepare(`
      CREATE TABLE IF NOT EXISTS legal_acceptances (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        terms_version TEXT NOT NULL,
        privacy_version TEXT NOT NULL,
        refund_version TEXT NOT NULL,
        accepted_at TEXT NOT NULL,
        acceptance_context TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL
      )
    `),
  ]);
}

async function createVerifiedSession(userId: string) {
  await ensureTestSchema();

  const email = `${userId}@example.com`;
  const deviceId = `${userId}-device`;
  const now = new Date().toISOString();
  const salt = makeSalt();
  const hash = await pbkdf2("password-123", salt);

  await env.creatorrr_db
    .prepare(`
      INSERT INTO users (
        id,
        email,
        pass_salt,
        pass_hash,
        created_at,
        email_verified_at,
        updated_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    `)
    .bind(userId, email, salt, hash, now, now, now)
    .run();

  await env.creatorrr_db
    .prepare(`
      INSERT INTO user_devices (
        user_id,
        device_id,
        token_version,
        created_at,
        last_seen_at
      ) VALUES (?1, ?2, 0, ?3, ?3)
    `)
    .bind(userId, deviceId, now)
    .run();

  const token = await jwtSign(TEST_JWT_SECRET, {
    sub: userId,
    did: deviceId,
    tv: 0,
    exp: Math.floor(Date.now() / 1000) + 3600,
  });

  return { email, deviceId, token };
}

function makeStripeEnabledEnv() {
  return {
    ...env,
    JWT_SECRET: TEST_JWT_SECRET,
    STRIPE_SECRET_KEY: "sk_test_123",
    STRIPE_PRICE_ID_MONTHLY: "price_monthly",
    STRIPE_PRICE_ID_YEARLY: "price_yearly",
  };
}

function makeAuthedEnv() {
  return {
    ...env,
    JWT_SECRET: TEST_JWT_SECRET,
  };
}

describe("legal acceptance enforcement", () => {
  it("requires trial starters to accept the current legal versions and persists proof server-side", async () => {
    const userId = `trial_user_${crypto.randomUUID()}`;
    const { token } = await createVerifiedSession(userId);

    const missingAcceptanceRes = await worker.fetch(
      new IncomingRequest("https://example.com/license/trial/start", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
          "CF-Connecting-IP": "203.0.113.10",
          "user-agent": "Vitest Trial Agent/1.0",
        },
        body: JSON.stringify({}),
      }),
      makeAuthedEnv(),
      createExecutionContext(),
    );

    expect(missingAcceptanceRes.status).toBe(400);
    await expect(missingAcceptanceRes.json()).resolves.toMatchObject({
      ok: false,
      error: "legal_acceptance_required",
      current_terms_version: "2026-03-21",
      current_privacy_version: "2026-03-21",
      current_refund_version: "2026-03-21",
    });

    const acceptedRes = await worker.fetch(
      new IncomingRequest("https://example.com/license/trial/start", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
          "CF-Connecting-IP": "203.0.113.10",
          "user-agent": "Vitest Trial Agent/1.0",
        },
        body: JSON.stringify({
          legal_acceptance: {
            accepted: true,
            terms_version: "2026-03-21",
            privacy_version: "2026-03-21",
            refund_version: "2026-03-21",
          },
        }),
      }),
      makeAuthedEnv(),
      createExecutionContext(),
    );

    expect(acceptedRes.status).toBe(200);
    await expect(acceptedRes.json()).resolves.toMatchObject({
      ok: true,
      legal: {
        has_accepted_current_versions: true,
      },
      license: {
        in_trial: true,
      },
    });

    const acceptanceRow = await env.creatorrr_db
      .prepare(`
        SELECT
          user_id,
          terms_version,
          privacy_version,
          refund_version,
          acceptance_context,
          ip_address,
          user_agent
        FROM legal_acceptances
        WHERE user_id=?1
        ORDER BY created_at DESC
        LIMIT 1
      `)
      .bind(userId)
      .first<Record<string, string>>();

    expect(acceptanceRow).toMatchObject({
      user_id: userId,
      terms_version: "2026-03-21",
      privacy_version: "2026-03-21",
      refund_version: "2026-03-21",
      acceptance_context: "license_trial_start",
      ip_address: "203.0.113.10",
      user_agent: "Vitest Trial Agent/1.0",
    });
  });

  it("requires Stripe checkout starters to accept the current legal versions", async () => {
    const userId = `checkout_user_${crypto.randomUUID()}`;
    const { token } = await createVerifiedSession(userId);
    const ctx = createExecutionContext();

    const response = await worker.fetch(
      new IncomingRequest("https://example.com/stripe/checkout", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ interval: "month" }),
      }),
      makeStripeEnabledEnv(),
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      ok: false,
      error: "legal_acceptance_required",
    });
  });

  it("exposes the server-side legal acceptance state in account/me", async () => {
    const userId = `account_user_${crypto.randomUUID()}`;
    const { token } = await createVerifiedSession(userId);

    await env.creatorrr_db
      .prepare(`
        INSERT INTO legal_acceptances (
          id,
          user_id,
          terms_version,
          privacy_version,
          refund_version,
          accepted_at,
          acceptance_context,
          ip_address,
          user_agent,
          created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
      `)
      .bind(
        crypto.randomUUID(),
        userId,
        "2026-03-21",
        "2026-03-21",
        "2026-03-21",
        new Date().toISOString(),
        "seeded_test",
        "198.51.100.7",
        "Vitest Account Agent/1.0",
        new Date().toISOString(),
      )
      .run();

    const ctx = createExecutionContext();
    const response = await worker.fetch(
      new IncomingRequest("https://example.com/account/me", {
        method: "GET",
        headers: {
          authorization: `Bearer ${token}`,
        },
      }),
      makeAuthedEnv(),
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      ok: true,
      legal: {
        has_accepted_current_versions: true,
        current_terms_version: "2026-03-21",
        current_privacy_version: "2026-03-21",
        current_refund_version: "2026-03-21",
      },
    });
  });
});
