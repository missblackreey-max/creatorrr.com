import { env, createExecutionContext, waitOnExecutionContext, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src/index";
import { makeSalt, pbkdf2 } from "../src/lib/crypto";

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

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
	]);
}

async function seedVerifiedUserWithDevices(deviceIds: string[]) {
	await ensureTestSchema();

	const userId = `user_${crypto.randomUUID()}`;
	const email = `${userId}@example.com`;
	const password = "password-123";
	const now = new Date().toISOString();
	const salt = makeSalt();
	const hash = await pbkdf2(password, salt);

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

	for (const deviceId of deviceIds) {
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
	}

	return { userId, email, password };
}

describe("creatorrr-api worker", () => {
	it("returns not_found for unknown paths (unit style)", async () => {
		const request = new IncomingRequest("https://example.com/");
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(404);
		expect(await response.json()).toEqual({ ok: false, error: "not_found" });
	});

	it("handles CORS preflight (integration style)", async () => {
		const response = await SELF.fetch("https://example.com/auth/login", {
			method: "OPTIONS",
			headers: {
				origin: "https://creatorrr.com",
				"access-control-request-method": "POST",
			},
		});

		expect(response.status).toBe(204);
		expect(response.headers.get("access-control-allow-origin")).toBe("https://creatorrr.com");
		expect(response.headers.get("access-control-allow-methods")).toContain("POST");
	});

	it("rejects verify-email requests without a token", async () => {
		const response = await SELF.fetch("https://example.com/auth/verify-email", {
			method: "POST",
			headers: {
				"content-type": "application/json",
			},
			body: JSON.stringify({ token: "" }),
		});

		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ ok: false, error: "invalid_input" });
	});

	it("rejects resend-verification requests without an email", async () => {
		const response = await SELF.fetch("https://example.com/auth/resend-verification", {
			method: "POST",
			headers: {
				"content-type": "application/json",
			},
			body: JSON.stringify({ email: "" }),
		});

		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ ok: false, error: "invalid_input" });
	});

	it("logs out other devices and preserves the requesting device slot", async () => {
		const { userId, email, password } = await seedVerifiedUserWithDevices(["device-a", "device-b", "device-c"]);

		const response = await SELF.fetch("https://example.com/auth/logout-other-devices", {
			method: "POST",
			headers: {
				"content-type": "application/json",
			},
			body: JSON.stringify({
				email,
				password,
				deviceId: "device-new",
			}),
		});

		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toMatchObject({
			ok: true,
			device_id: "device-new",
		});

		const devices = await env.creatorrr_db
			.prepare("SELECT device_id FROM user_devices WHERE user_id=?1 ORDER BY device_id")
			.bind(userId)
			.all<{ device_id: string }>();

		expect(devices.results).toEqual([{ device_id: "device-new" }]);
	});
});
