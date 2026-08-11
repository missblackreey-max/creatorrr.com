import { env, createExecutionContext, waitOnExecutionContext, SELF } from "cloudflare:test";
import { afterEach, describe, it, expect, vi } from "vitest";
import worker from "../src/index";
import { jwtSign, makeSalt, pbkdf2 } from "../src/lib/crypto";

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
		env.creatorrr_db.prepare(`
      CREATE TABLE IF NOT EXISTS analytics_pageviews (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        path TEXT NOT NULL,
        query TEXT,
        referrer TEXT,
        title TEXT,
        country TEXT,
        user_agent TEXT,
        ip_hash TEXT,
        is_bot INTEGER NOT NULL DEFAULT 0,
        bot_score INTEGER,
        timezone TEXT,
        screen TEXT,
        language TEXT
      )
    `),
		env.creatorrr_db.prepare(`
      CREATE TABLE IF NOT EXISTS analytics_events (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        event_name TEXT NOT NULL,
        item_id TEXT,
        item_version TEXT,
        item_variant TEXT,
        path TEXT,
        country TEXT,
        user_agent TEXT,
        ip_hash TEXT,
        is_bot INTEGER NOT NULL DEFAULT 0,
        bot_score INTEGER
      )
		`),
		env.creatorrr_db.prepare(`
      CREATE TABLE IF NOT EXISTS boost_fit_requests (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        telegram TEXT,
        links TEXT NOT NULL,
        stage TEXT NOT NULL,
        revenue_have TEXT NOT NULL,
        revenue_want TEXT NOT NULL,
        help TEXT NOT NULL,
        time_per_day TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'received',
        ip_hash TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `),
		env.creatorrr_db.prepare(`
      CREATE TABLE IF NOT EXISTS boost_fit_rate_limits (
        ip_hash TEXT NOT NULL,
        window_start TEXT NOT NULL,
        submission_count INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (ip_hash, window_start)
      )
    `),
	]);
}

afterEach(() => {
	vi.restoreAllMocks();
});

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

	it("rejects invalid analytics event payloads", async () => {
		await ensureTestSchema();
		const response = await SELF.fetch("https://example.com/analytics/event", {
			method: "POST",
			headers: {
				"content-type": "application/json",
			},
			body: JSON.stringify({
				event: "download_click",
				item_id: "",
				item_version: "1.1.0",
				item_variant: "exe",
				path: "/account",
			}),
		});

		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ ok: false, error: "invalid_event_payload" });
	});

	it("stores valid download analytics events", async () => {
		await ensureTestSchema();
		const response = await SELF.fetch("https://example.com/analytics/event", {
			method: "POST",
			headers: {
				"content-type": "application/json",
			},
			body: JSON.stringify({
				event: "download_click",
				item_id: "contentorrr_windows",
				item_version: "1.1.0",
				item_variant: "exe",
				path: "/account",
			}),
		});

		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toMatchObject({ ok: true });

		const inserted = await env.creatorrr_db
			.prepare("SELECT event_name, item_id, item_version, item_variant FROM analytics_events ORDER BY created_at DESC LIMIT 1")
			.first<{ event_name: string; item_id: string; item_version: string; item_variant: string }>();

		expect(inserted).toMatchObject({
			event_name: "download_click",
			item_id: "contentorrr_windows",
			item_version: "1.1.0",
			item_variant: "exe",
		});
	});

	it("rejects invalid Creatorrr Boost fit requests", async () => {
		await ensureTestSchema();
		const response = await SELF.fetch("https://example.com/api/boost-fit", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ email: "not-an-email" }),
		});

		expect(response.status).toBe(400);
		await expect(response.json()).resolves.toMatchObject({ ok: false, error: "invalid_input" });
	});

	it("rejects oversized Boost requests based on bytes read without Content-Length", async () => {
		await ensureTestSchema();
		const request = new IncomingRequest("https://example.com/api/boost-fit", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ help: "x".repeat(20_001) }),
		});
		expect(request.headers.get("content-length")).toBeNull();
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(413);
		await expect(response.json()).resolves.toMatchObject({ ok: false, error: "request_too_large" });
	});

	it("stores a valid Boost request and sends both emails", async () => {
		await ensureTestSchema();
		await env.creatorrr_db.prepare("DELETE FROM boost_fit_requests").run();
		await env.creatorrr_db.prepare("DELETE FROM boost_fit_rate_limits").run();
		const resend = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
		const testEnv = { ...env, RESEND_API_KEY: "test-key", RESEND_FROM_EMAIL: "noreply@mail.creatorrr.com" };
		const request = new IncomingRequest("https://api.creatorrr.com/api/boost-fit", {
			method: "POST",
			headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.10" },
			body: JSON.stringify({
				email: "creator@example.com",
				telegram: "@creator",
				links: "https://example.com/profile",
				stage: "1–6 months",
				revenueHave: "$0–$500",
				revenueWant: "$2,000–$5,000",
				help: "I post three times per week.",
				timePerDay: "1–2 hours",
			}),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toEqual({ ok: true });
		expect(resend).toHaveBeenCalledOnce();
		const [, init] = resend.mock.calls[0];
		const messages = JSON.parse(String(init?.body));
		expect(messages).toHaveLength(2);
		expect(messages[0]).toMatchObject({ to: ["ben@creatorrr.com"], reply_to: "creator@example.com" });
		expect(messages[1]).toMatchObject({ to: ["creator@example.com"] });

		const stored = await env.creatorrr_db.prepare("SELECT email, status FROM boost_fit_requests LIMIT 1")
			.first<{ email: string; status: string }>();
		expect(stored).toEqual({ email: "creator@example.com", status: "emailed" });
	});

	it("atomically limits concurrent Boost requests to three per IP and hour", async () => {
		await ensureTestSchema();
		await env.creatorrr_db.prepare("DELETE FROM boost_fit_requests").run();
		await env.creatorrr_db.prepare("DELETE FROM boost_fit_rate_limits").run();
		vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
		const testEnv = { ...env, RESEND_API_KEY: "test-key", RESEND_FROM_EMAIL: "noreply@mail.creatorrr.com" };
		const payload = {
			email: "creator@example.com", telegram: "", links: "https://example.com/profile",
			stage: "1–6 months", revenueHave: "$0–$500", revenueWant: "$2,000–$5,000",
			help: "I post three times per week.", timePerDay: "1–2 hours",
		};
		const responses = await Promise.all(Array.from({ length: 6 }, async () => {
			const request = new IncomingRequest("https://api.creatorrr.com/api/boost-fit", {
				method: "POST",
				headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.20" },
				body: JSON.stringify(payload),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, testEnv, ctx);
			await waitOnExecutionContext(ctx);
			return response;
		}));

		expect(responses.filter((response) => response.status === 200)).toHaveLength(3);
		expect(responses.filter((response) => response.status === 429)).toHaveLength(3);
	});
	it("returns dashboard traffic windows with unbounded download totals and daily downloads", async () => {
		await ensureTestSchema();
		await env.creatorrr_db.batch([
			env.creatorrr_db.prepare("DELETE FROM analytics_pageviews"),
			env.creatorrr_db.prepare("DELETE FROM analytics_events"),
		]);

		const { userId, email } = await seedVerifiedUserWithDevices(["dashboard-device"]);
		const jwtSecret = "test-dashboard-secret";
		const testEnv = {
			...env,
			DASHBOARD_OWNER_EMAILS: email,
			JWT_SECRET: jwtSecret,
		};
		const token = await jwtSign(jwtSecret, {
			sub: userId,
			did: "dashboard-device",
			tv: 0,
			exp: Math.floor(Date.now() / 1000) + 3600,
		});

		const now = new Date();
		const daysAgo = (days: number) => new Date(now.getTime() - days * 24 * 60 * 60 * 1000).toISOString();
		const statements = [
			env.creatorrr_db.prepare("INSERT INTO analytics_pageviews (id, created_at, path, country, ip_hash, is_bot) VALUES (?1, ?2, ?3, ?4, ?5, ?6)").bind("pv-us-1", daysAgo(1), "/", "US", "ip-us", 0),
			env.creatorrr_db.prepare("INSERT INTO analytics_pageviews (id, created_at, path, country, ip_hash, is_bot) VALUES (?1, ?2, ?3, ?4, ?5, ?6)").bind("pv-ch", daysAgo(1), "/", "CH", "ip-ch", 0),
			env.creatorrr_db.prepare("INSERT INTO analytics_pageviews (id, created_at, path, country, ip_hash, is_bot) VALUES (?1, ?2, ?3, ?4, ?5, ?6)").bind("pv-us-2", daysAgo(10), "/account", "US", "ip-us-2", 0),
			env.creatorrr_db.prepare("INSERT INTO analytics_pageviews (id, created_at, path, country, ip_hash, is_bot) VALUES (?1, ?2, ?3, ?4, ?5, ?6)").bind("pv-old", daysAgo(40), "/old", "DE", "ip-de", 0),
			env.creatorrr_db.prepare("INSERT INTO analytics_events (id, created_at, event_name, item_id, item_version, item_variant, country, ip_hash, is_bot) VALUES (?1, ?2, 'download_click', ?3, ?4, ?5, ?6, ?7, 0)").bind("dl-old", daysAgo(40), "contentorrr_macos_old", "1.1.2", "dmg", "DE", "ip-de"),
		];

		for (let i = 0; i < 35; i += 1) {
			statements.push(
				env.creatorrr_db.prepare("INSERT INTO analytics_events (id, created_at, event_name, item_id, item_version, item_variant, country, ip_hash, is_bot) VALUES (?1, ?2, 'download_click', ?3, ?4, ?5, ?6, ?7, 0)")
					.bind(`dl-${i}`, daysAgo(1), `contentorrr_${i}`, "1.1.2", "exe", i === 0 ? "CH" : "US", `ip-${i}`),
			);
		}

		await env.creatorrr_db.batch(statements);

		const sevenDayRequest = new IncomingRequest("https://example.com/dashboard/traffic?window=7", {
			headers: { authorization: `Bearer ${token}` },
		});
		const sevenDayCtx = createExecutionContext();
		const sevenDay = await worker.fetch(sevenDayRequest, testEnv, sevenDayCtx);
		await waitOnExecutionContext(sevenDayCtx);
		expect(sevenDay.status).toBe(200);
		const sevenDayBody = await sevenDay.json<{
			window: string;
			totals: { pageviews: number; downloads: number };
			countries: Array<{ country: string; visits: number }>;
			downloads: Array<{ downloads: number }>;
			daily: Array<{ downloads: number }>;
		}>();
		expect(sevenDayBody).toMatchObject({
			window: "7",
			totals: { pageviews: 2, downloads: 35 },
		});
		expect(sevenDayBody.countries).toEqual(
			expect.arrayContaining([
				{ country: "US", visits: 1 },
				{ country: "CH", visits: 1 },
			]),
		);
		expect(sevenDayBody.downloads).toHaveLength(30);
		expect(sevenDayBody.daily.reduce((sum, row) => sum + row.downloads, 0)).toBe(35);

		const allTimeRequest = new IncomingRequest("https://example.com/dashboard/traffic?window=all", {
			headers: { authorization: `Bearer ${token}` },
		});
		const allTimeCtx = createExecutionContext();
		const allTime = await worker.fetch(allTimeRequest, testEnv, allTimeCtx);
		await waitOnExecutionContext(allTimeCtx);
		expect(allTime.status).toBe(200);
		await expect(allTime.json()).resolves.toMatchObject({
			window: "all",
			totals: { pageviews: 4, downloads: 36 },
		});
	});

});
