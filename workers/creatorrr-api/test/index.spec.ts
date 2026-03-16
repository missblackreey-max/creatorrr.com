import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('creatorrr-api worker', () => {
	it('returns not_found for unknown paths (unit style)', async () => {
		const request = new IncomingRequest('https://example.com/');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(404);
		expect(await response.json()).toEqual({ ok: false, error: 'not_found' });
	});

	it('handles CORS preflight (integration style)', async () => {
		const response = await SELF.fetch('https://example.com/auth/login', {
			method: 'OPTIONS',
			headers: {
				origin: 'https://creatorrr.com',
				'access-control-request-method': 'POST',
			},
		});

		expect(response.status).toBe(204);
		expect(response.headers.get('access-control-allow-origin')).toBe('https://creatorrr.com');
		expect(response.headers.get('access-control-allow-methods')).toContain('POST');
	});

	it('rejects verify-email requests without a token', async () => {
		const response = await SELF.fetch('https://example.com/auth/verify-email', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
			},
			body: JSON.stringify({ token: '' }),
		});

		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ ok: false, error: 'invalid_input' });
	});

	it('rejects resend-verification requests without an email', async () => {
		const response = await SELF.fetch('https://example.com/auth/resend-verification', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
			},
			body: JSON.stringify({ email: '' }),
		});

		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ ok: false, error: 'invalid_input' });
	});

});
