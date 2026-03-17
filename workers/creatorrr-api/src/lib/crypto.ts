export function b64url(bytes: ArrayBufferLike) {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function b64urlText(s: string) {
  return b64url(new TextEncoder().encode(s).buffer);
}

async function hmacSign(secret: string, data: string): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
}

export async function hmacSha256(secret: string, data: string) {
  return b64url(await hmacSign(secret, data));
}

export async function hmacSha256Hex(secret: string, data: string) {
  const bytes = new Uint8Array(await hmacSign(secret, data));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256Hex(data: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  const bytes = new Uint8Array(digest);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function jwtSign(secret: string, payload: any) {
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64urlText(JSON.stringify(header));
  const p = b64urlText(JSON.stringify(payload));
  const msg = `${h}.${p}`;
  const sig = await hmacSha256(secret, msg);
  return `${msg}.${sig}`;
}

export async function jwtVerify(secret: string, token: string) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const msg = `${h}.${p}`;
  const expected = await hmacSha256(secret, msg);
  if (expected !== s) return null;
  const payloadJson = atob(p.replace(/-/g, "+").replace(/_/g, "/"));
  return JSON.parse(payloadJson);
}

export function makeSalt() {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  let bin = "";
  for (const b of salt) bin += String.fromCharCode(b);
  return btoa(bin);
}

export async function pbkdf2(password: string, saltB64: string) {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256,
  );
  const bytes = new Uint8Array(bits);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function makeOpaqueToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return b64url(bytes.buffer);
}

export function makeOpaqueSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return b64url(bytes.buffer);
}

export function timingSafeEqualStr(a: string, b: string): boolean {
  const aa = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa[i] ^ bb[i];
  return diff === 0;
}
