import type { Env } from "../types";

export function nowIso() {
  return new Date().toISOString();
}

export function uuid() {
  return crypto.randomUUID();
}

export function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

export async function readJson<T = any>(req: Request): Promise<T | null> {
  try {
    return (await req.json()) as T;
  } catch {
    return null;
  }
}

export function getBearer(req: Request) {
  const h = req.headers.get("authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

export function normalizeDeviceId(deviceId: string) {
  const v = deviceId.trim();
  if (!v) return "";
  if (v.length > 80) return "";
  return v;
}

export function normalizeClientNonce(v: string) {
  const s = (v || "").trim();
  if (!s) return "";
  if (s.length > 120) return "";
  return s;
}

export function parseIsoMs(v: unknown): number | null {
  if (typeof v !== "string" || !v.trim()) return null;
  const ms = Date.parse(v);
  return Number.isFinite(ms) ? ms : null;
}

export function normalizeSiteUrl(v: string): string {
  return (v || "").trim().replace(/\/+$/, "");
}

export function safeSiteUrl(env: Env): string {
  return normalizeSiteUrl(env.SITE_URL || "https://creatorrr.com") || "https://creatorrr.com";
}

export function escapeHtml(v: string): string {
  return v
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function unixToIso(v: unknown): string | null {
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) return null;
  return new Date(v * 1000).toISOString();
}

export function addMinutesIso(minutes: number): string {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

export function isExpiredIso(v: string | null | undefined): boolean {
  if (!v) return true;
  const ms = Date.parse(v);
  return !Number.isFinite(ms) || ms <= Date.now();
}

export function asRecord(v: unknown): Record<string, any> {
  return v && typeof v === "object" ? (v as Record<string, any>) : {};
}

export function getCookieValue(req: Request, name: string): string {
  const cookie = req.headers.get("cookie") || "";
  if (!cookie) return "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const s = p.trim();
    if (!s) continue;
    const idx = s.indexOf("=");
    if (idx <= 0) continue;
    const k = s.slice(0, idx).trim();
    if (k !== name) continue;
    return s.slice(idx + 1).trim();
  }
  return "";
}
