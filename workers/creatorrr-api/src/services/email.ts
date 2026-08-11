import type { Env } from "../types";
import { makeOpaqueToken, sha256Hex } from "../lib/crypto";
import { addMinutesIso, escapeHtml, nowIso, safeSiteUrl } from "../lib/utils";

async function sendPasswordResetEmail(env: Env, toEmail: string, resetUrl: string): Promise<boolean> {
  const apiKey = String(env.RESEND_API_KEY || "").trim();
  const fromEmail = String(env.RESEND_FROM_EMAIL || "noreply@mail.creatorrr.com").trim();
  const fromName = String(env.RESEND_FROM_NAME || "Creatorrr").trim() || "Creatorrr";
  if (!apiKey || !fromEmail) return false;

  const safeUrl = escapeHtml(resetUrl);
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: `${fromName} <${fromEmail}>`,
      to: [toEmail],
      subject: "Reset your Creatorrr password",
      html: [
        '<div style="padding:22px 18px;text-align:center;background:#060606;border-radius:18px;margin-bottom:24px;"><img src="https://creatorrr.com/creatorrr-logo-nolink.png" alt="creatorrr.com" width="72" height="72" style="display:inline-block;border-radius:16px;"></div>',
        "<p>You requested a password reset for your Creatorrr account.</p>",
        `<p><a href=\"${safeUrl}\">Reset your password</a></p>`,
        "<p>This link expires in 30 minutes. If you did not request this, you can ignore this email.</p>",
      ].join(""),
    }),
  });

  return response.ok;
}

async function sendEmailVerificationEmail(
  env: Env,
  toEmail: string,
  verificationUrl: string,
): Promise<boolean> {
  const apiKey = String(env.RESEND_API_KEY || "").trim();
  const fromEmail = String(env.RESEND_FROM_EMAIL || "noreply@mail.creatorrr.com").trim();
  const fromName = String(env.RESEND_FROM_NAME || "Creatorrr").trim() || "Creatorrr";
  if (!apiKey || !fromEmail) return false;

  const safeUrl = escapeHtml(verificationUrl);
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: `${fromName} <${fromEmail}>`,
      to: [toEmail],
      subject: "Verify your Creatorrr email",
      html: [
        '<div style="padding:22px 18px;text-align:center;background:#060606;border-radius:18px;margin-bottom:24px;"><img src="https://creatorrr.com/creatorrr-logo-nolink.png" alt="creatorrr.com" width="72" height="72" style="display:inline-block;border-radius:16px;"></div>',
        "<p>Thanks for creating your Creatorrr account.</p>",
        `<p><a href=\"${safeUrl}\">Verify your email address</a></p>`,
        "<p>This link expires in 24 hours. If you did not create this account, you can ignore this email.</p>",
      ].join(""),
    }),
  });

  return response.ok;
}

export function isEmailDeliveryConfigured(env: Env): boolean {
  return Boolean(String(env.RESEND_API_KEY || "").trim() && String(env.RESEND_FROM_EMAIL || "").trim());
}

export async function issueEmailVerification(
  env: Env,
  userId: string,
  email: string,
): Promise<{ sent: boolean; expires_at: string }> {
  const rawToken = makeOpaqueToken();
  const tokenHash = await sha256Hex(rawToken);
  const expiresAt = addMinutesIso(60 * 24);
  const now = nowIso();

  const previous = await env.creatorrr_db
    .prepare(
      `
        SELECT
          email_verify_token_hash,
          email_verify_expires_at
        FROM users
        WHERE id=?1
      `,
    )
    .bind(userId)
    .first<{ email_verify_token_hash?: string | null; email_verify_expires_at?: string | null }>();

  await env.creatorrr_db
    .prepare(
      `
        UPDATE users
        SET
          email_verify_token_hash=?2,
          email_verify_expires_at=?3,
          updated_at=?4
        WHERE id=?1
      `,
    )
    .bind(userId, tokenHash, expiresAt, now)
    .run();

  const siteUrl = safeSiteUrl(env);
  const verifyUrl = `${siteUrl}/verify-email.html?token=${encodeURIComponent(rawToken)}`;
  const mailed = await sendEmailVerificationEmail(env, email, verifyUrl).catch(() => false);

  if (!mailed) {
    await env.creatorrr_db
      .prepare(
        `
          UPDATE users
          SET
            email_verify_token_hash=?2,
            email_verify_expires_at=?3,
            updated_at=?4
          WHERE id=?1
        `,
      )
      .bind(
        userId,
        previous?.email_verify_token_hash || null,
        previous?.email_verify_expires_at || null,
        nowIso(),
      )
      .run();
  }

  return {
    sent: mailed,
    expires_at: mailed ? expiresAt : String(previous?.email_verify_expires_at || expiresAt),
  };
}

export async function issuePasswordReset(env: Env, userId: string, email: string) {
  const rawToken = makeOpaqueToken();
  const tokenHash = await sha256Hex(rawToken);
  const expiresAt = addMinutesIso(30);
  const now = nowIso();

  await env.creatorrr_db
    .prepare(`
      UPDATE users
      SET
        password_reset_token_hash=?2,
        password_reset_expires_at=?3,
        updated_at=?4
      WHERE id=?1
    `)
    .bind(userId, tokenHash, expiresAt, now)
    .run();

  const siteUrl = safeSiteUrl(env);
  const resetUrl = `${siteUrl}/reset-password.html?token=${encodeURIComponent(rawToken)}`;
  const mailed = await sendPasswordResetEmail(env, email, resetUrl).catch(() => false);

  return {
    sent: true,
    delivery: mailed ? "email" : "link",
    reset_url: mailed ? undefined : resetUrl,
    expires_at: expiresAt,
  };
}

export async function sendSubscriberVerificationEmail(
  env: Env,
  toEmail: string,
  verificationUrl: string,
): Promise<boolean> {
  const apiKey = String(env.RESEND_API_KEY || "").trim();
  const fromEmail = String(env.RESEND_FROM_EMAIL || "noreply@mail.creatorrr.com").trim();
  const fromName = String(env.RESEND_FROM_NAME || "Creatorrr").trim() || "Creatorrr";
  if (!apiKey || !fromEmail) return false;

  const safeUrl = escapeHtml(verificationUrl);
  const redditUrl = "https://www.reddit.com/r/CreatorrrHub/";
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: `${fromName} <${fromEmail}>`,
      to: [toEmail],
      subject: "Confirm creatorrr.com updates",
      html: [
        '<div style="padding:22px 18px;text-align:center;background:#060606;border-radius:18px;margin-bottom:24px;"><img src="https://creatorrr.com/creatorrr-logo-nolink.png" alt="creatorrr.com" width="72" height="72" style="display:inline-block;border-radius:16px;"></div>',
        "<p>Thanks for signing up for creatorrr.com updates.</p>",
        `<p>We’ll send version updates and weekly insights on how we approach the adult creator business. You’re also invited to join r/CreatorrrHub on Reddit: <a href=\"${redditUrl}\">${redditUrl}</a></p>`,
        "<p>Please confirm your email address.</p>",
        `<p><a href=\"${safeUrl}\">Confirm your email</a></p>`,
        "<p>This link expires in 24 hours. If you did not request this, you can ignore this email.</p>",
      ].join(""),
    }),
  });

  return response.ok;
}

export type BoostFitEmailData = {
  email: string;
  telegram: string;
  links: string;
  stage: string;
  revenueHave: string;
  revenueWant: string;
  help: string;
  timePerDay: string;
};

export async function sendBoostFitEmails(env: Env, data: BoostFitEmailData): Promise<boolean> {
  const apiKey = String(env.RESEND_API_KEY || "").trim();
  const fromEmail = String(env.RESEND_FROM_EMAIL || "noreply@mail.creatorrr.com").trim();
  const fromName = String(env.RESEND_FROM_NAME || "Creatorrr").trim() || "Creatorrr";
  const adminEmail = String(env.BOOST_ADMIN_EMAIL || "ben@creatorrr.com").trim();
  if (!apiKey || !fromEmail || !adminEmail) return false;

  const rows: Array<[string, string]> = [
    ["Email", data.email],
    ["Telegram", data.telegram || "—"],
    ["Profiles / links", data.links],
    ["Creating for", data.stage],
    ["Monthly revenue now", data.revenueHave],
    ["Monthly revenue goal", data.revenueWant],
    ["Current strategy & workflow", data.help],
    ["Time available per day", data.timePerDay],
  ];
  const answers = rows.map(([label, value]) =>
    `<p><strong>${escapeHtml(label)}</strong><br>${escapeHtml(value).replace(/\n/g, "<br>")}</p>`,
  ).join("");
  const header = '<div style="padding:22px 18px;text-align:center;background:#060606;border-radius:18px;margin-bottom:24px;"><img src="https://creatorrr.com/creatorrr-logo-nolink.png" alt="creatorrr.com" width="72" height="72" style="display:inline-block;border-radius:16px;"></div>';

  const response = await fetch("https://api.resend.com/emails/batch", {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify([
      {
        from: `${fromName} <${fromEmail}>`,
        to: [adminEmail],
        reply_to: data.email,
        subject: `New Creatorrr Boost fit request — ${data.email}`,
        html: `${header}<h2>New Creatorrr Boost fit request</h2>${answers}`,
      },
      {
        from: `${fromName} <${fromEmail}>`,
        to: [data.email],
        subject: "We received your Creatorrr Boost fit request",
        html: `${header}<p>Thanks for applying for Creatorrr Boost. We received your fit request and will get back to you as soon as possible.</p><h2>Your answers</h2>${answers}`,
      },
    ]),
  });

  return response.ok;
}
