export interface Env {
  creatorrr_db: D1Database;
  JWT_SECRET: string;
  STRIPE_SECRET_KEY: string;
  STRIPE_PRICE_ID_MONTHLY: string;
  STRIPE_PRICE_ID_YEARLY: string;
  STRIPE_WEBHOOK_SECRET: string;
  SITE_URL: string;
  STRIPE_PORTAL_RETURN_URL?: string;
  RESEND_API_KEY?: string;
  RESEND_FROM_EMAIL?: string;
  RESEND_FROM_NAME?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GOOGLE_OAUTH_ENABLED?: string;
  DASHBOARD_OWNER_EMAILS?: string;
  DASHBOARD_MONTHLY_PRICE_USD?: string;
  DASHBOARD_YEARLY_PRICE_USD?: string;
}

export type LicenseRow = {
  user_id: string;
  plan: string;
  status: string;
  notes?: string | null;
  created_at: string;
  updated_at: string;
  stripe_customer_id?: string | null;
  stripe_subscription_id?: string | null;
  stripe_price_id?: string | null;
  billing_interval?: string | null;
  current_period_start?: string | null;
  current_period_end?: string | null;
  trial_start_at?: string | null;
  trial_end_at?: string | null;
  scheduled_billing_interval?: string | null;
  scheduled_change_at?: string | null;
  cancel_at?: string | null;
  canceled_at?: string | null;
  ended_at?: string | null;
};

export type UserRow = {
  id: string;
  email: string;
  pass_salt: string;
  pass_hash: string;
  created_at: string;
  email_verified_at?: string | null;
  password_reset_token_hash?: string | null;
  password_reset_expires_at?: string | null;
  email_verify_token_hash?: string | null;
  email_verify_expires_at?: string | null;
  updated_at?: string | null;
};

export type EntitlementView = {
  plan: string;
  status: string;
  entitled: boolean;
  entitled_until: string | null;
  in_trial: boolean;
  cancel_at: string | null;
};

export type LegalAcceptanceRow = {
  id: string;
  user_id: string;
  terms_version: string;
  privacy_version: string;
  refund_version: string;
  accepted_at: string;
  acceptance_context: string;
  ip_address?: string | null;
  user_agent?: string | null;
  created_at: string;
};

export type LegalAcceptancePayload = {
  accepted?: boolean;
  terms_version?: string;
  privacy_version?: string;
  refund_version?: string;
};

export type AuthContext = {
  userId: string;
  deviceId: string;
  tokenVersion: number;
};

export type StripeCheckoutSessionResponse = {
  id: string;
  url?: string | null;
};

export type StripePortalSessionResponse = {
  url?: string | null;
};

export type StripeSubscriptionLike = {
  id: string;
  customer?: string | null;
  schedule?: string | null | { id?: string | null } | false;
  billing_mode?: {
    type?: string | null;
  } | null;
  status?: string | null;
  cancel_at?: number | null;
  canceled_at?: number | null;
  ended_at?: number | null;
  current_period_start?: number | null;
  current_period_end?: number | null;
  trial_start?: number | null;
  trial_end?: number | null;
  metadata?: Record<string, string>;
  items?: {
    data?: Array<{
      id?: string | null;
      quantity?: number | null;
      current_period_start?: number | null;
      current_period_end?: number | null;
      price?: {
        id?: string | null;
        recurring?: {
          interval?: string | null;
        } | null;
      } | null;
    }>;
  } | null;
};

export type StripeSubscriptionScheduleLike = {
  id: string;
  subscription?: string | null;
  status?: string | null;
  current_phase?: {
    start_date?: number | null;
    end_date?: number | null;
  } | null;
  phases?: Array<{
    start_date?: number | null;
    end_date?: number | null;
    proration_behavior?: string | null;
    items?: Array<{
      price?: string | { id?: string | null } | null;
      quantity?: number | null;
    }> | null;
  }> | null;
};

export type GoogleIdTokenInfo = {
  sub: string;
  email?: string;
  email_verified?: string;
};
