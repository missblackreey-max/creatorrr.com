# Refactor Recommendations

## Scope Reviewed
- `workers/creatorrr-api/src/index.ts`
- `public/index.html`
- `public/account.html`
- `public/reset-password.html`
- `public/verify-email.html`

## Highest Priority Refactors

### 1) Break up `workers/creatorrr-api/src/index.ts` (currently monolithic)
**Why:** The file mixes routing, auth/session logic, Stripe integration, OAuth, email workflows, token crypto, and SQL access in one 1,900+ line module. This increases cognitive load and makes targeted testing difficult.

**How:**
- Introduce folders:
  - `src/http/` (`cors.ts`, `responses.ts`, `router.ts`)
  - `src/auth/` (`jwt.ts`, `password.ts`, `devices.ts`, `oauth-google.ts`)
  - `src/billing/` (`stripe-client.ts`, `stripe-webhooks.ts`, `entitlements.ts`)
  - `src/email/` (`resend.ts`, `templates.ts`)
  - `src/db/` (`users.repo.ts`, `licenses.repo.ts`, `oauth.repo.ts`)
- Keep `src/index.ts` as a thin composition root (route registration + dependency wiring).

### 2) Consolidate duplicate utility logic
**Why:** There are duplicate timestamp helpers (`nowIso` and `isoNow`) and repeated HMAC key import logic across digest helpers.

**How:**
- Keep one timestamp helper (`nowIso`).
- Add reusable crypto primitives:
  - `signHmacSha256(secret, data): ArrayBuffer`
  - `toHex(bytes)` / `toBase64Url(bytes)`
- Keep JWT code in a dedicated auth utility module.

### 3) Introduce repository layer for repeated SQL blocks
**Why:** User row selection columns are repeated in multiple queries. Inline SQL in handlers causes route blocks to become large and error-prone when schema changes.

**How:**
- Extract SQL into repository functions:
  - `usersRepo.findByEmail(email)`
  - `usersRepo.findById(id)`
  - `usersRepo.updatePasswordReset(...)`
  - `licensesRepo.upsertFromStripeSubscription(...)`
- Define one canonical user select fragment and reuse it.

### 4) Split route handlers by domain
**Why:** Current `fetch` method has many long conditional branches; this makes control flow hard to scan and complicates middleware-like reuse (auth checks, body parsing, config validation).

**How:**
- Use a small router table (`method + pathname -> handler`).
- Route files:
  - `routes/auth.ts`
  - `routes/account.ts`
  - `routes/license.ts`
  - `routes/stripe.ts`
- Add shared guards (`requireAuth`, `requireStripeConfig`) as composable wrappers.

### 5) Strengthen type safety around request/response payloads
**Why:** `any` appears in event/object parsing and DB reads, and ad-hoc casting is common. This weakens confidence in refactors.

**How:**
- Add Zod schemas for incoming payloads (register/login/checkout/reset).
- Add typed Stripe event narrowing utilities.
- Replace `Record<string, any>` where possible with precise interfaces.

## Medium Priority Refactors

### 6) Centralize email sending concerns
**Why:** Password-reset and verification email flows duplicate sender setup and request construction.

**How:**
- Build a generic `sendEmail({to, subject, html})` in `email/resend.ts`.
- Keep template builders in `email/templates.ts`.
- Return structured results (`{ok:boolean, providerStatus?:number, error?:string}`).

### 7) Extract account and entitlement view mappers
**Why:** Response shaping logic is currently mixed with endpoint control flow.

**How:**
- Create `presenters/account.presenter.ts` and `presenters/entitlement.presenter.ts`.
- Keep route handlers focused on orchestration only.

### 8) Normalize and deduplicate static frontend pages
**Why:** `public/index.html` and `public/account.html` are large, likely containing repeated styles/scripts and mixed concerns.

**How:**
- Move shared CSS and JS into static assets:
  - `public/assets/styles/common.css`
  - `public/assets/js/account.js`, `landing.js`, etc.
- Use small reusable JS helpers for API calls, token storage, and form state.

## Low Priority / Opportunistic

### 9) Add lightweight architectural tests
- Unit tests for:
  - entitlement edge cases
  - webhook signature validation
  - token verify/sign mismatch cases
- Route tests by domain instead of one large integration file.

### 10) Add internal boundaries documentation
- `docs/architecture.md` with module responsibilities and data flow.
- Keep migration policy notes (how repo methods evolve with D1 schema changes).

## Suggested Implementation Sequence
1. Extract utilities (`time`, `crypto`, `responses`) with no behavior changes.
2. Extract repositories and keep route outputs unchanged.
3. Move auth and stripe flows into domain modules.
4. Introduce router table and shrink `index.ts`.
5. Modularize frontend assets (`public/assets/*`).
6. Add unit tests around extracted business logic.

## Expected Outcome
- Smaller, testable modules.
- Lower regression risk when changing auth/billing.
- Faster onboarding for contributors due to clearer boundaries.
