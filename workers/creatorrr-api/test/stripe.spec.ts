import { describe, expect, it } from 'vitest';
import { makeStripeAutoRenewUpdateForm } from '../src/services/stripe';

describe('makeStripeAutoRenewUpdateForm', () => {
  it('clears cancel_at when auto-renew is enabled', () => {
    const form = makeStripeAutoRenewUpdateForm({
      id: 'sub_123',
      current_period_end: 1735689600,
      cancel_at: 1735689600,
    }, true);

    expect(form?.get('cancel_at')).toBe('');
  });

  it('uses current_period_end as cancel_at when auto-renew is disabled', () => {
    const form = makeStripeAutoRenewUpdateForm({
      id: 'sub_123',
      current_period_end: 1735689600,
    }, false);

    expect(form?.get('cancel_at')).toBe('1735689600');
  });

  it('falls back to the first subscription item period end when needed', () => {
    const form = makeStripeAutoRenewUpdateForm({
      id: 'sub_123',
      items: {
        data: [
          {
            id: 'si_123',
            price: { id: 'price_123', recurring: { interval: 'month' } },
            current_period_end: 1735689600,
          },
        ],
      },
    }, false);

    expect(form?.get('cancel_at')).toBe('1735689600');
  });

  it('returns null when Stripe gives us no period end to cancel on', () => {
    const form = makeStripeAutoRenewUpdateForm({
      id: 'sub_123',
    }, false);

    expect(form).toBeNull();
  });
});
