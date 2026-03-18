import { describe, expect, it } from 'vitest';
import {
  makeStripeAutoRenewUpdateForm,
  makeStripeSubscriptionIntervalUpdateForm,
} from '../src/services/stripe';

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

describe('makeStripeSubscriptionIntervalUpdateForm', () => {
  it('changes the subscription price without proration and keeps the existing anchor', () => {
    const form = makeStripeSubscriptionIntervalUpdateForm('si_123', 'price_year');

    expect(form.get('items[0][id]')).toBe('si_123');
    expect(form.get('items[0][price]')).toBe('price_year');
    expect(form.get('items[0][quantity]')).toBe('1');
    expect(form.get('billing_cycle_anchor')).toBe('unchanged');
    expect(form.get('proration_behavior')).toBe('none');
  });
});
