import { describe, expect, it } from 'vitest';
import {
  makeStripeAutoRenewUpdateForm,
  makeStripeSubscriptionScheduleUpdateForm,
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

describe('makeStripeSubscriptionScheduleUpdateForm', () => {
  it('keeps the current phase intact and schedules the next renewal price without proration', () => {
    const form = makeStripeSubscriptionScheduleUpdateForm({
      startDate: 1733011200,
      endDate: 1735689600,
      currentPriceId: 'price_month',
      quantity: 1,
    }, 'price_year');

    expect(form.get('end_behavior')).toBe('release');
    expect(form.get('proration_behavior')).toBe('none');
    expect(form.get('phases[0][start_date]')).toBe('1733011200');
    expect(form.get('phases[0][end_date]')).toBe('1735689600');
    expect(form.get('phases[0][items][0][price]')).toBe('price_month');
    expect(form.get('phases[0][items][0][quantity]')).toBe('1');
    expect(form.get('phases[0][proration_behavior]')).toBe('none');
    expect(form.get('phases[1][start_date]')).toBe('1735689600');
    expect(form.get('phases[1][items][0][price]')).toBe('price_year');
    expect(form.get('phases[1][items][0][quantity]')).toBe('1');
    expect(form.get('phases[1][proration_behavior]')).toBe('none');
  });
});
