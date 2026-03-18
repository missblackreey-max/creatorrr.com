import { describe, expect, it } from 'vitest';
import {
  makeStripeAutoRenewUpdateForm,
  makeStripeSubscriptionScheduleCreateForm,
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

describe('makeStripeSubscriptionScheduleCreateForm', () => {
  it('creates schedules from the existing subscription without extra create-only params', () => {
    const form = makeStripeSubscriptionScheduleCreateForm('sub_123');

    expect(form.get('from_subscription')).toBe('sub_123');
    expect(form.get('end_behavior')).toBeNull();
  });
});

describe('makeStripeSubscriptionScheduleUpdateForm', () => {
  it('keeps the current phase intact and schedules the next interval at the period boundary', () => {
    const form = makeStripeSubscriptionScheduleUpdateForm(
      'price_month',
      1733011200,
      1735689600,
      'price_year',
    );

    expect(form.get('end_behavior')).toBe('release');
    expect(form.get('proration_behavior')).toBe('none');
    expect(form.get('phases[0][start_date]')).toBe('1733011200');
    expect(form.get('phases[0][end_date]')).toBe('1735689600');
    expect(form.get('phases[0][items][0][price]')).toBe('price_month');
    expect(form.get('phases[1][start_date]')).toBe('1735689600');
    expect(form.get('phases[1][billing_cycle_anchor]')).toBe('phase_start');
    expect(form.get('phases[1][proration_behavior]')).toBe('none');
    expect(form.get('phases[1][items][0][price]')).toBe('price_year');
  });
});
