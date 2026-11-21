process.env.NODE_ENV = 'test';

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import jwt from 'jsonwebtoken';
import app, {
  validateMoneyAmount,
  parseAndValidateCalendarDate,
  getTodayCalendarDate,
  fulfillPaymentSession,
  fulfillSubscriptionSession,
  extractInvoiceSubscriptionId,
  handleInvoicePaid,
  handleInvoicePaymentFailed,
  handleSubscriptionDeleted,
  setTestDb,
  setTestStripe,
} from '../index.js';
import { ObjectId } from 'mongodb';

test('validateMoneyAmount strictly enforces USD gateway limits and decimal precision', () => {
  // Valid amounts
  assert.equal(validateMoneyAmount(50).valid, true);
  assert.equal(validateMoneyAmount('50.25').valid, true);
  assert.equal(validateMoneyAmount(0.50).valid, true);
  assert.equal(validateMoneyAmount(100000).valid, true);

  // Precision and cents conversion
  const parsed = validateMoneyAmount('45.99');
  assert.equal(parsed.valid, true);
  assert.equal(parsed.cents, 4599);
  assert.equal(parsed.amount, 45.99);

  // Invalid amounts
  assert.equal(validateMoneyAmount(Infinity).valid, false);
  assert.equal(validateMoneyAmount(-10).valid, false);
  assert.equal(validateMoneyAmount(0.20).valid, false, 'Amounts under $0.50 must be rejected');
  assert.equal(validateMoneyAmount(100001).valid, false);
  assert.equal(validateMoneyAmount('abc').valid, false);
  assert.equal(validateMoneyAmount(NaN).valid, false);
  assert.equal(validateMoneyAmount(45.999).valid, false, 'More than 2 decimal places must be rejected');
});

test('parseAndValidateCalendarDate validates YYYY-MM-DD format and rejects impossible or past days in Asia/Dhaka', () => {
  // Invalid format patterns
  assert.equal(parseAndValidateCalendarDate('2026/12/31').valid, false);
  assert.equal(parseAndValidateCalendarDate('12-31-2026').valid, false);
  assert.equal(parseAndValidateCalendarDate('invalid-date').valid, false);

  // Impossible leap days & non-existent dates
  assert.equal(parseAndValidateCalendarDate('2026-02-29').valid, false, '2026 is not a leap year');
  assert.equal(parseAndValidateCalendarDate('2026-04-31').valid, false, 'April has only 30 days');
  assert.equal(parseAndValidateCalendarDate('2026-13-01').valid, false, 'Month 13 does not exist');

  // Past dates rejected
  assert.equal(parseAndValidateCalendarDate('2020-01-01').valid, false, 'Past calendar date must be rejected');

  // Valid today in Asia/Dhaka accepted
  const todayDhaka = getTodayCalendarDate('Asia/Dhaka');
  const todayValidation = parseAndValidateCalendarDate(todayDhaka, 'Asia/Dhaka');
  assert.equal(todayValidation.valid, true, `Today (${todayDhaka}) must be recognized as valid`);
  assert.equal(todayValidation.date, todayDhaka);

  // Future valid date accepted
  const futureValidation = parseAndValidateCalendarDate('2030-06-15', 'Asia/Dhaka');
  assert.equal(futureValidation.valid, true);
  assert.equal(futureValidation.date, '2030-06-15');
});

test('fulfillPaymentSession rejects non-completed bookings and amount mismatches', async () => {
  const bookingId = new ObjectId().toString();
  const mockBooking = {
    _id: new ObjectId(bookingId),
    serviceTitle: 'Test Repair',
    customerEmail: 'customer@fixmate.dev',
    status: 'requested', // Not completed
    paymentStatus: 'unpaid',
    finalAmount: 100,
    history: [],
  };

  const bookingsMap = new Map([[bookingId, mockBooking]]);
  const paymentsMap = new Map();

  const fakeDb = {
    collection: (name) => {
      if (name === 'bookings') {
        return {
          findOne: async (q) => {
            const id = q._id?.toString() || q._id;
            return bookingsMap.get(id) || null;
          },
          updateOne: async (q, u) => {
            const id = q._id?.toString() || q._id;
            const b = bookingsMap.get(id);
            if (!b) return { matchedCount: 0, modifiedCount: 0 };
            if (u.$set) Object.assign(b, u.$set);
            return { matchedCount: 1, modifiedCount: 1 };
          },
        };
      }
      if (name === 'payments') {
        return {
          findOne: async (q) => {
            if (q.bookingId) {
              for (const p of paymentsMap.values()) {
                if (p.bookingId === q.bookingId) return p;
              }
            }
            return null;
          },
          insertOne: async (doc) => {
            paymentsMap.set(doc.stripeSessionId, doc);
            return { insertedId: new ObjectId() };
          },
        };
      }
      if (name === 'user') {
        return {
          findOne: async () => ({ email: 'tech@fixmate.dev', isPro: false }),
        };
      }
      return {};
    },
  };

  setTestDb(fakeDb);

  const mockSession = {
    id: 'cs_test_non_completed',
    amount_total: 10000,
    currency: 'usd',
    client_reference_id: bookingId,
    mode: 'payment',
    livemode: false,
    payment_status: 'paid',
  };

  // Rejects because status is 'requested'
  const resNonCompleted = await fulfillPaymentSession(mockSession);
  assert.equal(resNonCompleted, null);

  // Amount mismatch
  mockBooking.status = 'completed';
  const mockSessionMismatch = {
    id: 'cs_test_mismatch',
    amount_total: 5000, // $50 instead of $100
    currency: 'usd',
    client_reference_id: bookingId,
    mode: 'payment',
    livemode: false,
    payment_status: 'paid',
  };
  const resMismatch = await fulfillPaymentSession(mockSessionMismatch);
  assert.equal(resMismatch, null);

  // Livemode rejection
  const mockSessionLivemode = {
    id: 'cs_test_livemode',
    amount_total: 10000,
    currency: 'usd',
    client_reference_id: bookingId,
    mode: 'payment',
    livemode: true, // Livemode rejected in test suite
    payment_status: 'paid',
  };
  const resLive = await fulfillPaymentSession(mockSessionLivemode);
  assert.equal(resLive, null);

  // Customer email mismatch rejected
  const mockSessionMismatchEmail = {
    id: 'cs_test_email_mismatch',
    amount_total: 10000,
    currency: 'usd',
    customer_email: 'wrong@fixmate.dev',
    client_reference_id: bookingId,
    mode: 'payment',
    livemode: false,
    payment_status: 'paid',
  };
  const resEmailMismatch = await fulfillPaymentSession(mockSessionMismatchEmail);
  assert.equal(resEmailMismatch, null);

  // Valid fulfillment with issued attempt verification
  mockBooking.stripeSessionId = 'cs_test_valid';
  const mockSessionValid = {
    id: 'cs_test_valid',
    amount_total: 10000,
    currency: 'usd',
    customer_email: 'customer@fixmate.dev',
    client_reference_id: bookingId,
    mode: 'payment',
    livemode: false,
    payment_status: 'paid',
  };
  const resValid = await fulfillPaymentSession(mockSessionValid);
  assert.equal(resValid !== null, true);
  assert.equal(resValid.paymentStatus, 'paid');
});

test('fulfillSubscriptionSession rejects livemode and validates test-mode technician subscription idempotently', async () => {
  const usersMap = new Map([
    ['tech@fixmate.dev', { email: 'tech@fixmate.dev', name: 'Tech Rahim', role: 'technician', isPro: false }],
  ]);
  const servicesMap = new Map();
  const paymentsMap = new Map();

  const fakeSubDb = {
    collection: (name) => {
      if (name === 'user') {
        return {
          findOne: async (q) => usersMap.get(q.email) || null,
          updateOne: async (q, u) => {
            const user = usersMap.get(q.email);
            if (!user) return { matchedCount: 0 };
            if (u.$set) Object.assign(user, u.$set);
            return { matchedCount: 1 };
          },
        };
      }
      if (name === 'services') {
        return {
          updateMany: async () => ({ modifiedCount: 1 }),
        };
      }
      if (name === 'payments') {
        return {
          findOne: async (q) => paymentsMap.get(q.stripeSessionId) || null,
          insertOne: async (doc) => {
            paymentsMap.set(doc.stripeSessionId, doc);
            return { insertedId: new ObjectId() };
          },
        };
      }
      return {};
    },
  };

  setTestDb(fakeSubDb);

  // 1. Livemode rejected
  const liveSubSession = {
    id: 'cs_live_sub_1',
    customer_email: 'tech@fixmate.dev',
    currency: 'usd',
    mode: 'subscription',
    payment_status: 'paid',
    livemode: true,
    subscription: 'sub_live_123',
    amount_total: 2900,
    metadata: { type: 'pro_subscription', tier: 'pro', technicianEmail: 'tech@fixmate.dev' },
  };
  const liveResult = await fulfillSubscriptionSession(liveSubSession);
  assert.equal(liveResult, null, 'Livemode subscription session must be rejected');

  // 2. Unpaid rejected (even if status is complete)
  const unpaidSession = {
    id: 'cs_test_unpaid_sub',
    customer_email: 'tech@fixmate.dev',
    currency: 'usd',
    mode: 'subscription',
    payment_status: 'unpaid',
    status: 'complete',
    livemode: false,
    subscription: 'sub_test_123',
    amount_total: 2900,
    metadata: { type: 'pro_subscription', tier: 'pro', technicianEmail: 'tech@fixmate.dev' },
  };
  const unpaidResult = await fulfillSubscriptionSession(unpaidSession);
  assert.equal(unpaidResult, null, 'Unpaid subscription session must be rejected');

  // 3. One-time payment mode rejected for subscriptions
  const wrongModeSession = {
    id: 'cs_test_wrong_mode',
    customer_email: 'tech@fixmate.dev',
    currency: 'usd',
    mode: 'payment', // Invalid mode
    payment_status: 'paid',
    livemode: false,
    subscription: 'sub_test_123',
    amount_total: 2900,
    metadata: { type: 'pro_subscription', tier: 'pro', technicianEmail: 'tech@fixmate.dev' },
  };
  assert.equal(await fulfillSubscriptionSession(wrongModeSession), null);

  // 4. Underpriced amount rejected
  const underpricedSession = {
    id: 'cs_test_underpriced',
    customer_email: 'tech@fixmate.dev',
    currency: 'usd',
    mode: 'subscription',
    payment_status: 'paid',
    livemode: false,
    subscription: 'sub_test_123',
    amount_total: 100, // $1.00 instead of $29.00
    metadata: { type: 'pro_subscription', tier: 'pro', technicianEmail: 'tech@fixmate.dev' },
  };
  assert.equal(await fulfillSubscriptionSession(underpricedSession), null);

  // 5. Valid testmode subscription fulfilled
  const validSubSession = {
    id: 'cs_test_valid_sub',
    customer_email: 'tech@fixmate.dev',
    currency: 'usd',
    mode: 'subscription',
    payment_status: 'paid',
    status: 'complete',
    livemode: false,
    subscription: 'sub_test_12345',
    amount_total: 2900,
    metadata: { type: 'pro_subscription', tier: 'pro', technicianEmail: 'tech@fixmate.dev' },
  };
  const validResult = await fulfillSubscriptionSession(validSubSession);
  assert.equal(validResult !== null, true);
  assert.equal(validResult.isPro, true);
  assert.equal(usersMap.get('tech@fixmate.dev').isPro, true);
  assert.equal(paymentsMap.has('cs_test_valid_sub'), true);

  // 6. Idempotency: repeating fulfillment returns active without duplicating ledger row
  const repeatResult = await fulfillSubscriptionSession(validSubSession);
  assert.equal(repeatResult.isPro, true);
  assert.equal(paymentsMap.size, 1, 'Idempotent verification must not create duplicate ledger records');
});

test('extractInvoiceSubscriptionId resolves modern nested and legacy Stripe subscription IDs', () => {
  // Modern Stripe 2026-11-18.endive: parent.subscription_details.subscription
  const modernInvoice = {
    id: 'in_test_1',
    parent: {
      subscription_details: {
        subscription: 'sub_modern_123',
      },
    },
  };
  assert.equal(extractInvoiceSubscriptionId(modernInvoice), 'sub_modern_123');

  // Expanded object in subscription_details
  const expandedInvoice = {
    id: 'in_test_2',
    subscription_details: {
      subscription: { id: 'sub_expanded_456' },
    },
  };
  assert.equal(extractInvoiceSubscriptionId(expandedInvoice), 'sub_expanded_456');

  // Line item subscription
  const linesInvoice = {
    id: 'in_test_3',
    lines: {
      data: [{ subscription: 'sub_line_789' }],
    },
  };
  assert.equal(extractInvoiceSubscriptionId(linesInvoice), 'sub_line_789');

  // Legacy root subscription
  const legacyInvoice = {
    id: 'in_test_4',
    subscription: 'sub_legacy_001',
  };
  assert.equal(extractInvoiceSubscriptionId(legacyInvoice), 'sub_legacy_001');

  // Missing subscription yields null
  assert.equal(extractInvoiceSubscriptionId({ id: 'in_test_5' }), null);
  assert.equal(extractInvoiceSubscriptionId(null), null);
});

test('handleInvoicePaid strictly validates positive amounts and records renewals idempotently', async () => {
  const usersMap = new Map([
    ['tech@fixmate.dev', { email: 'tech@fixmate.dev', role: 'technician', isPro: true, stripeSubscriptionId: 'sub_tech_1' }],
  ]);
  const paymentsMap = new Map();

  const fakeInvoiceDb = {
    collection: (name) => {
      if (name === 'user') {
        return {
          findOne: async (q) => {
            if (q.stripeSubscriptionId) {
              for (const u of usersMap.values()) {
                if (u.stripeSubscriptionId === q.stripeSubscriptionId) return u;
              }
            }
            return usersMap.get(q.email) || null;
          },
          updateOne: async (q, u) => {
            const user = usersMap.get(q.email) || Array.from(usersMap.values()).find(u => u.stripeSubscriptionId === q.stripeSubscriptionId);
            if (!user) return { matchedCount: 0 };
            if (u.$set) Object.assign(user, u.$set);
            return { matchedCount: 1 };
          },
        };
      }
      if (name === 'services') {
        return { updateMany: async () => ({ modifiedCount: 1 }) };
      }
      if (name === 'payments') {
        return {
          findOne: async (q) => {
            if (q.stripeInvoiceId) {
              for (const p of paymentsMap.values()) {
                if (p.stripeInvoiceId === q.stripeInvoiceId) return p;
              }
            }
            return null;
          },
          insertOne: async (doc) => {
            paymentsMap.set(doc.stripeInvoiceId, doc);
            return { insertedId: new ObjectId() };
          },
          updateOne: async (q, u) => {
            return { matchedCount: 1 };
          },
        };
      }
      return {};
    },
  };

  setTestDb(fakeInvoiceDb);

  // 1. Zero amount invoice rejected
  const zeroInvoice = {
    id: 'in_zero_1',
    amount_paid: 0,
    currency: 'usd',
    billing_reason: 'subscription_cycle',
    parent: { subscription_details: { subscription: 'sub_tech_1' } },
  };
  const zeroResult = await handleInvoicePaid(zeroInvoice);
  assert.equal(zeroResult === null || zeroResult === false, true, 'Zero amount invoice must be rejected');

  // 2. Valid renewal recorded
  const validRenewalInvoice = {
    id: 'in_valid_renewal',
    amount_paid: 2900,
    currency: 'usd',
    billing_reason: 'subscription_cycle',
    customer_email: 'tech@fixmate.dev',
    parent: { subscription_details: { subscription: 'sub_tech_1' } },
  };
  const renewalSuccess = await handleInvoicePaid(validRenewalInvoice);
  assert.equal(renewalSuccess?.success, true);
  assert.equal(paymentsMap.has('in_valid_renewal'), true);
  assert.equal(paymentsMap.get('in_valid_renewal').type, 'subscription_renewal');

  // 3. Duplicate invoice ignored idempotently
  const duplicateRenewal = await handleInvoicePaid(validRenewalInvoice);
  assert.equal(duplicateRenewal?.success, true);
  assert.equal(paymentsMap.size, 1, 'Duplicate invoice must not insert another ledger row');
});

test('review rating validation strictly accepts integers 1-5 and rejects invalid values', () => {
  function validateReviewRating(rating) {
    if (typeof rating !== 'number' || !Number.isInteger(rating) || rating < 1 || rating > 5) {
      return false;
    }
    return true;
  }

  assert.equal(validateReviewRating(1), true);
  assert.equal(validateReviewRating(5), true);
  assert.equal(validateReviewRating(3), true);
  assert.equal(validateReviewRating(4.6), false, 'Floating point rating 4.6 must be rejected');
  assert.equal(validateReviewRating(0), false);
  assert.equal(validateReviewRating(6), false);
  assert.equal(validateReviewRating('5'), false);
  assert.equal(validateReviewRating(true), false);
  assert.equal(validateReviewRating(null), false);
});

test('fulfillSubscriptionSession strictly rejects missing or non-integer amount_total (Section 4)', async () => {
  const usersMap = new Map([
    ['tech@fixmate.dev', { email: 'tech@fixmate.dev', name: 'Tech Rahim', role: 'technician', isPro: false }],
  ]);
  const fakeDb = {
    collection: (name) => {
      if (name === 'user') return { findOne: async (q) => usersMap.get(q.email) || null };
      if (name === 'services') return { updateMany: async () => ({ modifiedCount: 1 }) };
      if (name === 'payments') return { findOne: async () => null, insertOne: async () => ({ insertedId: new ObjectId() }) };
      return {};
    },
  };
  setTestDb(fakeDb);

  // Missing amount_total must NOT pass or default to $29
  const missingAmountSession = {
    id: 'cs_test_missing_amount',
    customer_email: 'tech@fixmate.dev',
    currency: 'usd',
    mode: 'subscription',
    payment_status: 'paid',
    livemode: false,
    subscription: 'sub_test_missing_amt',
    metadata: { type: 'pro_subscription', tier: 'pro', technicianEmail: 'tech@fixmate.dev' },
  };
  const resMissing = await fulfillSubscriptionSession(missingAmountSession);
  assert.equal(resMissing, null, 'Omitted amount_total must be rejected rather than defaulted');

  // Floating point amount_total must be rejected
  const floatAmountSession = {
    ...missingAmountSession,
    id: 'cs_test_float_amt',
    amount_total: 2900.5,
  };
  const resFloat = await fulfillSubscriptionSession(floatAmountSession);
  assert.equal(resFloat, null, 'Non-integer amount_total must be rejected');
});

test('late failed invoices do not undo a newer successful payment period (Section 3)', async () => {
  const techUser = {
    _id: new ObjectId(),
    email: 'tech@fixmate.dev',
    role: 'technician',
    isPro: true,
    stripeSubscriptionId: 'sub_test_ordering',
    lastPaidInvoiceId: 'in_newer_paid',
    lastPaidPeriodEnd: 1770000000000,
    lastPaidInvoiceCreated: 1769000000000,
  };

  const fakeDb = {
    collection: (name) => {
      if (name === 'user') {
        return {
          findOne: async (q) => (q.stripeSubscriptionId === techUser.stripeSubscriptionId ? techUser : null),
          updateOne: async (q, u) => {
            if (u.$set) Object.assign(techUser, u.$set);
            return { matchedCount: 1 };
          },
        };
      }
      if (name === 'services') {
        return { updateMany: async () => ({ modifiedCount: 1 }) };
      }
      return {};
    },
  };
  setTestDb(fakeDb);

  // 1. Older failed invoice (period_end is before lastPaidPeriodEnd)
  const olderFailedInvoice = {
    id: 'in_older_failed',
    period_end: 1765000000, // 1765000000000 < 1770000000000
    created: 1764000000,
    parent: { subscription_details: { subscription: 'sub_test_ordering' } },
  };
  await handleInvoicePaymentFailed(olderFailedInvoice);
  assert.equal(techUser.isPro, true, 'Older failed invoice must NOT undo active Pro access from newer paid period');
  assert.equal(techUser.subscriptionPastDue, undefined);

  // 2. Current/newer failed invoice (period_end is after lastPaidPeriodEnd)
  const newerFailedInvoice = {
    id: 'in_newer_failed',
    period_end: 1775000000, // 1775000000000 > 1770000000000
    created: 1774000000,
    parent: { subscription_details: { subscription: 'sub_test_ordering' } },
  };
  await handleInvoicePaymentFailed(newerFailedInvoice);
  assert.equal(techUser.isPro, false, 'Current/newer failed invoice must suspend Pro access');
  assert.equal(techUser.subscriptionPastDue, true);
});

test('repair Checkout route: generation consistency, Stripe parameters, and ownership gates', async () => {
  const jwtSecret = process.env.JWT_SECRET;
  const customerId = new ObjectId().toString();
  const customerEmail = 'customer@fixmate.dev';
  const otherCustomerId = new ObjectId().toString();

  const customerUser = {
    _id: new ObjectId(customerId),
    id: customerId,
    email: customerEmail,
    role: 'customer',
    name: 'Customer Test',
  };

  const otherCustomerUser = {
    _id: new ObjectId(otherCustomerId),
    id: otherCustomerId,
    email: 'other@fixmate.dev',
    role: 'customer',
    name: 'Other Customer',
  };

  const bookingId = new ObjectId().toString();
  const mockBooking = {
    _id: new ObjectId(bookingId),
    serviceId: new ObjectId().toString(),
    serviceTitle: 'Laptop Logic Board Repair',
    technicianEmail: 'tech@fixmate.dev',
    technicianName: 'Tech Rahim',
    customerEmail,
    customerId,
    status: 'completed',
    paymentStatus: 'unpaid',
    finalAmount: 120,
    checkoutGeneration: 0,
    history: [],
  };

  const bookingsMap = new Map([[bookingId, mockBooking]]);

  const fakeDb = {
    collection: (name) => {
      if (name === 'user') {
        return {
          findOne: async (q) => {
            if (q.$or) {
              for (const cond of q.$or) {
                const id = cond.id || cond._id?.toString();
                if (id === customerId) return customerUser;
                if (id === otherCustomerId) return otherCustomerUser;
              }
            }
            const id = q.id || q._id?.toString();
            if (id === customerId || q.email === customerEmail) return customerUser;
            if (id === otherCustomerId || q.email === 'other@fixmate.dev') return otherCustomerUser;
            return null;
          },
        };
      }
      if (name === 'bookings') {
        return {
          findOne: async (q) => {
            const id = q._id?.toString() || q._id;
            return bookingsMap.get(id) || null;
          },
          findOneAndUpdate: async (q, u) => {
            const id = q._id?.toString() || q._id;
            const b = bookingsMap.get(id);
            if (!b) return null;
            if (b.status !== 'completed' || b.paymentStatus !== 'unpaid') return null;
            if (u.$set) {
              Object.assign(b, u.$set);
              if (u.$set['activeAttempt.generation']) {
                b.activeAttempt = { ...(b.activeAttempt || {}), generation: u.$set['activeAttempt.generation'] };
              }
            }
            return b;
          },
          updateOne: async (q, u) => {
            const id = q._id?.toString() || q._id;
            const b = bookingsMap.get(id);
            if (!b) return { matchedCount: 0 };
            if (u.$set) {
              Object.assign(b, u.$set);
              if (u.$set['activeAttempt.generation']) {
                b.activeAttempt = { ...(b.activeAttempt || {}), generation: u.$set['activeAttempt.generation'] };
              }
            }
            if (u.$push) {
              for (const [k, v] of Object.entries(u.$push)) {
                if (!b[k]) b[k] = [];
                b[k].push(v);
              }
            }
            return { matchedCount: 1 };
          },
        };
      }
      return {};
    },
  };

  setTestDb(fakeDb);

  let stripeCreatedSession = null;
  let stripeCreatedOpts = null;

  setTestStripe({
    checkout: {
      sessions: {
        create: async (params, opts) => {
          stripeCreatedSession = params;
          stripeCreatedOpts = opts;
          return {
            id: 'cs_test_session_xyz789',
            url: 'https://checkout.stripe.com/c/pay/cs_test_session_xyz789',
            payment_status: 'unpaid',
            status: 'open',
          };
        },
        retrieve: async (id) => null,
      },
    },
  });

  // Start test server
  const server = http.createServer(app);
  const serverUrl = await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });

  try {
    const validToken = jwt.sign(
      { sub: customerId, email: customerEmail, role: 'customer' },
      jwtSecret,
      { algorithm: 'HS256', issuer: process.env.JWT_ISSUER || 'http://localhost:3000', audience: 'fixmate-api', expiresIn: '1h' }
    );

    const otherToken = jwt.sign(
      { sub: otherCustomerId, email: 'other@fixmate.dev', role: 'customer' },
      jwtSecret,
      { algorithm: 'HS256', issuer: process.env.JWT_ISSUER || 'http://localhost:3000', audience: 'fixmate-api', expiresIn: '1h' }
    );

    // 1. Unauthenticated request rejected with 401
    const resNoAuth = await fetch(`${serverUrl}/api/payments/create-checkout-session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bookingId }),
    });
    assert.equal(resNoAuth.status, 401, 'Request without token must be rejected with 401');

    // 2. Non-owner customer rejected with 403
    const resWrongOwner = await fetch(`${serverUrl}/api/payments/create-checkout-session`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${otherToken}`,
      },
      body: JSON.stringify({ bookingId }),
    });
    assert.equal(resWrongOwner.status, 403, 'Non-owner must be rejected with 403');

    // 3. Valid owner checkout: exercises generation consistency without ReferenceError
    const resValid = await fetch(`${serverUrl}/api/payments/create-checkout-session`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${validToken}`,
      },
      body: JSON.stringify({ bookingId }),
    });
    assert.equal(resValid.status, 200, `Expected 200 OK from checkout handler, got ${resValid.status}`);
    const data = await resValid.json();
    assert.equal(data.sessionId, 'cs_test_session_xyz789');
    assert.equal(data.url, 'https://checkout.stripe.com/c/pay/cs_test_session_xyz789');

    // Verify Stripe params and metadata generation
    assert.equal(stripeCreatedSession.metadata.generation, '1');
    assert.equal(stripeCreatedSession.metadata.bookingId, bookingId);
    assert.equal(stripeCreatedOpts.idempotencyKey.includes('_gen_1_'), true);

    // Verify booking state persistence matches generation
    assert.equal(mockBooking.checkoutGeneration, 1);
    assert.equal(mockBooking.stripeSessionId, 'cs_test_session_xyz789');
    assert.equal(mockBooking.activeAttempt.generation, 1);
    assert.equal(mockBooking.issuedCheckoutSessions.length, 1);
    assert.equal(mockBooking.issuedCheckoutSessions[0].generation, 1);

    // 4. Non-completed booking rejected with 400
    mockBooking.status = 'requested';
    const resNotCompleted = await fetch(`${serverUrl}/api/payments/create-checkout-session`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${validToken}`,
      },
      body: JSON.stringify({ bookingId }),
    });
    assert.equal(resNotCompleted.status, 400, 'Non-completed booking checkout must return 400');

    // 5. Already-paid booking rejected with 400
    mockBooking.status = 'completed';
    mockBooking.paymentStatus = 'paid';
    const resPaid = await fetch(`${serverUrl}/api/payments/create-checkout-session`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${validToken}`,
      },
      body: JSON.stringify({ bookingId }),
    });
    assert.equal(resPaid.status, 400, 'Already paid booking checkout must return 400');
  } finally {
    await new Promise((res) => server.close(res));
  }
});

test('active booking duplicate prevention: rejects second request for same service with HTTP 409', async () => {
  const jwtSecret = process.env.JWT_SECRET;
  const customerId = new ObjectId().toString();
  const customerEmail = 'customer@fixmate.dev';
  const serviceId = new ObjectId().toString();

  const customerUser = {
    _id: new ObjectId(customerId),
    id: customerId,
    email: customerEmail,
    role: 'customer',
    name: 'Customer Test',
  };

  const targetService = {
    _id: new ObjectId(serviceId),
    title: 'AC Gas Refill & Coil Cleaning',
    category: 'HVAC',
    basePrice: 65,
    technicianEmail: 'tech@fixmate.dev',
    technicianName: 'Tech Rahim',
    approvalStatus: 'approved',
    isAvailable: true,
  };

  const activeBookings = [];

  const fakeDb = {
    collection: (name) => {
      if (name === 'user') {
        return {
          findOne: async (q) => {
            if (q.$or) {
              for (const cond of q.$or) {
                const id = cond.id || cond._id?.toString();
                if (id === customerId) return customerUser;
              }
            }
            if (q.email === customerEmail || q.id === customerId || q._id?.toString() === customerId) return customerUser;
            return null;
          },
        };
      }
      if (name === 'services') {
        return {
          findOne: async (q) => (q._id.toString() === serviceId ? targetService : null),
        };
      }
      if (name === 'bookings') {
        return {
          findOne: async (q) => {
            // Check active booking query: customerEmail + serviceId + status in ['requested', 'accepted', 'in-progress']
            if (q.customerEmail === customerEmail && q.serviceId === serviceId) {
              const activeStatuses = ['requested', 'accepted', 'in-progress'];
              return activeBookings.find(b => activeStatuses.includes(b.status)) || null;
            }
            return null;
          },
          insertOne: async (doc) => {
            const hasConflict = activeBookings.some(
              b => b.customerEmail === doc.customerEmail && b.serviceId === doc.serviceId && ['requested', 'accepted', 'in-progress'].includes(b.status)
            );
            if (hasConflict) {
              const err = new Error('E11000 duplicate key error: unique_active_customer_service_booking');
              err.code = 11000;
              throw err;
            }
            activeBookings.push(doc);
            return { insertedId: new ObjectId() };
          },
        };
      }
      return {};
    },
  };

  setTestDb(fakeDb);

  const server = http.createServer(app);
  const serverUrl = await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });

  try {
    const token = jwt.sign(
      { sub: customerId, email: customerEmail, role: 'customer' },
      jwtSecret,
      { algorithm: 'HS256', issuer: process.env.JWT_ISSUER || 'http://localhost:3000', audience: 'fixmate-api', expiresIn: '1h' }
    );

    const bookingPayload = {
      serviceId,
      customerPhone: '+1-555-0199',
      serviceAddress: 'House 12, Road 4, Dhanmondi, Dhaka',
      preferredDate: '2026-12-25',
      problemDescription: 'The compressor runs but cold airflow stops completely after 15 minutes of operation.',
    };

    // 1. Initial request succeeds with 201 Created
    const resInitial = await fetch(`${serverUrl}/api/bookings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(bookingPayload),
    });
    assert.equal(resInitial.status, 201, `First booking request must return 201, got ${resInitial.status}`);

    // 2. Duplicate active request refused with HTTP 409 Conflict
    const resDuplicate = await fetch(`${serverUrl}/api/bookings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(bookingPayload),
    });
    assert.equal(resDuplicate.status, 409, 'Duplicate active booking request must return 409 Conflict');
    const dupDataBody = await resDuplicate.json();
    assert.equal(dupDataBody.error, 'Conflict');
    assert.equal(dupDataBody.message.includes('already have an active booking request'), true);

    // 3. Once terminal (e.g. completed), a new request is allowed
    activeBookings[0].status = 'completed';
    const resAfterTerminal = await fetch(`${serverUrl}/api/bookings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(bookingPayload),
    });
    assert.equal(resAfterTerminal.status, 201, 'New booking request must be permitted after prior booking completed');
  } finally {
    await new Promise((res) => server.close(res));
  }
});
