process.env.NODE_ENV = 'test';

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateMoneyAmount,
  parseAndValidateCalendarDate,
  getTodayCalendarDate,
  fulfillPaymentSession,
  setTestDb,
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
  assert.equal(validateMoneyAmount(0).valid, false);
  assert.equal(validateMoneyAmount(0.49).valid, false); // below $0.50 minimum
  assert.equal(validateMoneyAmount(100001).valid, false); // above cap
  assert.equal(validateMoneyAmount('50junk').valid, false);
  assert.equal(validateMoneyAmount('45.999').valid, false); // more than 2 decimal places
  assert.equal(validateMoneyAmount(null).valid, false);
  assert.equal(validateMoneyAmount(undefined).valid, false);
  assert.equal(validateMoneyAmount({}).valid, false);
});

test('parseAndValidateCalendarDate validates YYYY-MM-DD format and rejects impossible or past days in Asia/Dhaka', () => {
  const todayStr = getTodayCalendarDate('Asia/Dhaka');
  assert.match(todayStr, /^\d{4}-\d{2}-\d{2}$/);

  // Today in Dhaka is valid
  assert.equal(parseAndValidateCalendarDate(todayStr, 'Asia/Dhaka').valid, true);

  // Tomorrow is valid
  const tomorrow = new Date(Date.now() + 86400000);
  const tomorrowStr = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Dhaka',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(tomorrow);
  assert.equal(parseAndValidateCalendarDate(tomorrowStr, 'Asia/Dhaka').valid, true);

  // Yesterday is invalid
  const yesterday = new Date(Date.now() - 86400000);
  const yesterdayStr = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Dhaka',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(yesterday);
  assert.equal(parseAndValidateCalendarDate(yesterdayStr, 'Asia/Dhaka').valid, false);

  // Impossible dates
  assert.equal(parseAndValidateCalendarDate('2026-02-30', 'Asia/Dhaka').valid, false);
  assert.equal(parseAndValidateCalendarDate('2026-13-01', 'Asia/Dhaka').valid, false);
  assert.equal(parseAndValidateCalendarDate('not-a-date', 'Asia/Dhaka').valid, false);
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

  // Valid fulfillment
  const mockSessionValid = {
    id: 'cs_test_valid',
    amount_total: 10000,
    currency: 'usd',
    client_reference_id: bookingId,
    mode: 'payment',
    livemode: false,
    payment_status: 'paid',
  };
  const resValid = await fulfillPaymentSession(mockSessionValid);
  assert.equal(resValid !== null, true);
  assert.equal(resValid.paymentStatus, 'paid');
});
