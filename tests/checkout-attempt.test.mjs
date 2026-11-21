import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareCheckoutAttempt } from '../checkout-attempt.js';

const options = {
  prefix: 'checkout', resourceId: 'booking-verification',
  buildParams: generation => ({ mode: 'payment', metadata: { generation: String(generation) }, line_items: [{ price_data: { unit_amount: 9900, currency: 'usd' }, quantity: 1 }] }),
};

test('legacy cached keys are replaced after the parameter migration', () => {
  const old = { status: 'creating', generation: 1, key: 'checkout_old_gen_1_9900', attemptId: 'old-attempt' };
  const attempt = prepareCheckoutAttempt({ ...options, previous: old, generation: 1 });
  assert.notEqual(attempt.key, old.key);
  assert.notEqual(attempt.attemptId, old.attemptId);
  assert.equal(attempt.generation, 2);
  assert.equal(attempt.params.metadata.generation, '2');
  assert.equal(attempt.params.payment_method_types, undefined);
});

test('a retry replays the saved payload and key instead of rebuilding changed parameters', () => {
  const first = prepareCheckoutAttempt(options);
  const previous = { ...first, status: 'creating' };
  const retry = prepareCheckoutAttempt({ ...options, previous, generation: first.generation, buildParams: () => { throw new Error('A retry must use its snapshot'); } });
  assert.equal(retry.key, first.key);
  assert.equal(retry.attemptId, first.attemptId);
  assert.deepEqual(retry.params, first.params);
  retry.params.metadata.generation = 'changed';
  assert.equal(previous.params.metadata.generation, '1');
});

test('expired attempts get a new generation and a new key', () => {
  const first = prepareCheckoutAttempt(options);
  const next = prepareCheckoutAttempt({ ...options, previous: { ...first, status: 'expired' }, generation: first.generation });
  assert.equal(next.generation, 2);
  assert.notEqual(next.key, first.key);
});

test('equivalent concurrent requests have the same Stripe key regardless of property order', () => {
  const first = prepareCheckoutAttempt(options);
  const reordered = prepareCheckoutAttempt({ ...options, buildParams: generation => ({ line_items: [{ quantity: 1, price_data: { currency: 'usd', unit_amount: 9900 } }], metadata: { generation: String(generation) }, mode: 'payment' }) });
  assert.equal(first.key, reordered.key);
  assert.notEqual(first.attemptId, reordered.attemptId);
});

test('an invalid stored snapshot cannot poison a later attempt with its old key', () => {
  const first = prepareCheckoutAttempt(options);
  const previous = { ...first, status: 'creating', params: { ...first.params, success_url: 'https://changed.example' } };
  const next = prepareCheckoutAttempt({ ...options, previous, generation: first.generation });
  assert.equal(next.generation, 2);
  assert.notEqual(next.key, previous.key);
});

test('subscription keys use the same retry rules without exposing emails', () => {
  const opts = { prefix: 'pro_sub', resourceId: 'private@example.com', buildParams: generation => ({ mode: 'subscription', metadata: { generation: String(generation) } }) };
  const first = prepareCheckoutAttempt(opts);
  const retry = prepareCheckoutAttempt({ ...opts, previous: { ...first, status: 'creating' }, generation: first.generation });
  assert.equal(retry.key, first.key);
  assert.ok(!first.key.includes('@'));
});
