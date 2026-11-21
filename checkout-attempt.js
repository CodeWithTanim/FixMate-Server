import { createHash, randomUUID } from 'node:crypto';

const REQUEST_VERSION = 2;

function stableJSON(value) {
  if (Array.isArray(value)) return `[${value.map(stableJSON).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().filter(key => value[key] !== undefined).map(key => `${JSON.stringify(key)}:${stableJSON(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function fingerprint(params) {
  return createHash('sha256').update(stableJSON(params)).digest('hex');
}

function requestKey(prefix, resourceId, generation, params) {
  const resource = createHash('sha256').update(resourceId).digest('hex').slice(0, 16);
  return `${prefix}_v${REQUEST_VERSION}_${resource}_gen_${generation}_${fingerprint(params).slice(0, 32)}`;
}

export function prepareCheckoutAttempt({ previous, generation = 0, prefix, resourceId, buildParams }) {
  const current = Math.max(Number(generation) || 0, Number(previous?.generation) || 0);
  if (
    previous?.status === 'creating' && previous.requestVersion === REQUEST_VERSION &&
    previous.attemptId && previous.params && previous.generation === current &&
    previous.key === requestKey(prefix, resourceId, current, previous.params)
  ) {
    return {
      attemptId: previous.attemptId, generation: current, key: previous.key,
      requestVersion: REQUEST_VERSION, params: structuredClone(previous.params),
    };
  }

  // Older attempts did not save their request body. They must not reuse a key
  // cached by Stripe before the Checkout parameter migration.
  const next = current + 1;
  const params = structuredClone(buildParams(next));
  return {
    attemptId: randomUUID(), generation: next,
    key: requestKey(prefix, resourceId, next, params),
    requestVersion: REQUEST_VERSION, params,
  };
}
