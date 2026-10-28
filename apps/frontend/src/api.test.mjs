import test from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, API_BASE, get, post } from './api.mjs';

test('API base stays on loopback and includes the versioned prefix', () => {
  assert.match(API_BASE, /^http:\/\/(127\.0\.0\.1|localhost):\d+\/api\/v1$/);
});

test('typed client targets a versioned base and rejects HTTP 404', async () => {
  const original = globalThis.fetch;
  let url;
  globalThis.fetch = async (requestUrl) => {
    url = requestUrl;
    return { ok: false, status: 404, json: async () => ({ error: { message: 'API v1 route was not found' } }) };
  };
  try {
    await assert.rejects(get('/sessions'), (error) => error instanceof ApiError && error.status === 404 && error.message.includes('route'));
    assert.equal(url, `${API_BASE}/sessions`);
  } finally {
    globalThis.fetch = original;
  }
});

test('client sends JSON payloads and returns successful API data', async () => {
  const original = globalThis.fetch;
  let received;
  globalThis.fetch = async (_url, options) => {
    received = options;
    return { ok: true, status: 201, json: async () => ({ id: 'session-1', synthetic: true }) };
  };
  try {
    assert.deepEqual(await post('/sessions', {}), { id: 'session-1', synthetic: true });
    assert.equal(received.method, 'POST');
    assert.equal(received.headers['Content-Type'], 'application/json');
    assert.equal(received.body, '{}');
  } finally {
    globalThis.fetch = original;
  }
});
