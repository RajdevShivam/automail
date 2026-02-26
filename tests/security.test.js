/**
 * AutoMail security-fix tests
 *
 * Run with:  node --test tests/security.test.js
 *
 * Covers:
 *  1. Token fix — dotted emails round-trip correctly through createToken/verifyToken
 *  2. Token fix — plain emails still work after the fix
 *  3. Token fix — expired tokens return null
 *  4. Token fix — tampered signature returns null
 *  5. Honeypot — bot request (website field set) gets silent 200
 *  6. Honeypot — legitimate request (website field absent) is not blocked
 *  7. Rate limiting — allows up to MAX_REQUESTS in window
 *  8. Rate limiting — blocks on MAX_REQUESTS + 1
 *  9. Rate limiting — fails open when db is null
 * 10. Confirm guard — already-confirmed email redirects without re-sending welcome
 * 11. Confirm guard — unconfirmed email is confirmed and redirects
 * 12. Confirm guard — email not in DB returns 404
 * 13. Unsubscribe guard — already-unsubscribed returns graceful 200
 * 14. Unsubscribe guard — active subscriber is unsubscribed
 * 15. Unsubscribe XSS — email is HTML-escaped in response body
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

// ---------------------------------------------------------------------------
// Shim Web Crypto for Node (available natively in Node 18+, just ensure it's
// on globalThis so the modules can access it without importing).
// ---------------------------------------------------------------------------
if (!globalThis.crypto) {
  const { webcrypto } = await import('node:crypto');
  globalThis.crypto = webcrypto;
}
if (!globalThis.atob) {
  globalThis.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');
  globalThis.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
}

// ---------------------------------------------------------------------------
// Helpers — minimal in-memory D1 stub
// ---------------------------------------------------------------------------

function makeDb(rows = {}) {
  // rows: { [email]: { confirmed, unsubscribed } }
  const store = { ...rows };
  const rateLimits = [];

  return {
    prepare(sql) {
      // first() called without bind() — used for COUNT(*) queries with no params
      const unboundFirst = async () => {
        if (sql.includes('COUNT(*)')) {
          return { total: Object.keys(store).length };
        }
        return null;
      };
      return {
        first: unboundFirst,
        bind(...args) {
          return {
            async first() {
              if (sql.includes('rate_limits')) {
                const [ip, windowStart] = args;
                const cnt = rateLimits.filter(
                  (r) => r.ip === ip && r.attempted_at > windowStart
                ).length;
                return { cnt };
              }
              if (sql.includes('COUNT(*)')) {
                return { total: Object.keys(store).length };
              }
              const email = args[0];
              return store[email] ?? null;
            },
            async run() {
              if (sql.includes('DELETE FROM rate_limits')) {
                // Prune old entries from mock (no-op is fine for tests)
                return;
              }
              if (sql.includes('INSERT INTO rate_limits')) {
                // args for the atomic INSERT...SELECT: [ip, now, ip, windowStart, max]
                const [ip, attempted_at, , windowStart, max] = args;
                const cnt = rateLimits.filter(
                  (r) => r.ip === ip && r.attempted_at > windowStart
                ).length;
                if (cnt >= max) return { meta: { changes: 0 } };
                rateLimits.push({ ip, attempted_at });
                return { meta: { changes: 1 } };
              }
              if (sql.includes('INSERT INTO waitlist')) {
                // args: email, source, frequency, created_at, confirmed
                const [email, , , , confirmed] = args;
                store[email] = { confirmed, unsubscribed: 0 };
                return;
              }
              if (sql.includes('UPDATE waitlist SET confirmed')) {
                const email = args[0];
                if (store[email]) {
                  store[email].confirmed = 1;
                  store[email].unsubscribed = 0;
                }
                return;
              }
              if (sql.includes('UPDATE waitlist SET unsubscribed = 0')) {
                // Re-subscribe: args are [confirmedFlag, created_at, frequency, email]
                const [confirmed, , frequency, email] = args;
                if (store[email]) { store[email].unsubscribed = 0; store[email].confirmed = confirmed; store[email].frequency = frequency; }
                return;
              }
              if (sql.includes('UPDATE waitlist SET unsubscribed')) {
                // Unsubscribe: args are [email]
                const email = args[0];
                if (store[email]) store[email].unsubscribed = 1;
                return;
              }
            },
            async all() {
              if (sql.includes('rate_limits')) {
                const [ip, windowStart] = args;
                const cnt = rateLimits.filter(
                  (r) => r.ip === ip && r.attempted_at > windowStart
                ).length;
                return { results: [{ cnt }] };
              }
              return { results: [] };
            },
          };
        },
      };
    },
    _store: store,
    _rateLimits: rateLimits,
  };
}

function makeRequest(url, opts = {}) {
  return new Request(url, opts);
}

const SECRET = 'test-secret-key';

// ---------------------------------------------------------------------------
// 1–4  Token round-trip tests
// ---------------------------------------------------------------------------

const { createToken, verifyToken } = await import('../functions/lib/tokens.js');

test('dotted email round-trips through createToken/verifyToken', async () => {
  const email = 'first.last@sub.domain.com';
  const token = await createToken(email, SECRET);
  const result = await verifyToken(token, SECRET);
  assert.equal(result, email);
});

test('plain email round-trips through createToken/verifyToken', async () => {
  const email = 'hello@example.com';
  const token = await createToken(email, SECRET);
  const result = await verifyToken(token, SECRET);
  assert.equal(result, email);
});

test('expired token returns null', async () => {
  const email = 'user@example.com';
  const token = await createToken(email, SECRET, -1); // already expired
  const result = await verifyToken(token, SECRET);
  assert.equal(result, null);
});

test('tampered token signature returns null', async () => {
  const email = 'user@example.com';
  const token = await createToken(email, SECRET);
  const tampered = token.slice(0, -4) + 'aaaa';
  const result = await verifyToken(tampered, SECRET);
  assert.equal(result, null);
});

// ---------------------------------------------------------------------------
// 5–6  Honeypot tests (testing signup.js handler directly)
// ---------------------------------------------------------------------------

const { onRequestPost: signupHandler } = await import('../functions/api/signup.js');

function makeSignupEnv(overrides = {}) {
  return {
    D1: makeDb(),
    DOUBLE_OPT_IN: 'false',
    ...overrides,
  };
}

test('honeypot: bot request (website field set) gets silent 200', async () => {
  const env = makeSignupEnv();
  const req = makeRequest('https://example.com/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '1.2.3.4' },
    body: JSON.stringify({ email: 'bot@evil.com', website: 'http://spam.com' }),
  });
  const res = await signupHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.success, true);
  // Verify nothing was written to DB
  assert.equal(env.D1._store['bot@evil.com'], undefined);
});

test('honeypot: legitimate request (no website field) proceeds normally', async () => {
  const env = makeSignupEnv();
  const req = makeRequest('https://example.com/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '5.6.7.8' },
    body: JSON.stringify({ email: 'real@user.com' }),
  });
  const res = await signupHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.success, true);
});

// ---------------------------------------------------------------------------
// 7–9  Rate limiting tests
// ---------------------------------------------------------------------------

const { checkRateLimit } = await import('../functions/lib/rateLimit.js');

test('rate limiter: allows up to MAX_REQUESTS (5) within window', async () => {
  const db = makeDb();
  for (let i = 0; i < 5; i++) {
    const allowed = await checkRateLimit(db, '10.0.0.1', { maxRequests: 5, windowSeconds: 3600 });
    assert.equal(allowed, true, `Request ${i + 1} should be allowed`);
  }
});

test('rate limiter: blocks on the 6th request within window', async () => {
  const db = makeDb();
  for (let i = 0; i < 5; i++) {
    await checkRateLimit(db, '10.0.0.2', { maxRequests: 5, windowSeconds: 3600 });
  }
  const blocked = await checkRateLimit(db, '10.0.0.2', { maxRequests: 5, windowSeconds: 3600 });
  assert.equal(blocked, false);
});

test('rate limiter: fails open when db is null', async () => {
  const allowed = await checkRateLimit(null, '10.0.0.3');
  assert.equal(allowed, true);
});

// ---------------------------------------------------------------------------
// 10–12  Confirm guard tests
// ---------------------------------------------------------------------------

const { onRequestGet: confirmHandler } = await import('../functions/confirm.js');

function makeConfirmEnv(rows, overrides = {}) {
  return {
    D1: makeDb(rows),
    CONFIRM_SECRET: SECRET,
    SEND_WELCOME_EMAIL: 'false', // disable actual email sending in tests
    BASE_URL: 'https://example.com',
    ...overrides,
  };
}

test('confirm guard: already-confirmed email redirects without error', async () => {
  const email = 'confirmed@example.com';
  const token = await createToken(email, SECRET);
  const env = makeConfirmEnv({ [email]: { confirmed: 1, unsubscribed: 0 } });
  const req = makeRequest(`https://example.com/confirm?token=${encodeURIComponent(token)}`);
  const res = await confirmHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('Location'), 'https://example.com/confirmed');
});

test('confirm guard: unconfirmed email gets confirmed and redirects', async () => {
  const email = 'pending@example.com';
  const token = await createToken(email, SECRET);
  const env = makeConfirmEnv({ [email]: { confirmed: 0, unsubscribed: 0 } });
  const req = makeRequest(`https://example.com/confirm?token=${encodeURIComponent(token)}`);
  const res = await confirmHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(res.status, 302);
  assert.equal(env.D1._store[email].confirmed, 1);
});

test('confirm guard: email not in DB returns 404', async () => {
  const email = 'ghost@example.com';
  const token = await createToken(email, SECRET);
  const env = makeConfirmEnv({}); // empty DB
  const req = makeRequest(`https://example.com/confirm?token=${encodeURIComponent(token)}`);
  const res = await confirmHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(res.status, 404);
});

// ---------------------------------------------------------------------------
// 13–15  Unsubscribe guard + XSS tests
// ---------------------------------------------------------------------------

const { onRequestGet: unsubscribeHandler } = await import('../functions/unsubscribe.js');

function makeUnsubEnv(rows, overrides = {}) {
  return {
    D1: makeDb(rows),
    CONFIRM_SECRET: SECRET,
    ...overrides,
  };
}

test('unsubscribe guard: already-unsubscribed returns graceful 200', async () => {
  const email = 'gone@example.com';
  const token = await createToken(email, SECRET);
  const env = makeUnsubEnv({ [email]: { confirmed: 1, unsubscribed: 1 } });
  const req = makeRequest(`https://example.com/unsubscribe?token=${encodeURIComponent(token)}`);
  const res = await unsubscribeHandler({ request: req, env });
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.ok(text.includes('Already unsubscribed'));
});

test('unsubscribe guard: active subscriber is unsubscribed', async () => {
  const email = 'active@example.com';
  const token = await createToken(email, SECRET);
  const env = makeUnsubEnv({ [email]: { confirmed: 1, unsubscribed: 0 } });
  const req = makeRequest(`https://example.com/unsubscribe?token=${encodeURIComponent(token)}`);
  const res = await unsubscribeHandler({ request: req, env });
  assert.equal(res.status, 200);
  assert.equal(env.D1._store[email].unsubscribed, 1);
  const text = await res.text();
  assert.ok(text.includes("You've been unsubscribed"));
});

test('unsubscribe XSS: email is HTML-escaped in response body', async () => {
  // This test verifies that even if a crafted email somehow passed validation,
  // it would be safely escaped before being reflected into HTML.
  // We inject a crafted email with HTML metacharacters directly into the mock store,
  // bypassing normal email validation, to directly test the escaping logic.
  const email = 'user+tag@example.com'; // normal email for token creation
  const craftedEmail = '<img onerror=x>@example.com'; // crafted email with HTML chars
  const token = await createToken(email, SECRET);
  const env = makeUnsubEnv({ [craftedEmail]: { confirmed: 1, unsubscribed: 0 } });

  // Manually verify the token to get the original email, then test with crafted email
  // by directly querying the mock store with the crafted email
  const req = makeRequest(`https://example.com/unsubscribe?token=${encodeURIComponent(token)}`);

  // Since we can't easily bypass token verification, we'll test by making the handler
  // think the email in the token is the crafted one. We do this by modifying the
  // verifyToken behavior through env. However, simpler: just directly test that
  // if an email with HTML chars made it through, it would be escaped.
  // We'll inject into the store with a safe token for a different email, then
  // manually check the escaping would work by examining unsubscribe.js behavior.

  // Better approach: inject a payload where the email contains HTML metacharacters
  // and verify the response escapes them properly.
  const xssEmail = '"onload=alert(1)"@example.com';
  const xssToken = await createToken(xssEmail, SECRET);
  const xssEnv = makeUnsubEnv({ [xssEmail]: { confirmed: 1, unsubscribed: 1 } }); // already unsubscribed
  const xssReq = makeRequest(`https://example.com/unsubscribe?token=${encodeURIComponent(xssToken)}`);
  const xssRes = await unsubscribeHandler({ request: xssReq, env: xssEnv });
  const xssText = await xssRes.text();

  // Verify HTML metacharacters are escaped, not rendered as HTML
  assert.ok(xssText.includes('&quot;onload=alert(1)&quot;'), 'Double quotes should be escaped as &quot;');
  assert.ok(!xssText.includes('"onload=alert(1)"'), 'Raw attribute syntax should not appear');
  assert.ok(!xssText.includes('<script'), 'No unescaped script tags');
});

// ---------------------------------------------------------------------------
// 16–17  Signup input validation
// ---------------------------------------------------------------------------

test('signup: malformed JSON body returns 400', async () => {
  const env = makeSignupEnv();
  const req = makeRequest('https://example.com/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '1.2.3.4' },
    body: 'not valid json {{{',
  });
  const res = await signupHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.success, false);
});

test('signup: invalid email address returns 400', async () => {
  const env = makeSignupEnv();
  const req = makeRequest('https://example.com/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '1.2.3.4' },
    body: JSON.stringify({ email: 'not-an-email' }),
  });
  const res = await signupHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.success, false);
  assert.equal(body.error, 'Invalid email address');
});

// ---------------------------------------------------------------------------
// 18–20  Re-subscribe flow
// ---------------------------------------------------------------------------

test('signup: unsubscribed user can re-subscribe and is not treated as duplicate', async () => {
  const env = makeSignupEnv({
    D1: makeDb({ 'returning@example.com': { confirmed: 1, unsubscribed: 1 } }),
  });
  const req = makeRequest('https://example.com/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '9.9.9.9' },
    body: JSON.stringify({ email: 'returning@example.com' }),
  });
  const res = await signupHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.success, true);
  // unsubscribed flag must be cleared
  assert.equal(env.D1._store['returning@example.com'].unsubscribed, 0);
});

test('signup: re-subscribed user gets confirmed=1 when DOUBLE_OPT_IN is false', async () => {
  const env = makeSignupEnv({
    D1: makeDb({ 'returning@example.com': { confirmed: 1, unsubscribed: 1 } }),
    DOUBLE_OPT_IN: 'false',
  });
  const req = makeRequest('https://example.com/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '9.9.9.9' },
    body: JSON.stringify({ email: 'returning@example.com' }),
  });
  await signupHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(env.D1._store['returning@example.com'].confirmed, 1);
  assert.equal(env.D1._store['returning@example.com'].unsubscribed, 0);
});

test('signup: active subscriber is told they are already on the waitlist', async () => {
  const env = makeSignupEnv({
    D1: makeDb({ 'active@example.com': { confirmed: 1, unsubscribed: 0 } }),
  });
  const req = makeRequest('https://example.com/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '9.9.9.9' },
    body: JSON.stringify({ email: 'active@example.com' }),
  });
  const res = await signupHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.success, true);
  assert.equal(body.message, 'You are already on the waitlist!');
  // DB must be unchanged — no extra rate-limit slot consumed
  assert.equal(env.D1._rateLimits.length, 0);
});

// ---------------------------------------------------------------------------
// 21  Confirm guard: unsubscribed user cannot be re-subscribed via old link
// ---------------------------------------------------------------------------

test('confirm guard: previously-unsubscribed user gets 200 (not re-subscribed)', async () => {
  const email = 'unsub@example.com';
  const token = await createToken(email, SECRET);
  const env = makeConfirmEnv({ [email]: { confirmed: 1, unsubscribed: 1 } });
  const req = makeRequest(`https://example.com/confirm?token=${encodeURIComponent(token)}`);
  const res = await confirmHandler({ request: req, env, waitUntil: () => {} });
  assert.equal(res.status, 200);
  // Must NOT have cleared unsubscribed flag
  assert.equal(env.D1._store[email].unsubscribed, 1);
  const text = await res.text();
  assert.ok(text.toLowerCase().includes('unsubscribed'));
});
