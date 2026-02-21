// Confirm email endpoint: GET /confirm?token=...

import { verifyToken, createToken } from './lib/tokens.js';
import { buildWelcomeEmail } from './lib/email.js';

export async function onRequestGet({ request, env, waitUntil }) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token') || '';
  const secret = env.CONFIRM_SECRET || env.ADMIN_TOKEN || '';

  const email = await verifyToken(token, secret);
  if (!email) {
    return new Response('<h1>Invalid or expired confirmation link.</h1>', {
      status: 400,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
    });
  }

  try {
    const db = env.D1 || env.DB;
    if (!db) {
      return new Response('<h1>Database binding missing</h1>', { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // Guard: token is cryptographically valid but check current DB state to
    // prevent replay abuse (e.g. old confirmation link re-triggering welcome email).
    const row = await db.prepare(
      'SELECT confirmed, unsubscribed FROM waitlist WHERE email = ?'
    ).bind(email.toLowerCase()).first();

    if (!row) {
      return new Response('<h1>No signup found. Please subscribe again.</h1>', {
        status: 404,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
      });
    }

    const base = env.BASE_URL || `${url.protocol}//${url.host}`;

    if (row.confirmed && !row.unsubscribed) {
      // Already confirmed and active — redirect without re-sending welcome email.
      return Response.redirect(`${base}/confirmed`, 302);
    }

    await db.prepare(
      'UPDATE waitlist SET confirmed = 1, unsubscribed = 0 WHERE email = ?'
    ).bind(email.toLowerCase()).run();

    // Send welcome email after confirmation
    const shouldSend = String(env.SEND_WELCOME_EMAIL || 'true').toLowerCase() !== 'false';
    if (shouldSend && env.RESEND_API_KEY) {
      try {
        const welcomeToken = await createToken(email.toLowerCase(), secret, 60 * 60 * 24 * 30);
        const unsubscribeUrl = `${base}/unsubscribe?token=${encodeURIComponent(welcomeToken)}`;
        const { subject, html, text } = buildWelcomeEmail({ baseUrl: base, unsubscribeUrl, userEmail: email.toLowerCase() });
        const fromEmail = env.FROM_EMAIL || 'no-reply@yourdomain.com';
        const fromName = env.FROM_NAME || 'Your App';
        const p = fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.RESEND_API_KEY}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ from: `${fromName} <${fromEmail}>`, to: [email.toLowerCase()], subject, html, text })
        }).catch((err) => console.error('Welcome email error:', err));
        // Use waitUntil so the CF Workers runtime doesn't kill the fetch
        // before it completes (fire-and-forget is not guaranteed otherwise).
        if (typeof waitUntil === 'function') waitUntil(p);
      } catch (err) {
        console.error('Welcome email build error:', err);
      }
    }

    return Response.redirect(`${base}/confirmed`, 302);
  } catch (e) {
    return new Response('<h1>Confirmation failed. Please try again.</h1>', {
      status: 500,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
    });
  }
}
