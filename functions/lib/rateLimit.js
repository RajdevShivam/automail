// IP-based rate limiting stored in Cloudflare D1
// Returns true if the request is allowed, false if it should be blocked.
//
// Requires the rate_limits table — see schema/d1-schema.sql.
// Configure RATE_LIMIT_MAX and RATE_LIMIT_WINDOW_SECONDS in your environment
// or accept the defaults (5 requests per hour).

const DEFAULT_WINDOW_SECONDS = 3600; // 1 hour
const DEFAULT_MAX_REQUESTS = 5;

export async function checkRateLimit(db, ip, opts = {}) {
  if (!db || !ip || ip === 'unknown') return true; // fail open if no DB or IP

  const window = opts.windowSeconds ?? DEFAULT_WINDOW_SECONDS;
  const max = opts.maxRequests ?? DEFAULT_MAX_REQUESTS;
  const windowStart = new Date(Date.now() - window * 1000).toISOString();

  try {
    const { results } = await db.prepare(
      'SELECT COUNT(*) as cnt FROM rate_limits WHERE ip = ? AND attempted_at > ?'
    ).bind(ip, windowStart).all();

    const count = results[0]?.cnt ?? 0;
    if (count >= max) return false;

    // Record this attempt
    await db.prepare(
      'INSERT INTO rate_limits (ip, attempted_at) VALUES (?, ?)'
    ).bind(ip, new Date().toISOString()).run();

    // Lazy cleanup: prune rows older than 1 hour (fire-and-forget)
    db.prepare("DELETE FROM rate_limits WHERE attempted_at < datetime('now', '-1 hour')").run().catch(() => {});

    return true;
  } catch {
    return true; // fail open on unexpected DB error
  }
}
