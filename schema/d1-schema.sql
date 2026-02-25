-- AutoMail Database Schema for Cloudflare D1
-- Run with: npm run db:migrate

CREATE TABLE IF NOT EXISTS waitlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  source TEXT DEFAULT 'website',
  -- Email digest frequency preference: 'daily' | 'weekly' | 'monthly'
  frequency TEXT DEFAULT 'weekly' CHECK (frequency IN ('daily', 'weekly', 'monthly')),
  created_at TEXT NOT NULL,
  confirmed BOOLEAN DEFAULT 0,
  unsubscribed BOOLEAN DEFAULT 0,
  metadata TEXT -- JSON field for extra data (optional)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_waitlist_email ON waitlist(email);
CREATE INDEX IF NOT EXISTS idx_waitlist_created ON waitlist(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waitlist_confirmed ON waitlist(confirmed);
CREATE INDEX IF NOT EXISTS idx_waitlist_unsubscribed ON waitlist(unsubscribed);

-- Stats view for quick analytics
CREATE VIEW IF NOT EXISTS waitlist_stats AS
SELECT
  COUNT(*) as total_signups,
  SUM(CASE WHEN confirmed = 1 THEN 1 ELSE 0 END) as confirmed_count,
  SUM(CASE WHEN unsubscribed = 1 THEN 1 ELSE 0 END) as unsubscribed_count,
  DATE(MIN(created_at)) as first_signup,
  DATE(MAX(created_at)) as last_signup
FROM waitlist;

-- Rate limiting table — used by functions/lib/rateLimit.js
-- Stores one row per signup attempt; old rows are cheap to leave in place
-- (D1 is append-optimised) but you can prune them periodically if desired.
CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  attempted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_time ON rate_limits(ip, attempted_at DESC);
