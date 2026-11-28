const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json; charset=utf-8"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: corsHeaders });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
    if (url.pathname === "/health") return json({ ok: true, service: "sjp-website-api" });
    if (!["/visit", "/heartbeat", "/stats"].includes(url.pathname)) return json({ error: "Not found" }, 404);
    const id = env.VISITOR_STORE.idFromName("global-visitor-store");
    return env.VISITOR_STORE.get(id).fetch(request);
  }
};

export class VisitorStore {
  constructor(ctx) {
    this.ctx = ctx;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS visitors (
        visitor_id TEXT PRIMARY KEY,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
      )
    `);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS daily_visits (
        visitor_id TEXT NOT NULL,
        visit_day TEXT NOT NULL,
        PRIMARY KEY (visitor_id, visit_day)
      )
    `);
  }

  async fetch(request) {
    const url = new URL(request.url);
    const now = Date.now();
    const dateParts = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Dhaka", year: "numeric", month: "2-digit", day: "2-digit"
    }).formatToParts(new Date(now));
    const dateValue = Object.fromEntries(dateParts.map(part => [part.type, part.value]));
    const today = `${dateValue.year}-${dateValue.month}-${dateValue.day}`;

    if (url.pathname === "/visit" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
      const visitorId = String(body.visitorId || "").slice(0, 100);
      if (!/^[a-zA-Z0-9_-]{8,100}$/.test(visitorId)) return json({ error: "Valid visitorId required" }, 400);
      const found = this.ctx.storage.sql.exec(
        "SELECT visitor_id FROM visitors WHERE visitor_id = ?", visitorId
      ).toArray().length > 0;
      this.ctx.storage.sql.exec(`
        INSERT INTO visitors (visitor_id, first_seen, last_seen) VALUES (?, ?, ?)
        ON CONFLICT(visitor_id) DO UPDATE SET last_seen = excluded.last_seen
      `, visitorId, now, now);
      this.ctx.storage.sql.exec(
        "INSERT OR IGNORE INTO daily_visits (visitor_id, visit_day) VALUES (?, ?)", visitorId, today
      );
      return json({ ok: true, newVisitor: !found });
    }

    if (url.pathname === "/heartbeat" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
      const visitorId = String(body.visitorId || "").slice(0, 100);
      if (!/^[a-zA-Z0-9_-]{8,100}$/.test(visitorId)) return json({ error: "Valid visitorId required" }, 400);
      this.ctx.storage.sql.exec("UPDATE visitors SET last_seen = ? WHERE visitor_id = ?", now, visitorId);
      return json({ ok: true });
    }

    if (url.pathname === "/stats" && request.method === "GET") {
      const total = this.ctx.storage.sql.exec("SELECT COUNT(*) AS total FROM visitors").one().total;
      const online = this.ctx.storage.sql.exec(
        "SELECT COUNT(*) AS total FROM visitors WHERE last_seen >= ?", now - 90000
      ).one().total;
      const todayCount = this.ctx.storage.sql.exec(
        "SELECT COUNT(*) AS total FROM daily_visits WHERE visit_day = ?", today
      ).one().total;
      return json({
        totalVisitors: total,
        todayVisitors: todayCount,
        currentlyOnline: online,
        onlineWindowSeconds: 90,
        timezone: "Asia/Dhaka"
      });
    }
    return json({ error: "Not found" }, 404);
  }
}
