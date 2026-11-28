const SITE_ORIGIN = "https://sjp-technologies.github.io";
const enc = new TextEncoder();
const corsHeaders = (request) => ({
  "Access-Control-Allow-Origin": request.headers.get("Origin") === SITE_ORIGIN ? SITE_ORIGIN : "null",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Vary": "Origin",
  "Content-Type": "application/json; charset=utf-8"
});
function json(data,status=200,request=null) { const headers=request?corsHeaders(request):{"Access-Control-Allow-Origin":"*","Content-Type":"application/json; charset=utf-8"}; return new Response(JSON.stringify(data),{status,headers}); }
function b64url(bytes) { let s=""; for(const b of bytes)s+=String.fromCharCode(b); return btoa(s).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_"); }

function unb64url(s) { s=s.replace(/-/g,"+").replace(/_/g,"/"); return Uint8Array.from(atob(s+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0)); }
async function hmac(secret,data) {
  const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC",key,enc.encode(data)));
}
async function issueToken(secret) {
  const payload=b64url(enc.encode(JSON.stringify({exp:Date.now()+8*60*60*1000,scope:"admin"})));
  return payload+"."+b64url(await hmac(secret,payload));
}
async function validToken(request,secret) {
  const header=request.headers.get("Authorization")||"";
  const token=header.startsWith("Bearer ")?header.slice(7):"";
  const parts=token.split(".");
  if(parts.length!==2)return false;
  try {
    const expected=await hmac(secret,parts[0]),actual=unb64url(parts[1]);
    if(expected.length!==actual.length)return false;
    let diff=0;for(let i=0;i<expected.length;i++)diff|=expected[i]^actual[i];
    if(diff!==0)return false;
    const payload=JSON.parse(new TextDecoder().decode(unb64url(parts[0])));
    return payload.scope==="admin"&&Number(payload.exp)>Date.now();
  } catch { return false; }
}
export default {
 async fetch(request,env) {
  const url=new URL(request.url);
  if(request.method==="OPTIONS")return new Response(null,{headers:corsHeaders(request)});
  if(url.pathname==="/health")return json({ok:true,service:"sjp-website-api"},200,request);
  if(url.pathname==="/admin/login"&&request.method==="POST"){
    if(request.headers.get("Origin")!==SITE_ORIGIN)return json({error:"Forbidden origin"},403,request);
    if(!env.ADMIN_PASSWORD)return json({error:"Admin password is not configured in Worker secrets"},503,request);
    let body;try{body=await request.json()}catch{return json({error:"Invalid JSON"},400,request)}
    const supplied=String(body.password||"");
    if(supplied.length<1||supplied.length>200||supplied!==env.ADMIN_PASSWORD)return json({error:"ভুল পাসওয়ার্ড"},401,request);
    return json({ok:true,token:await issueToken(env.ADMIN_PASSWORD),expiresIn:28800},200,request);
  }
  if(url.pathname==="/admin/stats"&&request.method==="GET"){
    if(request.headers.get("Origin")!==SITE_ORIGIN||!env.ADMIN_PASSWORD||!(await validToken(request,env.ADMIN_PASSWORD)))return json({error:"Unauthorized"},401,request);
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const response = await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/stats",request.url),{method:"GET"}));
    const headers = new Headers(response.headers);
    for (const [key,value] of Object.entries(corsHeaders(request))) headers.set(key,value);
    return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
  }
  if(!["/visit","/heartbeat","/stats"].includes(url.pathname))return json({error:"Not found"},404,request);
  const id=env.VISITOR_STORE.idFromName("global-visitor-store");
  return env.VISITOR_STORE.get(id).fetch(request);
 }
};


/* Durable Object that stores visitor counts. */
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
    const parts = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Dhaka", year: "numeric", month: "2-digit", day: "2-digit"
    }).formatToParts(new Date(now));
    const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
    const today = `${values.year}-${values.month}-${values.day}`;

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
