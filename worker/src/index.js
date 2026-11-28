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
let ga4TokenCache = { token: "", expiresAt: 0 };
function pemBytes(pem) {
  const clean = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
  return Uint8Array.from(atob(clean), ch => ch.charCodeAt(0));
}
function b64urlText(value) {
  return b64url(enc.encode(value));
}
async function getGa4AccessToken(serviceAccount) {
  if (ga4TokenCache.token && ga4TokenCache.expiresAt > Date.now() + 60000) return ga4TokenCache.token;
  const header = b64urlText(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const claims = b64urlText(JSON.stringify({ iss: serviceAccount.client_email, scope: "https://www.googleapis.com/auth/analytics.readonly", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const unsigned = header + "." + claims;
  const key = await crypto.subtle.importKey("pkcs8", pemBytes(serviceAccount.private_key), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(unsigned)));
  const assertion = unsigned + "." + b64url(signature);
  const response = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }) });
  const data = await response.json();
  if (!response.ok || !data.access_token) throw new Error("GA4 OAuth failed: " + (data.error_description || data.error || response.status));
  ga4TokenCache = { token: data.access_token, expiresAt: Date.now() + Number(data.expires_in || 3600) * 1000 };
  return data.access_token;
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
    const auditId=env.VISITOR_STORE.idFromName("global-visitor-store");
    await env.VISITOR_STORE.get(auditId).fetch(new Request(new URL("/audit-event",request.url),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"LOGIN",config_key:"admin_session",summary:"Owner admin login successful",actor:"owner"})}));
    return json({ok:true,token:await issueToken(env.ADMIN_PASSWORD),expiresIn:28800},200,request);
  }
  if(url.pathname==="/admin/audit-event"&&request.method==="POST"){
    if(request.headers.get("Origin")!==SITE_ORIGIN||!env.ADMIN_PASSWORD||!(await validToken(request,env.ADMIN_PASSWORD)))return json({error:"Unauthorized"},401,request);
    let body;try{body=await request.json()}catch{return json({error:"Invalid JSON"},400,request)}
    const allowed=["SYSTEM_DIAGNOSTICS","ADMIN_LOGOUT","APP_CONSOLE_OPEN"];
    if(!allowed.includes(String(body.action||"")))return json({error:"Unsupported audit action"},400,request);
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const response=await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/audit-event",request.url),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:body.action,config_key:String(body.config_key||"admin").slice(0,120),summary:String(body.summary||body.action).slice(0,500),actor:"owner"})}));
    const headers=new Headers(response.headers);for(const [key,value] of Object.entries(corsHeaders(request)))headers.set(key,value);
    return new Response(response.body,{status:response.status,headers});
  }
  if(url.pathname==="/admin/ga4-report"&&request.method==="POST"){
    if(request.headers.get("Origin")!==SITE_ORIGIN||!env.ADMIN_PASSWORD||!(await validToken(request,env.ADMIN_PASSWORD)))return json({error:"Unauthorized"},401,request);
    if(!env.GA4_PROPERTY_ID||!env.GA4_SERVICE_ACCOUNT_JSON)return json({error:"GA4_PROPERTY_ID এবং GA4_SERVICE_ACCOUNT_JSON Worker secrets-এ সেট করতে হবে"},503,request);
    let body;try{body=await request.json()}catch{return json({error:"Invalid JSON"},400,request)}
    const startDate=String(body.startDate||"7daysAgo"),endDate=String(body.endDate||"today");
    if(!/^(\d{4}-\d{2}-\d{2}|\d+daysAgo|today|yesterday)$/.test(startDate)||!/^(\d{4}-\d{2}-\d{2}|\d+daysAgo|today|yesterday)$/.test(endDate))return json({error:"Invalid date range"},400,request);
    try{
      const account=JSON.parse(env.GA4_SERVICE_ACCOUNT_JSON);
      const token=await getGa4AccessToken(account);
      const response=await fetch("https://analyticsdata.googleapis.com/v1beta/properties/"+encodeURIComponent(env.GA4_PROPERTY_ID)+":runReport",{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({dateRanges:[{startDate,endDate}],dimensions:[{name:"date"},{name:"pagePath"}],metrics:[{name:"activeUsers"},{name:"sessions"},{name:"screenPageViews"},{name:"engagementRate"}],limit:10000})});
      const data=await response.json();
      if(!response.ok)return json({error:"GA4 API error",details:data.error?.message||response.status},502,request);
      const auditId=env.VISITOR_STORE.idFromName("global-visitor-store");
      await env.VISITOR_STORE.get(auditId).fetch(new Request(new URL("/audit-event",request.url),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"GA4_REPORT",config_key:"analytics",summary:"GA4 report requested: "+startDate+" to "+endDate,actor:"owner"})}));
      return json({ok:true,propertyId:env.GA4_PROPERTY_ID,rows:data.rows||[],totals:data.totals||[],rowCount:data.rowCount||0,dimensionHeaders:data.dimensionHeaders||[],metricHeaders:data.metricHeaders||[]},200,request);
    }catch(e){return json({error:"GA4 report failed",details:String(e.message||e)},502,request)}
  }
  if(url.pathname==="/admin/stats"&&request.method==="GET"){
    if(request.headers.get("Origin")!==SITE_ORIGIN||!env.ADMIN_PASSWORD||!(await validToken(request,env.ADMIN_PASSWORD)))return json({error:"Unauthorized"},401,request);
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const response = await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/stats",request.url),{method:"GET"}));
    const headers = new Headers(response.headers);
    for (const [key,value] of Object.entries(corsHeaders(request))) headers.set(key,value);
    return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
  }
  if((url.pathname==="/admin/audit"||url.pathname==="/admin/backup")&&request.method==="GET"){
    if(request.headers.get("Origin")!==SITE_ORIGIN||!env.ADMIN_PASSWORD||!(await validToken(request,env.ADMIN_PASSWORD)))return json({error:"Unauthorized"},401,request);
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const target=url.pathname==="/admin/audit"?"/audit":"/backup";
    if(target==="/backup")await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/audit-event",request.url),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"BACKUP_EXPORT",config_key:"website_backup",summary:"Website database backup exported",actor:"owner"})}));
    const response=await env.VISITOR_STORE.get(id).fetch(new Request(new URL(target,request.url),{method:"GET"}));
    const headers=new Headers(response.headers);
    for(const [key,value] of Object.entries(corsHeaders(request)))headers.set(key,value);
    return new Response(response.body,{status:response.status,headers});
  }
  if(url.pathname==="/admin/restore"&&request.method==="POST"){
    if(request.headers.get("Origin")!==SITE_ORIGIN||!env.ADMIN_PASSWORD||!(await validToken(request,env.ADMIN_PASSWORD)))return json({error:"Unauthorized"},401,request);
    let body;try{body=await request.json()}catch{return json({error:"Invalid JSON"},400,request)}
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const response=await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/restore",request.url),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}));
    const headers=new Headers(response.headers);for(const [key,value] of Object.entries(corsHeaders(request)))headers.set(key,value);
    return new Response(response.body,{status:response.status,headers});
  }
  if(url.pathname==="/admin/site-config"&&(request.method==="GET"||request.method==="POST")){
    if(request.headers.get("Origin")!==SITE_ORIGIN||!env.ADMIN_PASSWORD||!(await validToken(request,env.ADMIN_PASSWORD)))return json({error:"Unauthorized"},401,request);
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const init={method:request.method,headers:{"Content-Type":"application/json"}};
    if(request.method==="POST")init.body=await request.text();
    const response=await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/config",request.url),init));
    const headers=new Headers(response.headers);
    for(const [key,value] of Object.entries(corsHeaders(request)))headers.set(key,value);
    return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
  }
  if(url.pathname==="/admin/page-cms"&&(request.method==="GET"||request.method==="POST")){
    if(request.headers.get("Origin")!==SITE_ORIGIN||!env.ADMIN_PASSWORD||!(await validToken(request,env.ADMIN_PASSWORD)))return json({error:"Unauthorized"},401,request);
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const init={method:request.method,headers:{"Content-Type":"application/json"}};
    if(request.method==="POST")init.body=await request.text();
    const response=await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/pages",request.url),init));
    const headers=new Headers(response.headers);for(const [key,value] of Object.entries(corsHeaders(request)))headers.set(key,value);
    return new Response(response.body,{status:response.status,headers});
  }
  if(url.pathname==="/page-cms"&&request.method==="GET"){
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const response=await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/pages",request.url),{method:"GET"}));
    const headers=new Headers(response.headers);for(const [key,value] of Object.entries(corsHeaders(request)))headers.set(key,value);
    return new Response(response.body,{status:response.status,headers});
  }
  if(url.pathname==="/admin/site-content"&&(request.method==="GET"||request.method==="POST")){
    if(request.headers.get("Origin")!==SITE_ORIGIN||!env.ADMIN_PASSWORD||!(await validToken(request,env.ADMIN_PASSWORD)))return json({error:"Unauthorized"},401,request);
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const init={method:request.method,headers:{"Content-Type":"application/json"}};
    if(request.method==="POST")init.body=await request.text();
    const response=await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/content",request.url),init));
    const headers=new Headers(response.headers);
    for(const [key,value] of Object.entries(corsHeaders(request)))headers.set(key,value);
    return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
  }
  if(url.pathname==="/site-content"&&request.method==="GET"){
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const response=await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/content",request.url),{method:"GET"}));
    const headers=new Headers(response.headers);
    for(const [key,value] of Object.entries(corsHeaders(request)))headers.set(key,value);
    return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
  }
  if(url.pathname==="/site-config"&&request.method==="GET"){
    const id=env.VISITOR_STORE.idFromName("global-visitor-store");
    const response=await env.VISITOR_STORE.get(id).fetch(new Request(new URL("/config",request.url),{method:"GET"}));
    const headers=new Headers(response.headers);
    for(const [key,value] of Object.entries(corsHeaders(request)))headers.set(key,value);
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
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS admin_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, config_key TEXT NOT NULL, changed_at INTEGER NOT NULL, summary TEXT NOT NULL, actor TEXT NOT NULL DEFAULT 'owner', before_value TEXT, after_value TEXT)");
    for (const migration of ["ALTER TABLE admin_audit ADD COLUMN actor TEXT NOT NULL DEFAULT 'owner'", "ALTER TABLE admin_audit ADD COLUMN before_value TEXT", "ALTER TABLE admin_audit ADD COLUMN after_value TEXT"]) { try { this.ctx.storage.sql.exec(migration); } catch {} }
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
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS site_config (
        config_key TEXT PRIMARY KEY,
        config_value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
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
    if(url.pathname==="/audit-event"&&request.method==="POST"){
      let event;try{event=await request.json()}catch{return json({error:"Invalid JSON"},400)}
      const action=String(event.action||"ADMIN_ACTION").slice(0,80);
      const configKey=String(event.config_key||"admin").slice(0,120);
      const summary=String(event.summary||"Admin action").slice(0,500);
      const actor=String(event.actor||"owner").slice(0,80);
      this.ctx.storage.sql.exec("INSERT INTO admin_audit(action,config_key,changed_at,summary,actor,before_value,after_value) VALUES(?,?,?,?,?,?,?)",action,configKey,Date.now(),summary,actor,event.before_value==null?null:JSON.stringify(event.before_value),event.after_value==null?null:JSON.stringify(event.after_value));
      return json({ok:true});
    }
    if(url.pathname==="/audit"&&request.method==="GET"){const rows=this.ctx.storage.sql.exec("SELECT id,action,config_key,changed_at,summary,actor,before_value,after_value FROM admin_audit ORDER BY id DESC LIMIT 200").toArray();return json({items:rows});}
    if(url.pathname==="/backup"&&request.method==="GET"){
      const siteConfig=this.ctx.storage.sql.exec("SELECT config_key,config_value,updated_at FROM site_config ORDER BY config_key").toArray();
      const visitors=this.ctx.storage.sql.exec("SELECT visitor_id,first_seen,last_seen FROM visitors ORDER BY visitor_id").toArray();
      const dailyVisits=this.ctx.storage.sql.exec("SELECT visitor_id,visit_day FROM daily_visits ORDER BY visit_day,visitor_id").toArray();
      const audit=this.ctx.storage.sql.exec("SELECT id,action,config_key,changed_at,summary,actor,before_value,after_value FROM admin_audit ORDER BY id").toArray();
      return json({format:"sjp-website-backup-v2",createdAt:now,timezone:"Asia/Dhaka",scope:["site_config","visitors","daily_visits","admin_audit"],siteConfig,visitors,dailyVisits,audit});
    }
    if(url.pathname==="/restore"&&request.method==="POST"){
      let b;try{b=await request.json()}catch{return json({error:"Invalid JSON"},400)}
      if(b.format!=="sjp-website-backup-v2"||!Array.isArray(b.siteConfig)||!Array.isArray(b.visitors)||!Array.isArray(b.dailyVisits)||!Array.isArray(b.audit))return json({error:"Backup format invalid or incomplete"},400);
      if(b.siteConfig.length>500||b.visitors.length>200000||b.dailyVisits.length>500000||b.audit.length>100000)return json({error:"Backup exceeds safe limits"},413);
      for(const x of b.siteConfig)if(typeof x.config_key!=="string"||typeof x.config_value!=="string"||!Number.isFinite(Number(x.updated_at)))return json({error:"Invalid site config row"},400);
      for(const x of b.visitors)if(typeof x.visitor_id!=="string"||!Number.isFinite(Number(x.first_seen))||!Number.isFinite(Number(x.last_seen)))return json({error:"Invalid visitor row"},400);
      for(const x of b.dailyVisits)if(typeof x.visitor_id!=="string"||typeof x.visit_day!=="string")return json({error:"Invalid daily visit row"},400);
      for(const x of b.audit)if(typeof x.action!=="string"||typeof x.config_key!=="string"||!Number.isFinite(Number(x.changed_at))||typeof x.summary!=="string")return json({error:"Invalid audit row"},400);
      try{
        this.ctx.storage.sql.exec("BEGIN");
        this.ctx.storage.sql.exec("DELETE FROM site_config");this.ctx.storage.sql.exec("DELETE FROM visitors");this.ctx.storage.sql.exec("DELETE FROM daily_visits");this.ctx.storage.sql.exec("DELETE FROM admin_audit");
        for(const x of b.siteConfig)this.ctx.storage.sql.exec("INSERT INTO site_config(config_key,config_value,updated_at) VALUES(?,?,?)",x.config_key,x.config_value,Number(x.updated_at));
        for(const x of b.visitors)this.ctx.storage.sql.exec("INSERT INTO visitors(visitor_id,first_seen,last_seen) VALUES(?,?,?)",x.visitor_id,Number(x.first_seen),Number(x.last_seen));
        for(const x of b.dailyVisits)this.ctx.storage.sql.exec("INSERT INTO daily_visits(visitor_id,visit_day) VALUES(?,?)",x.visitor_id,x.visit_day);
        for(const x of b.audit)this.ctx.storage.sql.exec("INSERT INTO admin_audit(action,config_key,changed_at,summary,actor,before_value,after_value) VALUES(?,?,?,?,?,?,?)",x.action,x.config_key,Number(x.changed_at),x.summary,String(x.actor||"owner"),x.before_value??null,x.after_value??null);
        this.ctx.storage.sql.exec("COMMIT");
        this.ctx.storage.sql.exec("INSERT INTO admin_audit(action,config_key,changed_at,summary,actor,after_value) VALUES(?,?,?,?,?,?)","RESTORE","full_database",now,"Full website database restored from v2 backup","owner",JSON.stringify({siteConfig:b.siteConfig.length,visitors:b.visitors.length,dailyVisits:b.dailyVisits.length,audit:b.audit.length}));
        return json({ok:true,restored:{siteConfig:b.siteConfig.length,visitors:b.visitors.length,dailyVisits:b.dailyVisits.length,audit:b.audit.length}});
      }catch(e){try{this.ctx.storage.sql.exec("ROLLBACK")}catch{};return json({error:"Restore failed; database rollback attempted"},500)}
    }
    if(url.pathname==="/pages"&&request.method==="GET"){
      const row=this.ctx.storage.sql.exec("SELECT config_value,updated_at FROM site_config WHERE config_key='page_cms'").toArray()[0];
      let pages={};if(row){try{pages=JSON.parse(row.config_value)}catch{}}
      return json({pages,updatedAt:row?.updated_at||null});
    }
    if(url.pathname==="/pages"&&request.method==="POST"){
      let body;try{body=await request.json()}catch{return json({error:"Invalid JSON"},400)}
      const allowed=["index","about","apps","advertise","battle-of-brains","contact","resources","upcoming"];
      if(!body||typeof body.page!=="string"||!allowed.includes(body.page))return json({error:"Invalid page"},400);
      const fields=["title","heroText","introText","heroImage","primaryButtonText","primaryButtonUrl","secondaryButtonText","secondaryButtonUrl","sectionTitle","sectionText","section2Title","section2Text","seoDescription"];
      const row=this.ctx.storage.sql.exec("SELECT config_value FROM site_config WHERE config_key='page_cms'").toArray()[0];
      let pages={};if(row){try{pages=JSON.parse(row.config_value)}catch{}}
      const before=pages[body.page]||null;
      const content={};for(const f of fields){const v=String(body[f]??"").trim();if(v.length>1200)return json({error:f+" সর্বোচ্চ ১২০০ অক্ষর"},400);if((f.endsWith("Url")||f==="heroImage")&&v&&!/^https:\/\//i.test(v))return json({error:f+"-এ https URL দিতে হবে"},400);content[f]=v;}
      pages[body.page]=content;const value=JSON.stringify(pages);
      this.ctx.storage.sql.exec("INSERT INTO admin_audit(action,config_key,changed_at,summary,actor,before_value,after_value) VALUES(?,?,?,?,?,?,?)","UPDATE","page_cms:"+body.page,now,"Page CMS updated: "+body.page,"owner",before===null?null:JSON.stringify(before),JSON.stringify(content));
      this.ctx.storage.sql.exec("INSERT INTO site_config(config_key,config_value,updated_at) VALUES('page_cms',?,?) ON CONFLICT(config_key) DO UPDATE SET config_value=excluded.config_value,updated_at=excluded.updated_at",value,now);
      return json({ok:true,page:body.page,content,updatedAt:now});
    }
    if(url.pathname==="/config"&&request.method==="GET"){
      const row=this.ctx.storage.sql.exec("SELECT config_value, updated_at FROM site_config WHERE config_key = 'announcement'").toArray()[0];
      let announcement={enabled:false,text:"",updatedAt:null};
      if(row){try{announcement={...JSON.parse(row.config_value),updatedAt:row.updated_at}}catch{}}
      return json({announcement});
    }
    if(url.pathname==="/config"&&request.method==="POST"){
      let body;try{body=await request.json()}catch{return json({error:"Invalid JSON"},400)}
      const text=String(body.text||"").trim();
      const enabled=body.enabled===true;
      if(text.length>300)return json({error:"নোটিশ সর্বোচ্চ ৩০০ অক্ষরের হতে পারবে"},400);
      const value=JSON.stringify({enabled,text});
      const previous=this.ctx.storage.sql.exec("SELECT config_value FROM site_config WHERE config_key = 'announcement'").toArray()[0]?.config_value??null;
      this.ctx.storage.sql.exec("INSERT INTO admin_audit(action,config_key,changed_at,summary,actor,before_value,after_value) VALUES(?,?,?,?,?,?,?)","UPDATE","announcement",now,"Notice updated","owner",previous,value);
      this.ctx.storage.sql.exec("INSERT INTO site_config(config_key,config_value,updated_at) VALUES('announcement',?,?) ON CONFLICT(config_key) DO UPDATE SET config_value=excluded.config_value,updated_at=excluded.updated_at",value,now);
      return json({ok:true,announcement:{enabled,text,updatedAt:now}});
    }
    if(url.pathname==="/content"&&request.method==="GET"){
      const row=this.ctx.storage.sql.exec("SELECT config_value, updated_at FROM site_config WHERE config_key = 'homepage_content'").toArray()[0];
      let content={};
      if(row){try{content={...JSON.parse(row.config_value),updatedAt:row.updated_at}}catch{}}
      return json({content});
    }
    if(url.pathname==="/content"&&request.method==="POST"){
      let body;try{body=await request.json()}catch{return json({error:"Invalid JSON"},400)}
      const fields=["heroTitle","heroSubtitle","heroPrimaryButton","heroSecondaryButton","featuredTitle","featuredDescription","appDescription"];
      const content={};
      for(const field of fields){
        const value=String(body[field]??"").trim();
        if(value.length>500)return json({error:field+" সর্বোচ্চ ৫০০ অক্ষর হতে পারবে"},400);
        content[field]=value;
      }
      const value=JSON.stringify(content);
      const previous=this.ctx.storage.sql.exec("SELECT config_value FROM site_config WHERE config_key = 'homepage_content'").toArray()[0]?.config_value??null;
      this.ctx.storage.sql.exec("INSERT INTO admin_audit(action,config_key,changed_at,summary,actor,before_value,after_value) VALUES(?,?,?,?,?,?,?)","UPDATE","homepage_content",now,"Homepage CMS updated","owner",previous,value);
      this.ctx.storage.sql.exec("INSERT INTO site_config(config_key,config_value,updated_at) VALUES('homepage_content',?,?) ON CONFLICT(config_key) DO UPDATE SET config_value=excluded.config_value,updated_at=excluded.updated_at",value,now);
      return json({ok:true,content:{...content,updatedAt:now}});
    }
    return json({ error: "Not found" }, 404);
  }
}
