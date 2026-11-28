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
