// Diamantina - Cloudflare Worker: juego + captcha AdsLab
const enc = new TextEncoder();
async function hmac(secret, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret || "x"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const s = await crypto.subtle.sign("HMAC", k, enc.encode(msg));
  return [...new Uint8Array(s)].map(b => b.toString(16).padStart(2, "0")).join("");
}
const CORS = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type" };
const SITES = ["https://diamantinagame.xyz", "https://www.diamantinagame.xyz"];
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store", ...CORS } });
async function adslabInit(env, subId, returnUrl, key) {
  const r = await fetch("https://adslab.me/api/v1/captcha/init", {
    method: "POST", headers: { "content-type": "application/json", "accept": "application/json", "x-api-key": key || env.ADSLAB_API_KEY || "" },
    body: JSON.stringify({ sub_id: subId, return_url: returnUrl })
  });
  const text = await r.text(); let d = {}; try { d = JSON.parse(text); } catch (e) {}
  return { r, d, text };
}

/* ===== AdsLab Tasks postback -> credit the player in Firebase =====
   Cloudflare variables needed:
   TASKS_TOKEN = secret word that goes in the postback URL (/api/tasks/<TASKS_TOKEN>)
   FB_EMAIL / FB_PASS = owner account (the one in the Firestore rules)
   TASK_SHARE (optional) = part of the reward for the player, default 0.7 (70%) */
const FB_KEY = "AIzaSyBjRFR9IpFjcV_rJGJ_jWPOB2rrFNXSS40", FB_PROJECT = "diamantinagame-d2c79";
const FS = "https://firestore.googleapis.com/v1/projects/" + FB_PROJECT + "/databases/(default)/documents/";
async function fbToken(env) {
  const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" + FB_KEY, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: env.FB_EMAIL, password: env.FB_PASS, returnSecureToken: true }) });
  const d = await r.json(); if (!d.idToken) throw new Error("login " + ((d.error && d.error.message) || r.status)); return d.idToken;
}
const fv = v => typeof v === "number" ? (Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v }) : { stringValue: String(v) };
async function fsSet(tok, path, obj) {
  const fields = {}; for (const k in obj) fields[k] = fv(obj[k]);
  const r = await fetch(FS + path, { method: "PATCH", headers: { "content-type": "application/json", authorization: "Bearer " + tok }, body: JSON.stringify({ fields }) });
  if (!r.ok) throw new Error("firestore " + r.status + " " + (await r.text()).slice(0, 120));
}
async function tasksPostback(request, env, token) {
  if (!env.TASKS_TOKEN || token !== env.TASKS_TOKEN) return new Response("forbidden", { status: 403 });
  const q = new URL(request.url).searchParams;
  const uid = (q.get("uid") || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 64);
  const txid = (q.get("txid") || "").replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 80);
  const reward = parseFloat(q.get("reward") || "0") || 0, vcur = parseFloat(q.get("vCurrency") || "0") || 0;
  if (!uid || !txid) return new Response("missing uid/txid", { status: 400 });
  const share = Math.min(1, Math.max(0, parseFloat(env.TASK_SHARE || "0.7") || 0.7));
  const usd = Math.min(reward, 1) * share;                    // safety cap: max $1 per task
  const units = Math.max(0, Math.round(usd * 1e5));            // game units ($0.00001)
  const tok = await fbToken(env), now = Date.now();
  const rec = { type: "task", units, reward, vCurrency: vcur, txid, pid: q.get("pid") || "", ttype: q.get("type") || "", sig: q.get("signature") || "", at: now };
  await fsSet(tok, "credits/" + uid, { updatedAt: now });
  await fsSet(tok, "credits/" + uid + "/list/task_" + txid, rec);
  return new Response("OK");
}

async function handle(request, env) {
  try {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const url = new URL(request.url), a = url.searchParams.get("a");
    if (a === "diag") {
      const out = { ok: true, hasKey: !!env.ADSLAB_API_KEY, hasSecret: !!env.ADSLAB_SECRET, hasKeyXyz: !!env.ADSLAB_API_KEY_XYZ };
      if (out.hasKey) { const { r, text } = await adslabInit(env, "diag-" + Date.now(), url.origin + "/"); out.adslab = { status: r.status, body: text.replace(/"token"\s*:\s*"[^"]+"/, '"token":"(ok)"').slice(0, 300) }; }
      return json(out);
    }
    if (a === "init" && request.method === "POST") {
      if (!env.ADSLAB_API_KEY) return json({ ok: false, error: "missing ADSLAB_API_KEY" }, 500);
      let body = {}; try { body = await request.json(); } catch (e) {}
      const uid = String(body.uid || "anon").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 40) || "anon";
      const subId = uid + "-" + Date.now().toString(36) + "-" + crypto.randomUUID().slice(0, 8);
      const ck = (await hmac(env.ADSLAB_SECRET, "ret:" + subId)).slice(0, 32);
      const site = SITES.includes(body.origin) ? body.origin : url.origin;
      const key = site === url.origin ? env.ADSLAB_API_KEY : (env.ADSLAB_API_KEY_XYZ || env.ADSLAB_API_KEY);
      const { r, d, text } = await adslabInit(env, subId, site + "/?captcha=" + encodeURIComponent(subId) + "&ck=" + ck, key);
      if (!r.ok || !d.success || !d.token) return json({ ok: false, error: d.message || d.error || ("adslab " + r.status + " " + text.slice(0, 60)) }, 502);
      return json({ ok: true, sub_id: subId, token: d.token, solve_url: d.solve_url || "https://adslab.me/captcha" });
    }
    if (a === "postback") return new Response("OK");
    if (a === "status") {
      const subId = url.searchParams.get("sub_id") || "", ck = url.searchParams.get("ck") || "";
      if (!/^[A-Za-z0-9_-]{5,80}$/.test(subId)) return json({ ok: false, status: "unknown" }, 400);
      const parts = subId.split("-"), at = parseInt(parts[parts.length - 2], 36) || 0;
      const good = ck && ck === (await hmac(env.ADSLAB_SECRET, "ret:" + subId)).slice(0, 32);
      if (good && Date.now() - at < 30 * 60 * 1000) return json({ ok: true, status: "success" });
      return json({ ok: false, status: good ? "expired" : "unknown" });
    }
    return json({ ok: false, error: "bad_request" }, 400);
  } catch (e) {
    return json({ ok: false, error: "server: " + String((e && e.message) || e).slice(0, 120) }, 500);
  }
}

export default {
  async fetch(request, env) {
    const u = new URL(request.url);
    if (u.pathname === "/api/captcha") return handle(request, env);
    if (u.pathname.startsWith("/api/tasks/")) { try { return await tasksPostback(request, env, u.pathname.slice(11)); } catch (e) { return new Response("error: " + String((e && e.message) || e).slice(0, 150), { status: 500 }); } }
    return env.ASSETS.fetch(request);
  }
};
