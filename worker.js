// Diamantina - Cloudflare Worker: juego + captcha AdsLab + ranking/pruebas en D1
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


/* ===== D1 database: ranking, referrals and payment proofs (no Firebase reads) =====
   Binding name: DB (see wrangler.jsonc). Players prove who they are with their Firebase login token,
   which is checked here with Google's public keys (this does not use the Firestore quota). */
const OWNER_EMAIL = "julioduluc01@gmail.com";
const BOG = 5 * 3600000;                                  // Colombia = UTC-5
let JWKS = null, JWKS_AT = 0, D1_READY = false;
const b64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));
async function jwks(force) {
  if (JWKS && !force && Date.now() - JWKS_AT < 3600000) return JWKS;
  const r = await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com");
  const d = await r.json(), out = {};
  for (const k of d.keys || []) out[k.kid] = await crypto.subtle.importKey("jwk", k, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  JWKS = out; JWKS_AT = Date.now(); return out;
}
async function who(tok) {
  const [h, p, sg] = String(tok || "").split(".");
  if (!sg) throw new Error("no_token");
  const H = JSON.parse(new TextDecoder().decode(b64u(h))), P = JSON.parse(new TextDecoder().decode(b64u(p)));
  if (H.alg !== "RS256") throw new Error("bad_token");
  let keys = await jwks(), k = keys[H.kid];
  if (!k) { keys = await jwks(true); k = keys[H.kid]; }
  if (!k || !(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", k, b64u(sg), enc.encode(h + "." + p)))) throw new Error("bad_token");
  const now = Date.now() / 1000;
  if (P.aud !== FB_PROJECT || P.iss !== "https://securetoken.google.com/" + FB_PROJECT || !P.sub || P.exp < now - 60) throw new Error("bad_token");
  const anon = !!(P.firebase && P.firebase.sign_in_provider === "anonymous");
  return { uid: P.sub, anon, owner: !anon && P.email_verified === true && String(P.email || "").toLowerCase() === OWNER_EMAIL };
}
function weekKey(off = 0) {
  const d = new Date(Date.now() - BOG), dow = (d.getUTCDay() + 6) % 7;
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - dow + off * 7)).toISOString().slice(0, 10);
}
async function d1Init(db) {
  if (D1_READY) return;
  await db.batch([
    "CREATE TABLE IF NOT EXISTS lb (uid TEXT PRIMARY KEY, nick TEXT, code TEXT, hero TEXT, vip INTEGER DEFAULT 0, coin TEXT, seen INTEGER DEFAULT 0, at INTEGER DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS lbw (uid TEXT, week TEXT, ads INTEGER, at INTEGER, PRIMARY KEY (uid, week))",
    "CREATE INDEX IF NOT EXISTS lbw_week ON lbw (week, ads)",
    "CREATE TABLE IF NOT EXISTS refs (uid TEXT PRIMARY KEY, by TEXT, at INTEGER, via TEXT)",
    "CREATE INDEX IF NOT EXISTS refs_at ON refs (at)",
    "CREATE TABLE IF NOT EXISTS proofs (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER, coin TEXT, method TEXT, usd TEXT, amt REAL, who TEXT, code TEXT)",
    "CREATE INDEX IF NOT EXISTS proofs_at ON proofs (at)",
    "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT, at INTEGER)"
  ].map(q => db.prepare(q)));
  D1_READY = true;
}
const metaGet = async (db, k) => { const r = await db.prepare("SELECT v, at FROM meta WHERE k = ?").bind(k).first(); return r ? { v: JSON.parse(r.v), at: r.at } : null; };
const metaSet = (db, k, v) => db.prepare("INSERT INTO meta (k, v, at) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, at = excluded.at").bind(k, JSON.stringify(v), Date.now());
const str = (v, n) => String(v == null ? "" : v).slice(0, n);
const int = (v, max) => Math.max(0, Math.min(max, Math.floor(+v || 0)));
async function namesFor(db, uids, snap) {
  const need = [...new Set(uids)].filter(u => !(u in snap.names));
  for (let i = 0; i < need.length; i += 90) {
    const part = need.slice(i, i + 90);
    const r = await db.prepare("SELECT uid, nick, code, hero, vip FROM lb WHERE uid IN (" + part.map(() => "?").join(",") + ")").bind(...part).all();
    for (const x of r.results || []) { snap.names[x.uid] = x.nick || ("Hero-" + (x.code || "")); if (x.hero) snap.heroes[x.uid] = x.hero; if (x.vip) snap.vips[x.uid] = x.vip; }
  }
}
async function buildComp(db, week, fs, fe) {
  const snap = { ads: [], refs: [], names: {}, heroes: {}, vips: {} };
  const a = await db.prepare("SELECT w.uid, w.ads, l.nick, l.code, l.hero, l.vip FROM lbw w LEFT JOIN lb l ON l.uid = w.uid WHERE w.week = ? AND w.ads > 0 ORDER BY w.ads DESC LIMIT 150").bind(week).all();
  for (const x of a.results || []) { snap.ads.push({ uid: x.uid, n: x.ads }); snap.names[x.uid] = x.nick || ("Hero-" + (x.code || "")); if (x.hero) snap.heroes[x.uid] = x.hero; if (x.vip) snap.vips[x.uid] = x.vip; }
  const r = await db.prepare("SELECT by AS uid, COUNT(*) AS n FROM refs WHERE at >= ? AND at < ? AND via != 'bought' AND by != '' GROUP BY by ORDER BY n DESC LIMIT 150").bind(fs, fe).all();
  snap.refs = (r.results || []).map(x => ({ uid: x.uid, n: x.n }));
  await namesFor(db, snap.refs.map(x => x.uid), snap);
  return snap;
}
async function d1(request, env) {
  const db = env.DB; if (!db) return json({ ok: false, error: "no_db" }, 503);
  await d1Init(db);
  const url = new URL(request.url), a = url.searchParams.get("a");
  let body = {}; if (request.method === "POST") { try { body = JSON.parse(await request.text()); } catch (e) {} }
  if (a === "comp") {
    const week = url.searchParams.get("week") || weekKey(), fs = +url.searchParams.get("fs") || 0, fe = +url.searchParams.get("fe") || 0;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(week) || Math.abs(Date.parse(week) - Date.now()) > 40 * 86400000 || Math.abs(fs - Date.now()) > 40 * 86400000 || fe <= fs || fe - fs > 17 * 86400000) return json({ ok: false, error: "bad" }, 400);
    const key = "comp:" + week + ":" + fs, old = await metaGet(db, key), cur = week === weekKey();
    const fin = Math.max(Date.parse(week) + 7 * 86400000 + BOG, fe) + 600000;   // a past week is final 10 min after it ends
    if (old && (cur ? Date.now() - old.at < 120000 : old.at > fin)) return json({ ok: true, ...old.v, at: old.at, imp: !!(await metaGet(db, "imported")) });
    const snap = await buildComp(db, week, fs, fe);
    await metaSet(db, key, snap).run();
    return json({ ok: true, ...snap, at: Date.now(), imp: !!(await metaGet(db, "imported")) });
  }
  if (a === "proofs") {
    const old = await metaGet(db, "proofs");
    if (old && Date.now() - old.at < 10 * 60000) return json({ ok: true, ...old.v, at: old.at });
    const cut = Date.now() - 30 * 86400000;
    const p = await db.prepare("SELECT at, coin, method, usd, amt, who, code FROM proofs WHERE at >= ? ORDER BY at DESC LIMIT 40").bind(cut).all();
    const st = await metaGet(db, "stats"), n = await db.prepare("SELECT COUNT(*) AS n FROM lb").first();
    const snap = { p: (p.results || []).map(x => ({ at: x.at, coin: x.coin, method: x.method, amountUsd: x.usd, amountCoin: x.amt, who: x.who, code: x.code })), s: st ? st.v : null, n: Math.max(n ? n.n : 0, (st && st.v && st.v.players) || 0) };
    await metaSet(db, "proofs", snap).run();
    return json({ ok: true, ...snap, at: Date.now() });
  }
  if (request.method !== "POST") return json({ ok: false, error: "bad_request" }, 400);
  let me; try { me = await who(body.t); } catch (e) { return json({ ok: false, error: String(e.message || e) }, 401); }
  const now = Date.now();
  if (a === "push") {                                     // player's weekly ad count + profile + "online now"
    if (me.anon) return json({ ok: false, error: "register" }, 403);
    const q = [];
    const week = String(body.week || ""), ads = int(body.ads, 50000);
    if (week === weekKey() || week === weekKey(-1))
      q.push(db.prepare("INSERT INTO lbw (uid, week, ads, at) VALUES (?, ?, ?, ?) ON CONFLICT(uid, week) DO UPDATE SET ads = MAX(lbw.ads, excluded.ads), at = excluded.at WHERE excluded.ads > lbw.ads").bind(me.uid, week, ads, now));
    if (body.nick != null)
      q.push(db.prepare("INSERT INTO lb (uid, nick, code, hero, vip, coin, seen, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(uid) DO UPDATE SET nick = excluded.nick, code = excluded.code, hero = excluded.hero, vip = excluded.vip, coin = excluded.coin, seen = excluded.seen, at = excluded.at")
        .bind(me.uid, str(body.nick, 20), str(body.code, 8), str(body.hero, 20), int(body.vip, 4), str(body.coin, 10), now, now));
    else q.push(db.prepare("UPDATE lb SET seen = ?, coin = ?, vip = ? WHERE uid = ?").bind(now, str(body.coin, 10), int(body.vip, 4), me.uid));
    await db.batch(q);
    return json({ ok: true });
  }
  if (a === "ref") {                                       // "player X was invited by Y"
    const by = str(body.by, 64).replace(/[^A-Za-z0-9]/g, "");
    if (!by || by === me.uid) return json({ ok: false, error: "bad" }, 400);
    await db.prepare("INSERT OR IGNORE INTO refs (uid, by, at, via) VALUES (?, ?, ?, ?)").bind(me.uid, by, now, str(body.via, 10) || "code").run();
    return json({ ok: true });
  }
  if (a === "live") {                                      // owner: players online now
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const r = await db.prepare("SELECT coin, vip FROM lb WHERE seen > ?").bind(now - 240000).all();
    return json({ ok: true, list: r.results || [] });
  }
  if (a === "proof") {                                     // owner marks a payout as paid
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const usd = parseFloat(body.amountUsd) || 0, st = (await metaGet(db, "stats")) || { v: {} };
    const s = { ...st.v, paidUsd: (+st.v.paidUsd || 0) + usd, paidN: (+st.v.paidN || 0) + 1 };
    await db.batch([
      db.prepare("INSERT INTO proofs (at, coin, method, usd, amt, who, code) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(now, str(body.coin, 10), str(body.method, 12), str(body.amountUsd, 12), body.amountCoin == null ? null : +body.amountCoin || 0, str(body.who, 12), str(body.code, 8)),
      metaSet(db, "stats", s),
      db.prepare("DELETE FROM meta WHERE k = 'proofs'"),
      db.prepare("DELETE FROM proofs WHERE at < ?").bind(now - 30 * 86400000)
    ]);
    return json({ ok: true, s });
  }
  if (a === "import") {                                    // owner: one-time copy of the old Firebase data (small pieces: free plan = 50 queries per call)
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const q = [];
    for (const x of (body.lb || []).slice(0, 18)) {
      const uid = str(x.uid, 64); if (!uid) continue;
      q.push(db.prepare("INSERT INTO lb (uid, nick, code, hero, vip, coin, seen, at) VALUES (?, ?, ?, ?, ?, '', 0, ?) ON CONFLICT(uid) DO NOTHING").bind(uid, str(x.nick, 20), str(x.code, 8), str(x.hero, 20), int(x.vip, 4), int(x.at, 9e15)));
      if (x.week && x.ads > 0) q.push(db.prepare("INSERT INTO lbw (uid, week, ads, at) VALUES (?, ?, ?, ?) ON CONFLICT(uid, week) DO UPDATE SET ads = MAX(lbw.ads, excluded.ads)").bind(uid, str(x.week, 10), int(x.ads, 50000), now));
    }
    for (const x of (body.refs || []).slice(0, 40)) if (x.uid && x.by)
      q.push(db.prepare("INSERT OR IGNORE INTO refs (uid, by, at, via) VALUES (?, ?, ?, ?)").bind(str(x.uid, 64), str(x.by, 64), int(x.at, 9e15), str(x.via, 10)));
    for (const x of (body.proofs || []).slice(0, 40))
      q.push(db.prepare("INSERT INTO proofs (at, coin, method, usd, amt, who, code) SELECT ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM proofs WHERE at = ? AND code = ?)").bind(int(x.at, 9e15), str(x.coin, 10), str(x.method, 12), str(x.amountUsd, 12), x.amountCoin == null ? null : +x.amountCoin || 0, str(x.who, 12), str(x.code, 8), int(x.at, 9e15), str(x.code, 8)));
    if (body.stats) q.push(metaSet(db, "stats", { paidUsd: +body.stats.paidUsd || 0, paidN: int(body.stats.paidN, 1e9), players: int(body.stats.players, 1e9) }));
    if (body.done) { q.push(metaSet(db, "imported", 1)); q.push(db.prepare("DELETE FROM meta WHERE k LIKE 'comp:%' OR k = 'proofs'")); }
    for (let i = 0; i < q.length; i += 90) await db.batch(q.slice(i, i + 90));
    return json({ ok: true, n: q.length });
  }
  return json({ ok: false, error: "bad_request" }, 400);
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
    if (u.pathname === "/api/d1") { try { return await d1(request, env); } catch (e) { return json({ ok: false, error: "server: " + String((e && e.message) || e).slice(0, 150) }, 500); } }
    if (u.pathname.startsWith("/api/tasks/")) { try { return await tasksPostback(request, env, u.pathname.slice(11)); } catch (e) { return new Response("error: " + String((e && e.message) || e).slice(0, 150), { status: 500 }); } }
    return env.ASSETS.fetch(request);
  }
};
