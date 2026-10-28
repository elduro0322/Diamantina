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
/* every AdsLab notice is written down, so the owner can see if they arrive and why one failed */
async function tlog(env, uid, txid, st, reward) { try { if (!env.DB) return; await d1Init(env.DB);
  await env.DB.prepare("INSERT INTO tlog (at, uid, txid, st, reward) VALUES (?, ?, ?, ?, ?)").bind(Date.now(), str(uid, 64), str(txid, 80), str(st, 120), +reward || 0).run();
  if (Math.random() < 0.02) await env.DB.prepare("DELETE FROM tlog WHERE at < ?").bind(Date.now() - 30 * 86400000).run(); } catch (e) {} }
async function tasksPostback(request, env, token) {
  if (!env.TASKS_TOKEN || token !== env.TASKS_TOKEN) { await tlog(env, "", "", "clave incorrecta en el link de AdsLab", 0); return new Response("forbidden", { status: 403 }); }
  const q = new URL(request.url).searchParams;
  const uid = (q.get("uid") || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 64);
  const txid = (q.get("txid") || "").replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 80);
  const reward = parseFloat(q.get("reward") || "0") || 0, vcur = parseFloat(q.get("vCurrency") || "0") || 0;
  if (!uid || !txid) { await tlog(env, uid, txid, "faltan uid o txid", reward); return new Response("missing uid/txid", { status: 400 }); }
  const share = Math.min(1, Math.max(0, parseFloat(env.TASK_SHARE || "0.7") || 0.7));
  const usd = Math.min(reward, 1) * share;                    // safety cap: max $1 per task
  const units = Math.max(0, Math.round(usd * 1e5));            // game units ($0.00001)
  const now = Date.now();
  const rec = { type: "task", units, reward, vCurrency: vcur, txid, pid: q.get("pid") || "", ttype: q.get("type") || "", sig: q.get("signature") || "", at: now };
  if (env.DB) {                                               // D1 (does not use the Firebase quota)
    await d1Init(env.DB);
    const ins = await env.DB.prepare("INSERT OR IGNORE INTO creds (uid, id, at, d) VALUES (?, ?, ?, ?)").bind(uid, "task_" + txid, now, JSON.stringify(rec)).run();
    let st = ins.meta && ins.meta.changes ? "ok" : "repetida";
    if (st === "ok") await env.DB.prepare("DELETE FROM meta WHERE k = 'taskstat'").run();   // new task: the panel summary is counted again
    if (units > 0) { try { await walCredit(env.DB, uid, "task_" + txid, units, now); } catch (e) { st = "guardada, error al sumar saldo: " + String(e && e.message || e).slice(0, 60); } }   // straight into the server wallet
    else if (st === "ok") st = "ok (premio $0)";
    await tlog(env, uid, txid, st, reward);
    return new Response("OK");
  }
  const tok = await fbToken(env);
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
    "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT, at INTEGER)",
    "CREATE TABLE IF NOT EXISTS nfts (id INTEGER PRIMARY KEY, owner TEXT, trades INTEGER DEFAULT 0, prev TEXT, at INTEGER)",
    "CREATE INDEX IF NOT EXISTS nfts_owner ON nfts (owner)",
    "CREATE TABLE IF NOT EXISTS market (nft INTEGER PRIMARY KEY, seller TEXT, units INTEGER, status TEXT, promo INTEGER DEFAULT 0, at INTEGER, buyer TEXT, soldAt INTEGER)",
    "CREATE INDEX IF NOT EXISTS market_status ON market (status)",
    "CREATE TABLE IF NOT EXISTS sales (id INTEGER PRIMARY KEY AUTOINCREMENT, nft INTEGER, seller TEXT, buyer TEXT, units INTEGER, fee INTEGER, gets INTEGER, at INTEGER, claimed INTEGER DEFAULT 0, cat INTEGER)",
    "CREATE INDEX IF NOT EXISTS sales_seller ON sales (seller, claimed)",
    "CREATE TABLE IF NOT EXISTS wnft (id INTEGER PRIMARY KEY, owner TEXT, at INTEGER)",
    "CREATE TABLE IF NOT EXISTS offstat (day TEXT, k TEXT, e TEXT, n INTEGER, PRIMARY KEY (day, k, e))",
    "CREATE INDEX IF NOT EXISTS lb_code ON lb (code)",
    "CREATE TABLE IF NOT EXISTS refvis (day TEXT, iph TEXT, PRIMARY KEY (day, iph))",
    "CREATE TABLE IF NOT EXISTS visits (uid TEXT, day TEXT, n INTEGER DEFAULT 0, paid INTEGER DEFAULT 0, PRIMARY KEY (uid, day))",
    "CREATE INDEX IF NOT EXISTS visits_day ON visits (day)",
    "CREATE TABLE IF NOT EXISTS vislog (at INTEGER, uid TEXT, kind TEXT, via TEXT)",
    "CREATE INDEX IF NOT EXISTS vislog_at ON vislog (at)",
    "CREATE TABLE IF NOT EXISTS msgs (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT, body TEXT, at INTEGER, seen INTEGER DEFAULT 0, reply TEXT, rat INTEGER)",
    "CREATE INDEX IF NOT EXISTS msgs_uid ON msgs (uid, seen)",
    "CREATE INDEX IF NOT EXISTS msgs_at ON msgs (at)",
    "CREATE TABLE IF NOT EXISTS refearn (uid TEXT PRIMARY KEY, by TEXT, base REAL, total REAL, at INTEGER)",
    "CREATE INDEX IF NOT EXISTS refearn_by ON refearn (by)",
    "CREATE INDEX IF NOT EXISTS refs_by ON refs (by)",
    "CREATE TABLE IF NOT EXISTS pays (uid TEXT, date TEXT, st TEXT, at INTEGER, d TEXT, PRIMARY KEY (uid, date))",
    "CREATE INDEX IF NOT EXISTS pays_st ON pays (st)",
    "CREATE TABLE IF NOT EXISTS ords (uid TEXT, id TEXT, st TEXT, at INTEGER, d TEXT, PRIMARY KEY (uid, id))",
    "CREATE INDEX IF NOT EXISTS ords_st ON ords (st)",
    "CREATE TABLE IF NOT EXISTS creds (uid TEXT, id TEXT, at INTEGER, d TEXT, PRIMARY KEY (uid, id))",
    "CREATE INDEX IF NOT EXISTS creds_at ON creds (uid, at)",
    "CREATE TABLE IF NOT EXISTS vips (uid TEXT PRIMARY KEY, until INTEGER, tier INTEGER, at INTEGER)",
    "CREATE TABLE IF NOT EXISTS vreq (uid TEXT PRIMARY KEY, st TEXT, at INTEGER, d TEXT)",
    "CREATE INDEX IF NOT EXISTS vreq_st ON vreq (st)",
    "CREATE TABLE IF NOT EXISTS lbd (uid TEXT, day TEXT, td INTEGER, PRIMARY KEY (uid, day))",
    "CREATE INDEX IF NOT EXISTS lbd_day ON lbd (day)",
    "CREATE TABLE IF NOT EXISTS lbx (uid TEXT PRIMARY KEY, bal INTEGER, staked INTEGER, dmt INTEGER, dev TEXT, stk TEXT, at INTEGER, fx REAL DEFAULT 0, fxn INTEGER DEFAULT 0, fm INTEGER DEFAULT 0, fmn INTEGER DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS lbc (uid TEXT PRIMARY KEY, cl INTEGER DEFAULT 0, at INTEGER)",   // total faucet claims (the level) — only ever goes up
    /* server wallet: the balance lives here; the phone only shows it */
    "CREATE TABLE IF NOT EXISTS wal (uid TEXT PRIMARY KEY, bal REAL DEFAULT 0, hold TEXT DEFAULT '{}', inc REAL DEFAULT 0, out REAL DEFAULT 0, spent REAL DEFAULT 0, day TEXT, dm TEXT DEFAULT '{}', n INTEGER DEFAULT 0, last INTEGER DEFAULT 0, mig REAL DEFAULT 0, at INTEGER)",
    "CREATE TABLE IF NOT EXISTS wled (uid TEXT, id TEXT, u REAL, at INTEGER, PRIMARY KEY (uid, id))",
    "CREATE TABLE IF NOT EXISTS wstk (uid TEXT, id TEXT, asset TEXT, amt REAL, rew REAL, p INTEGER, start INTEGER, endt INTEGER, PRIMARY KEY (uid, id))",
    "CREATE TABLE IF NOT EXISTS wmig (uid TEXT PRIMARY KEY, bal REAL, stk TEXT)",
    "CREATE TABLE IF NOT EXISTS ban (uid TEXT PRIMARY KEY, why TEXT, bal REAL, hold TEXT, at INTEGER)",
    "CREATE TABLE IF NOT EXISTS tlog (at INTEGER, uid TEXT, txid TEXT, st TEXT, reward REAL)",
    "CREATE INDEX IF NOT EXISTS tlog_at ON tlog (at)",
    "CREATE INDEX IF NOT EXISTS lb_seen ON lb (seen)",      // blocked players (money kept aside, given back if unblocked)
    "CREATE TABLE IF NOT EXISTS newacc (uid TEXT PRIMARY KEY, iph TEXT, at INTEGER)",                      // new accounts by connection (max 3 a day)
    "CREATE INDEX IF NOT EXISTS newacc_iph ON newacc (iph, at)"
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
/* monthly board (most visits): added up at most every 15 min, so it stays cheap even with thousands of visits */
async function visBoard(db, mo) {
  const key = "vis:" + mo, old = await metaGet(db, key), cur = mo === today(Date.now()).slice(0, 7);
  if (old && (Date.now() - old.at < 60 * 60000 || (!cur && old.v.final))) return old.v.list;   // monthly visits board: rebuilt at most once an hour
  const [y, m] = mo.split("-").map(Number), next = m === 12 ? (y + 1) + "-01" : y + "-" + String(m + 1).padStart(2, "0");
  const v = await db.prepare("SELECT uid, SUM(n) AS n FROM visits WHERE day >= ? AND day < ? AND uid NOT IN (SELECT uid FROM ban) GROUP BY uid ORDER BY n DESC LIMIT 150").bind(mo + "-01", next + "-01").all();
  const list = (v.results || []).filter(x => x.n > 0).map(x => ({ uid: x.uid, n: x.n }));
  await metaSet(db, key, { list, final: !cur && Date.now() > Date.parse(next + "-01") + BOG + 3600000 }).run();
  return list;
}
const LIM0 = { ads: 600, pay: 5 };                     // anti-cheat: max weekly ads on the board, max USD per withdrawal
const getLim = async db => { const m = await metaGet(db, "lim"); return { ...LIM0, ...((m && m.v) || {}) }; };
async function buildComp(db, week, fs, fe, mo) {
  const lim = await getLim(db);
  const snap = { ads: [], refs: [], vis: [], names: {}, heroes: {}, vips: {} };
  if (mo) snap.vis = await visBoard(db, mo);
  const a = await db.prepare("SELECT w.uid, w.ads, l.nick, l.code, l.hero, l.vip FROM lbw w LEFT JOIN lb l ON l.uid = w.uid WHERE w.week = ? AND w.ads > 0 AND w.ads <= ? AND w.uid NOT IN (SELECT uid FROM ban) ORDER BY w.ads DESC LIMIT 150").bind(week, lim.ads).all();
  for (const x of a.results || []) { snap.ads.push({ uid: x.uid, n: x.ads }); snap.names[x.uid] = x.nick || ("Hero-" + (x.code || "")); if (x.hero) snap.heroes[x.uid] = x.hero; if (x.vip) snap.vips[x.uid] = x.vip; }
  const r = await db.prepare("SELECT by AS uid, COUNT(*) AS n FROM refs WHERE at >= ? AND at < ? AND via != 'bought' AND by != '' AND by NOT IN (SELECT uid FROM ban) GROUP BY by ORDER BY n DESC LIMIT 150").bind(fs, fe).all();
  snap.refs = (r.results || []).map(x => ({ uid: x.uid, n: x.n }));
  await namesFor(db, [...snap.refs, ...snap.vis].map(x => x.uid), snap);
  return snap;
}

/* ===== NFT market in D1 (ownership, listings, sales, world NFTs) ===== */
const NFT_FEE = 5, NFT_MAX = 600;   // 500 silver-chest NFTs + 100 of the new collection (501-600)
const dropNft = db => db.prepare("DELETE FROM meta WHERE k = 'nft'");
async function nftSnap(db) {
  const old = await metaGet(db, "nft");
  if (old && Date.now() - old.at < 15 * 60000) return { ...old.v, at: old.at };   // every NFT change clears this copy, so it can live 15 min
  const [own, mk, w, fee, imp] = await db.batch([
    db.prepare("SELECT id, trades FROM nfts WHERE owner IS NOT NULL AND owner != ''"),
    db.prepare("SELECT nft, seller, units, promo AS promotedUntil, at FROM market WHERE status = 'open'"),
    db.prepare("SELECT id, owner FROM wnft"),
    db.prepare("SELECT v FROM meta WHERE k = 'fee'"),
    db.prepare("SELECT v FROM meta WHERE k = 'nftimp'")
  ]);
  const tr = {}; for (const x of own.results || []) if (x.trades) tr[x.id] = x.trades;
  const wo = {}; for (const x of w.results || []) if (x.owner) wo[x.id] = x.owner;
  const v = { taken: (own.results || []).filter(x => x.id <= 500).length,   /* "X of 500 left" counts only the silver-chest NFTs */ tr, mk: mk.results || [], w: wo, fee: (fee.results || []).length ? JSON.parse(fee.results[0].v) : { sum: 0, n: 0 }, imp: !!(imp.results || []).length };
  await metaSet(db, "nft", v).run();
  return { ...v, at: Date.now() };
}
/* ===================== SERVER WALLET =====================
   Every balance change is decided here. The phone sends "I watched the ad at circle N" and the
   server pays at most what that circle can pay (once per game day), so editing the phone does nothing. */
const WAL_MAX0 = 200000;                                     // moving to the server wallet: more than $2 saved on the phone = starts at 0
const WAL_HOLD0 = 20000;                                     // coins held / coin staking brought from the phone: max $0.20
const VIP_M = [1, 2, 3, 5, 10];
const MAIN_CH = { 3: 4, 10: 10, 14: 12, 18: 20 };           // extra units of each chest (main path)
const BW_CH = { 3: 10, 10: 20, 17: 40 };                     // bonus worlds
const W_OK = ["main", "magic", "cars", "mush", "castle", "xmas", "pirate", "skel", "lava"];
const STK = [{ d: 1, r: .0003 }, { d: 7, r: .003 }, { d: 30, r: .015 }, { d: 90, r: .06 }];
const REF_T = [10, 15, 20, 25, 30];
const VIP_USD = [2, 3.99, 8.99, 19.99];
const COINS_OK = /^[A-Z0-9]{2,8}$/;
const wDay = t => new Date(t).toISOString().slice(0, 10);   // game day resets at 00:00 UTC (7 pm Colombia)
const r5 = v => Math.round(v * 10000) / 10000;
async function vipTierOf(db, uid, now) { const v = await db.prepare("SELECT until, tier FROM vips WHERE uid = ?").bind(uid).first(); return v && v.until > now ? Math.min(4, Math.max(1, v.tier || 1)) : 0; }
/* the wallet row (made on first use from the frozen copy of what the phone had, with the $2 rule) */
const MAX_ACC_IP = 3;                                        // new accounts per internet connection per day
const isBanned = async (db, uid) => !!(await db.prepare("SELECT 1 AS x FROM ban WHERE uid = ?").bind(uid).first());
async function walGet(db, uid, now, mig, iph) {
  let w = await db.prepare("SELECT * FROM wal WHERE uid = ?").bind(uid).first();
  if (w) return w;
  if (!(await metaGet(db, "walt0"))) {                       // first wallet ever: freeze what every phone had reported
    await db.batch([db.prepare("INSERT OR IGNORE INTO wmig (uid, bal, stk) SELECT uid, bal, stk FROM lbx"), metaSet(db, "walt0", { at: now })]);
  }
  const m = await db.prepare("SELECT bal, stk FROM wmig WHERE uid = ?").bind(uid).first();
  let bal = 0, hold = {}, q = [], stk = [];
  if (m) {
    const L = (() => { try { return JSON.parse(m.stk || "[]"); } catch (e) { return []; } })().filter(x => (x.a || "USD") === "USD" && x.amt > 0 && x.end > now);
    const tot = (+m.bal || 0) + L.reduce((s, x) => s + (+x.amt || 0), 0);
    if (tot <= WAL_MAX0) {
      bal = Math.max(0, +m.bal || 0); stk = L.slice(0, 20);
      let room = Math.min(WAL_HOLD0, WAL_MAX0 - tot);         // coins the phone says it holds (we can't check them, so small cap)
      const H = (mig && typeof mig.hold === "object") ? mig.hold : {};
      for (const [c, v] of Object.entries(H)) { if (!COINS_OK.test(c)) continue; const u = Math.min(room, Math.max(0, +v || 0)); if (u > 0) { hold[c] = r5(u); room -= u; } }
      for (const x of (Array.isArray(mig && mig.cstk) ? mig.cstk : []).slice(0, 10)) { const u = Math.min(room, Math.max(0, +x.amt || 0)); if (u > 0 && COINS_OK.test(x.a || "") && x.end > now) { stk.push({ a: x.a, amt: u, rew: Math.min(u * .06, Math.max(0, +x.rew || 0)), end: x.end, p: x.p }); room -= u; } }
    }
  }
  q.push(db.prepare("INSERT OR IGNORE INTO wal (uid, bal, hold, day, dm, at, mig) VALUES (?, ?, ?, ?, '{}', ?, ?)").bind(uid, bal, JSON.stringify(hold), wDay(now), now, bal));
  if (!m && iph) {                                           // brand-new account: max 3 a day from the same connection
    const c = await db.prepare("SELECT COUNT(*) AS n FROM newacc WHERE iph = ? AND at > ? AND uid != ?").bind(iph, now - 86400000, uid).first();
    q.push(db.prepare("INSERT OR IGNORE INTO newacc (uid, iph, at) VALUES (?, ?, ?)").bind(uid, iph, now));
    if (c && c.n >= MAX_ACC_IP) q.push(db.prepare("INSERT OR IGNORE INTO ban (uid, why, bal, hold, at) VALUES (?, 'ip', 0, '{}', ?)").bind(uid, now));
  }
  stk.forEach((x, i) => q.push(db.prepare("INSERT OR IGNORE INTO wstk (uid, id, asset, amt, rew, p, start, endt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").bind(uid, "m" + i, x.a || "USD", +x.amt, Math.max(0, Math.min(+x.amt * .06, +x.rew || 0)), Math.min(3, int(x.p, 3)), now, +x.end)));
  await db.batch(q);
  return await db.prepare("SELECT * FROM wal WHERE uid = ?").bind(uid).first();
}
/* one-time money in/out (deposit, task, prize, refund, sale, owner adjustment): never applied twice */
function walApply(db, uid, id, u, now) {
  return [db.prepare("UPDATE wal SET bal = MAX(0, bal + ?), inc = inc + MAX(0, ?), at = ? WHERE uid = ? AND NOT EXISTS (SELECT 1 FROM wled WHERE uid = ? AND id = ?)").bind(u, u, now, uid, uid, id),
          db.prepare("INSERT OR IGNORE INTO wled (uid, id, u, at) VALUES (?, ?, ?, ?)").bind(uid, id, u, now)];
}
async function walCredit(db, uid, id, u, now) { if (!uid || !u) return; await walGet(db, uid, now); await db.batch(walApply(db, uid, id, u, now)); }
const MONEY_T = { deposit: 1, task: 1, refund: 1, adj: 1, prize: 1 };
async function walView(db, uid, now) {
  const [w, s, b] = await db.batch([db.prepare("SELECT bal, hold, inc, out, spent, day, n FROM wal WHERE uid = ?").bind(uid), db.prepare("SELECT id, asset, amt, rew, p, start, endt FROM wstk WHERE uid = ? ORDER BY start").bind(uid), db.prepare("SELECT why FROM ban WHERE uid = ?").bind(uid)]);
  const bn = (b.results || [])[0] || null;
  const x = (w.results || [])[0] || { bal: 0, hold: "{}" };
  return { bal: r5(x.bal || 0), hold: (() => { try { return JSON.parse(x.hold || "{}"); } catch (e) { return {}; } })(), stakes: (s.results || []).map(k => ({ id: k.id, asset: k.asset, amt: k.amt, rew: k.rew, p: k.p, start: k.start, end: k.endt })), today: x.day === wDay(now) ? x.n : 0, at: now, ban: bn ? bn.why || "owner" : null };
}
/* finished staking goes back automatically */
async function walStakeDue(db, uid, now) {
  if (await isBanned(db, uid)) return [];
  const r = await db.prepare("SELECT id, asset, amt, rew FROM wstk WHERE uid = ? AND endt <= ?").bind(uid, now).all(), L = r.results || [];
  if (!L.length) return [];
  const w = await db.prepare("SELECT hold FROM wal WHERE uid = ?").bind(uid).first(), hold = JSON.parse((w && w.hold) || "{}");
  let usd = 0; for (const x of L) { if (x.asset === "USD") usd += x.amt + x.rew; else hold[x.asset] = r5((hold[x.asset] || 0) + x.amt + x.rew); }
  const inc = L.reduce((s, x) => s + x.rew, 0);
  await db.batch([db.prepare("UPDATE wal SET bal = bal + ?, hold = ?, inc = inc + ? WHERE uid = ?").bind(usd, JSON.stringify(hold), inc, uid), ...L.map(x => db.prepare("DELETE FROM wstk WHERE uid = ? AND id = ?").bind(uid, x.id))]);
  return L;
}
async function walEarn(db, uid, w, items, now) {             // the ads the player watched since the last call
  if (await isBanned(db, uid)) return { add: 0, took: 0, banned: true };
  const day = wDay(now); let dm = {}, n = 0;
  if (w.day === day) { try { dm = JSON.parse(w.dm || "{}"); } catch (e) {} n = w.n || 0; }
  const m = VIP_M[await vipTierOf(db, uid, now)], since = Math.max(0, now - (w.last || 0));
  let allow = 4 + Math.floor(since / 4000), add = 0, took = 0;   // at most 1 ad every 4 seconds (server clock)
  for (const it of (Array.isArray(items) ? items : []).slice(0, 80)) {
    if (allow <= 0 || n >= 260) break;
    const wd = W_OK.includes(it.w) ? it.w : null, c = +it.n; if (!wd || !Number.isInteger(c) || c < 1 || c > 25) continue;
    const k = wd + ":" + c, ch = (wd === "main" ? MAIN_CH : BW_CH)[c] || 0, bon = Math.min(100, Math.max(0, +it.b || 0));
    const cur = Array.isArray(dm[k]) ? dm[k] : [+dm[k] || 0, dm[k] ? 1 : 0], maxN = wd !== "main" && c === 17 ? 2 : 1;   // each circle pays once a day
    const cap = (10 + ch) * m * (1 + bon / 100), left = cap - cur[0]; if (left <= 1e-6 || cur[1] >= maxN) continue;
    const g = r5(Math.min(left, Math.max(0, +it.u || 0))); if (g <= 0) continue;
    dm[k] = [r5(cur[0] + g), cur[1] + 1]; add += g; n++; allow--; took++;
  }
  const q = [db.prepare("UPDATE wal SET bal = bal + ?, inc = inc + ?, day = ?, dm = ?, n = ?, last = ?, at = ? WHERE uid = ?").bind(add, add, day, JSON.stringify(dm), n, now, now, uid)];
  if (add > 0) {                                             // whoever invited him gets his % right away (10-30% by VIP level)
    const by = await db.prepare("SELECT by FROM refs WHERE uid = ?").bind(uid).first();
    if (by && by.by && by.by !== uid && !(await isBanned(db, by.by))) {
      await walGet(db, by.by, now);
      const com = r5(add * REF_T[await vipTierOf(db, by.by, now)] / 100);
      q.push(db.prepare("UPDATE wal SET bal = bal + ?, inc = inc + ? WHERE uid = ?").bind(com, com, by.by),
             db.prepare("INSERT INTO refearn (uid, by, base, total, at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(uid) DO UPDATE SET by = excluded.by, base = refearn.base + excluded.base, total = refearn.total + excluded.total, at = excluded.at").bind(uid, by.by, add, com, now));
    }
  }
  await db.batch(q);
  return { add: r5(add), took };
}
async function walOp(db, uid, op, now) {                     // spend / stake / unstake / swap / change coin
  if (await isBanned(db, uid)) return { error: "banned" };
  const w = await db.prepare("SELECT bal, hold FROM wal WHERE uid = ?").bind(uid).first(); if (!w) return { error: "nowal" };
  const hold = JSON.parse(w.hold || "{}"), src = a => a === "USD" ? w.bal : (hold[a] || 0);
  if (op.k === "spend") {
    const u = Math.max(0, Math.min(1e8, +op.u || 0)); if (!u) return { error: "bad" };
    const r = await db.prepare("UPDATE wal SET bal = bal - ?, spent = spent + ?, at = ? WHERE uid = ? AND bal >= ?").bind(u, u, now, uid, u - 1e-6).run();
    return r.meta && r.meta.changes ? {} : { error: "nobal" };
  }
  if (op.k === "stake") {
    const a = op.a === "USD" ? "USD" : (COINS_OK.test(op.a || "") ? op.a : null), p = int(op.p, 3), u = r5(Math.max(0, +op.u || 0));
    if (!a || !STK[p] || u < 100 || u > src(a) + 1e-6) return { error: u < 100 ? "min" : "nobal" };
    const rew = a === "USD" ? Math.floor(u * STK[p].r) : r5(u * STK[p].r), id = now.toString(36) + Math.random().toString(36).slice(2, 5);
    if (a === "USD") w.bal -= u; else hold[a] = r5(hold[a] - u);
    await db.batch([db.prepare("UPDATE wal SET bal = ?, hold = ?, at = ? WHERE uid = ?").bind(w.bal, JSON.stringify(hold), now, uid),
      db.prepare("INSERT INTO wstk (uid, id, asset, amt, rew, p, start, endt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").bind(uid, id, a, u, rew, p, now, now + STK[p].d * 86400000)]);
    return { id };
  }
  if (op.k === "unstake") {                                  // early = only the amount comes back
    const x = await db.prepare("SELECT asset, amt, rew, endt FROM wstk WHERE uid = ? AND id = ?").bind(uid, str(op.id, 20)).first(); if (!x) return { error: "gone" };
    const back = x.amt + (x.endt <= now ? x.rew : 0);
    if (x.asset === "USD") w.bal += back; else hold[x.asset] = r5((hold[x.asset] || 0) + back);
    await db.batch([db.prepare("UPDATE wal SET bal = ?, hold = ?, inc = inc + ?, at = ? WHERE uid = ?").bind(w.bal, JSON.stringify(hold), x.endt <= now ? x.rew : 0, now, uid), db.prepare("DELETE FROM wstk WHERE uid = ? AND id = ?").bind(uid, str(op.id, 20))]);
    return { back };
  }
  if (op.k === "swap") {                                     // 2% fee; amounts in USD units
    const f = op.f === "USD" ? "USD" : (COINS_OK.test(op.f || "") ? op.f : null), t = op.t === "USD" ? "USD" : (COINS_OK.test(op.t || "") ? op.t : null), u = r5(Math.max(0, +op.u || 0));
    if (!f || !t || f === t || u < 10 || u > src(f) + 1e-6) return { error: "nobal" };
    const out = r5(u * 0.98);
    if (f === "USD") w.bal -= u; else hold[f] = r5(Math.max(0, hold[f] - u));
    if (t === "USD") w.bal += out; else hold[t] = r5((hold[t] || 0) + out);
    await db.prepare("UPDATE wal SET bal = ?, hold = ?, at = ? WHERE uid = ?").bind(w.bal, JSON.stringify(hold), now, uid).run();
    return { out };
  }
  if (op.k === "coin") {                                     // new payout coin: what was earned stays in the old coin
    const c = COINS_OK.test(op.c || "") ? op.c : null; if (!c) return { error: "bad" };
    if (w.bal > 0) { hold[c] = r5((hold[c] || 0) + w.bal); await db.prepare("UPDATE wal SET bal = 0, hold = ?, at = ? WHERE uid = ?").bind(JSON.stringify(hold), now, uid).run(); }
    return {};
  }
  return { error: "bad" };
}
async function nftPost(a, db, me, body, now) {
  const id = int(body.id, NFT_MAX);
  if (a === "mine") {                                      // my NFTs + money from my NFTs that were sold
    const [up, my] = await db.batch([
      db.prepare("UPDATE sales SET claimed = 1, cat = ? WHERE seller = ? AND claimed = 0").bind(now, me.uid),
      db.prepare("SELECT id FROM nfts WHERE owner = ?").bind(me.uid)
    ]);
    let sold = [];
    if (up.meta && up.meta.changes) sold = (await db.prepare("SELECT nft, units, gets, at FROM sales WHERE seller = ? AND cat = ?").bind(me.uid, now).all()).results || [];
    if (sold.length && !me.anon) { await walGet(db, me.uid, now); await db.batch(sold.flatMap(x => walApply(db, me.uid, "sale-" + x.nft + "-" + x.at, +x.gets || 0, now))); }   // same id as at sale time: never paid twice
    return { my: (my.results || []).map(x => x.id), sold };
  }
  if (a === "claim") {                                     // chest / welcome gift: a random free NFT from the allowed pool
    const cand = [...new Set((body.ids || []).map(x => int(x, NFT_MAX)).filter(x => x > 0))];
    const taken = new Set(((await db.prepare("SELECT id FROM nfts WHERE owner IS NOT NULL AND owner != ''").all()).results || []).map(x => x.id));
    const free = cand.filter(x => !taken.has(x));
    for (let i = free.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [free[i], free[j]] = [free[j], free[i]]; }
    for (const n of free.slice(0, 6)) {
      const r = await db.prepare("INSERT INTO nfts (id, owner, trades, at) VALUES (?, ?, 0, ?) ON CONFLICT(id) DO UPDATE SET owner = excluded.owner, at = excluded.at WHERE nfts.owner IS NULL OR nfts.owner = ''").bind(n, me.uid, now).run();
      if (r.meta && r.meta.changes) { await dropNft(db).run(); return { id: n }; }
    }
    return { id: free.length ? null : 0 };
  }
  if (a === "ensure") {                                    // NFTs this phone got while offline: keep them if still free
    const ids = [...new Set((body.ids || []).map(x => int(x, NFT_MAX)).filter(x => x > 0))].slice(0, 20); const got = [];
    for (const n of ids) {
      await db.prepare("INSERT INTO nfts (id, owner, trades, at) VALUES (?, ?, 0, ?) ON CONFLICT(id) DO UPDATE SET owner = excluded.owner WHERE nfts.owner IS NULL OR nfts.owner = ''").bind(n, me.uid, now).run();
      const o = await db.prepare("SELECT owner FROM nfts WHERE id = ?").bind(n).first(); if (o && o.owner === me.uid) got.push(n);
    }
    if (ids.length) await dropNft(db).run();
    return { got };
  }
  if (a === "list") {
    const units = int(body.units, 1e7); if (!id || units < 1) return { error: "bad" };
    const o = await db.prepare("SELECT owner FROM nfts WHERE id = ?").bind(id).first(); if (!o || o.owner !== me.uid) return { error: "not_owner" };
    await db.batch([db.prepare("INSERT INTO market (nft, seller, units, status, promo, at, buyer, soldAt) VALUES (?, ?, ?, 'open', 0, ?, NULL, NULL) ON CONFLICT(nft) DO UPDATE SET seller = excluded.seller, units = excluded.units, status = 'open', promo = 0, at = excluded.at, buyer = NULL, soldAt = NULL").bind(id, me.uid, units, now), dropNft(db)]);
    return {};
  }
  if (a === "cancel" || a === "promote") {
    const q = a === "cancel" ? db.prepare("UPDATE market SET status = 'cancelled' WHERE nft = ? AND seller = ? AND status = 'open'").bind(id, me.uid)
      : db.prepare("UPDATE market SET promo = ? WHERE nft = ? AND seller = ? AND status = 'open'").bind(Math.min(int(body.until, 9e15), now + 7 * 86400000), id, me.uid);
    const [r] = await db.batch([q, dropNft(db)]);
    return r.meta && r.meta.changes ? {} : { error: "gone" };
  }
  if (a === "buy") {                                       // all-or-nothing: listing -> sold, sale record, new owner
    const units = int(body.units, 1e7), fee = Math.ceil(units * NFT_FEE / 100);
    if (!units) return { error: "bad" };
    await walGet(db, me.uid, now);                           // the buyer pays from the server wallet first
    const sp = await walOp(db, me.uid, { k: "spend", u: units }, now); if (sp.error) return { error: "nobal" };
    const [r] = await db.batch([
      db.prepare("UPDATE market SET status = 'sold', buyer = ?, soldAt = ? WHERE nft = ? AND status = 'open' AND seller != ? AND units = ? AND seller = (SELECT owner FROM nfts WHERE id = ?)").bind(me.uid, now, id, me.uid, units, id),
      db.prepare("INSERT INTO sales (nft, seller, buyer, units, fee, gets, at, claimed) SELECT nft, seller, buyer, units, ?, ?, soldAt, 0 FROM market WHERE nft = ? AND buyer = ? AND soldAt = ? AND status = 'sold'").bind(fee, units - fee, id, me.uid, now),
      db.prepare("UPDATE nfts SET prev = owner, owner = ?, trades = trades + 1, at = ? WHERE id = ? AND EXISTS (SELECT 1 FROM market WHERE nft = ? AND buyer = ? AND soldAt = ? AND status = 'sold')").bind(me.uid, now, id, id, me.uid, now),
      /* running total of market fees (so nobody has to add up every sale) */
      db.prepare("INSERT INTO meta (k, v, at) SELECT 'fee', json_object('sum', ?, 'n', 1), ? WHERE EXISTS (SELECT 1 FROM market WHERE nft = ? AND buyer = ? AND soldAt = ?) ON CONFLICT(k) DO UPDATE SET v = json_object('sum', json_extract(meta.v, '$.sum') + ?, 'n', json_extract(meta.v, '$.n') + 1), at = excluded.at").bind(fee, now, id, me.uid, now, fee),
      dropNft(db)
    ]);
    if (!(r.meta && r.meta.changes)) { await db.batch(walApply(db, me.uid, "nftback-" + id + "-" + now, units, now)); return { error: "gone" }; }   // not sold: money back
    const sl = await db.prepare("SELECT seller FROM market WHERE nft = ? AND buyer = ? AND soldAt = ?").bind(id, me.uid, now).first();
    if (sl && sl.seller) await walCredit(db, sl.seller, "sale-" + id + "-" + now, units - fee, now);     // the seller is paid right away
    return { fee, units, w: await walView(db, me.uid, now) };
  }
  if (a === "wgrant") {                                    // world NFT (only 1 owner each) — paid from the server wallet
    if (!id) return { error: "bad" };
    const u = int(body.units, 1e8);
    if (u > 0) { await walGet(db, me.uid, now); const sp = await walOp(db, me.uid, { k: "spend", u }, now); if (sp.error) return { error: "nobal" }; }
    await db.prepare("INSERT OR IGNORE INTO wnft (id, owner, at) VALUES (?, ?, ?)").bind(id, me.uid, now).run();
    const o = await db.prepare("SELECT owner FROM wnft WHERE id = ?").bind(id).first();
    await dropNft(db).run();
    if (!(o && o.owner === me.uid)) { if (u > 0) await db.batch(walApply(db, me.uid, "wback-" + id + "-" + now, u, now)); return { error: "sold" }; }
    return {};
  }
  if (a === "nftimport") {                                 // owner: copy from Firebase (small pieces)
    if (!me.owner) return { error: "owner" };
    const q = [];
    for (const x of (body.nfts || []).slice(0, 45)) if (x.owner) q.push(db.prepare("INSERT INTO nfts (id, owner, trades, prev, at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING").bind(int(x.id, NFT_MAX), str(x.owner, 64), int(x.trades, 1e6), str(x.from, 64), int(x.at, 9e15)));
    for (const x of (body.market || []).slice(0, 45)) q.push(db.prepare("INSERT INTO market (nft, seller, units, status, promo, at) VALUES (?, ?, ?, 'open', ?, ?) ON CONFLICT(nft) DO NOTHING").bind(int(x.nft, NFT_MAX), str(x.seller, 64), int(x.units, 1e7), int(x.promotedUntil, 9e15), int(x.at, 9e15)));
    for (const x of (body.sales || []).slice(0, 45)) q.push(db.prepare("INSERT INTO sales (nft, seller, buyer, units, fee, gets, at, claimed) SELECT ?, ?, ?, ?, ?, ?, ?, 0 WHERE NOT EXISTS (SELECT 1 FROM sales WHERE nft = ? AND at = ?)").bind(int(x.nft, NFT_MAX), str(x.seller, 64), str(x.buyer, 64), int(x.units, 1e7), int(x.fee, 1e7), int(x.sellerGets, 1e7), int(x.at, 9e15), int(x.nft, NFT_MAX), int(x.at, 9e15)));
    for (const x of (body.w || []).slice(0, 45)) if (x.owner) q.push(db.prepare("INSERT OR IGNORE INTO wnft (id, owner, at) VALUES (?, ?, ?)").bind(int(x.id, 1000), str(x.owner, 64), int(x.at, 9e15)));
    if (body.done) q.push(metaSet(db, "nftimp", 1));
    q.push(dropNft(db));
    await db.batch(q);
    return { n: q.length };
  }
  return null;
}

/* ===== Paid visits: a referrer earns 1 unit ($0.00001) for each different visitor (1 per internet connection per day, max VIS_CAP a day) ===== */
const VIS_CAP = 3000;
const today = now => new Date(now - BOG).toISOString().slice(0, 10);
async function sha(x) { const h = await crypto.subtle.digest("SHA-256", enc.encode(x)); return [...new Uint8Array(h)].slice(0, 10).map(b => b.toString(16).padStart(2, "0")).join(""); }
async function visit(db, me, body, request, env, now) {
  const code = str(body.code, 8).toUpperCase().replace(/[^A-Z0-9]/g, ""); if (code.length < 4) return { counted: false };
  const ua = request.headers.get("user-agent") || ""; if (!ua || /bot|crawl|spider|headless|curl|wget|python|preview/i.test(ua)) return { counted: false };
  const ref = await db.prepare("SELECT uid FROM lb WHERE code = ? LIMIT 1").bind(code).first();
  if (!ref || ref.uid === me.uid) return { counted: false };
  const day = today(now), ip = request.headers.get("cf-connecting-ip") || "";
  if (!ip) return { counted: false };
  const iph = await sha(ip + "|" + day + "|" + (env.ADSLAB_SECRET || "dia"));
  const ins = await db.prepare("INSERT OR IGNORE INTO refvis (day, iph) VALUES (?, ?)").bind(day, iph).run();
  if (!(ins.meta && ins.meta.changes)) return { counted: false };            // this connection already counted today
  const r = await db.prepare("INSERT INTO visits (uid, day, n, paid) VALUES (?, ?, 1, 0) ON CONFLICT(uid, day) DO UPDATE SET n = n + 1 WHERE visits.n < ?").bind(ref.uid, day, VIS_CAP).run();
  const counted = !!(r.meta && r.meta.changes);
  if (counted) await db.prepare("INSERT INTO vislog (at, uid, kind, via) VALUES (?, ?, 'visit', '')").bind(now, ref.uid).run();
  if (Math.random() < 0.01) await db.batch([db.prepare("DELETE FROM refvis WHERE day < ?").bind(today(now - 2 * 86400000)), db.prepare("DELETE FROM vislog WHERE at < ?").bind(now - 2 * 86400000)]);
  return { counted };
}
async function visStats(db, uid, now) {
  const r = await db.prepare("SELECT day, n, paid FROM visits WHERE uid = ?").bind(uid).all(), d = today(now);
  let total = 0, td = 0; for (const x of r.results || []) { total += x.n; if (x.day === d) td = x.n; }
  return { today: td, total, cap: VIS_CAP };
}

async function d1(request, env) {
  const db = env.DB; if (!db) return json({ ok: false, error: "no_db" }, 503);
  await d1Init(db);
  const url = new URL(request.url), a = url.searchParams.get("a");
  let body = {}; if (request.method === "POST") { try { body = JSON.parse(await request.text()); } catch (e) {} }
  if (a === "comp") {
    const week = url.searchParams.get("week") || weekKey(), fs = +url.searchParams.get("fs") || 0, fe = +url.searchParams.get("fe") || 0;
    const mo = /^\d{4}-\d{2}$/.test(url.searchParams.get("mo") || "") ? url.searchParams.get("mo") : "";
    if (!/^\d{4}-\d{2}-\d{2}$/.test(week) || Math.abs(Date.parse(week) - Date.now()) > 40 * 86400000 || Math.abs(fs - Date.now()) > 40 * 86400000 || fe <= fs || fe - fs > 17 * 86400000) return json({ ok: false, error: "bad" }, 400);
    const key = "comp:" + week + ":" + fs + ":" + mo, old = await metaGet(db, key), cur = week === weekKey() && (!mo || mo === today(Date.now()).slice(0, 7));
    const moEnd = mo ? Date.parse((mo.slice(5) === "12" ? (+mo.slice(0, 4) + 1) + "-01" : mo.slice(0, 5) + String(+mo.slice(5) + 1).padStart(2, "0")) + "-01") + BOG : 0;
    const fin = Math.max(Date.parse(week) + 7 * 86400000 + BOG, fe, moEnd) + 600000;   // a past week/month is final 10 min after it ends
    if (old && (cur ? Date.now() - old.at < 600000 : old.at > fin)) return json({ ok: true, ...old.v, at: old.at, imp: !!(await metaGet(db, "imported")) });
    const snap = await buildComp(db, week, fs, fe, mo);
    await metaSet(db, key, snap).run();
    return json({ ok: true, ...snap, at: Date.now(), imp: !!(await metaGet(db, "imported")) });
  }
  if (a === "proofs") {
    const old = await metaGet(db, "proofs");
    if (old && Date.now() - old.at < 30 * 60000) return json({ ok: true, ...old.v, at: old.at });   // a new payment clears it right away
    const cut = Date.now() - 30 * 86400000;
    const p = await db.prepare("SELECT at, coin, method, usd, amt, who, code FROM proofs WHERE at >= ? ORDER BY at DESC LIMIT 40").bind(cut).all();
    const st = await metaGet(db, "stats"), n = await db.prepare("SELECT COUNT(*) AS n FROM lb").first();
    const snap = { p: (p.results || []).map(x => ({ at: x.at, coin: x.coin, method: x.method, amountUsd: x.usd, amountCoin: x.amt, who: x.who, code: x.code })), s: st ? st.v : null, n: Math.max(n ? n.n : 0, (st && st.v && st.v.players) || 0) };
    await metaSet(db, "proofs", snap).run();
    return json({ ok: true, ...snap, at: Date.now() });
  }
  if (a === "nft") return json({ ok: true, ...(await nftSnap(db)) });
  if (a === "cfg") {                                      // game settings (coins on/off, accounts, ads, banners): 1 call instead of 4 Firebase reads
    const r = await db.prepare("SELECT k, v FROM meta WHERE k IN ('cfg:coins', 'cfg:main', 'cfg:ads', 'cfg:xbans')").all();
    const o = {}; for (const x of r.results || []) o[x.k.slice(4)] = JSON.parse(x.v);
    return json({ ok: true, ...o });
  }
  if (a === "dl") { const m = await metaGet(db, "dlinks"); return json({ ok: true, set: !!m, ...((m && m.v) || { on: false, links: [], label: "" }) }); }
  if (request.method !== "POST") return json({ ok: false, error: "bad_request" }, 400);
  let me; try { me = await who(body.t); } catch (e) { return json({ ok: false, error: String(e.message || e) }, 401); }
  const now = Date.now();
  { const r = await nftPost(a, db, me, body, now); if (r) return json(r.error ? { ok: false, ...r } : { ok: true, ...r }, r.error === "owner" ? 403 : 200); }
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
    if (body.refBy && body.refBase > 0) {                   // what this player earned for the one who invited them (10% is paid from it)
      const by = str(body.refBy, 64).replace(/[^A-Za-z0-9]/g, "");
      if (by && by !== me.uid) q.push(db.prepare("INSERT INTO refearn (uid, by, base, total, at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(uid) DO UPDATE SET base = MAX(refearn.base, excluded.base), total = MAX(refearn.total, excluded.total), at = excluded.at")
        .bind(me.uid, by, Math.min(1e9, +body.refBase || 0), Math.min(1e9, +body.refOwed || 0), now));
    }
    if (body.day) q.push(db.prepare("INSERT INTO lbd (uid, day, td) VALUES (?, ?, ?) ON CONFLICT(uid, day) DO UPDATE SET td = MAX(lbd.td, excluded.td)").bind(me.uid, str(body.day, 10), int(body.td, 1000)));
    if (body.x && typeof body.x === "object") q.push(db.prepare("INSERT INTO lbx (uid, bal, staked, dmt, dev, stk, at, fx, fxn, fm, fmn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(uid) DO UPDATE SET bal = excluded.bal, staked = excluded.staked, dmt = excluded.dmt, dev = excluded.dev, stk = excluded.stk, at = excluded.at, fx = excluded.fx, fxn = excluded.fxn, fm = excluded.fm, fmn = excluded.fmn")
      .bind(me.uid, int(body.x.bal, 1e12), int(body.x.staked, 1e12), Math.max(0, Math.min(1e12, Math.round((+body.x.dmt || 0) * 100) / 100)), str(body.x.dev, 40), JSON.stringify(Array.isArray(body.x.stk) ? body.x.stk.slice(0, 20) : []).slice(0, 4000), now,
        Math.max(0, Math.min(1e6, +body.x.fx || 0)), int(body.x.fxn, 1e9), int(body.x.fm, 1e12), int(body.x.fmn, 1e9)));
    if (body.x && body.x.cl > 0) q.push(db.prepare("INSERT INTO lbc (uid, cl, at) VALUES (?, ?, ?) ON CONFLICT(uid) DO UPDATE SET cl = MAX(lbc.cl, excluded.cl), at = excluded.at").bind(me.uid, int(body.x.cl, 1e7), now));
    const d7 = today(now - 7 * 86400000);
    q.push(db.prepare("SELECT COALESCE(SUM(n - paid), 0) AS v FROM visits WHERE uid = ? AND day >= ? AND n > paid").bind(me.uid, d7));
    q.push(db.prepare("UPDATE visits SET paid = n WHERE uid = ? AND day >= ? AND n > paid").bind(me.uid, d7));
    const res = await db.batch(q), vr = res[res.length - 2], vis = ((vr.results || [])[0] || {}).v || 0;
    if (vis > 0) await walCredit(db, me.uid, "vis-" + now, vis, now);    // paid visits go straight into the wallet
    return json({ ok: true, vis });
  }
  if (a === "wal") {                                       // the wallet: ads watched (q) + one action (op) -> real balance
    if (me.anon) return json({ ok: false, error: "register" }, 403);
    const ip = request.headers.get("cf-connecting-ip") || "", iph = ip ? await sha(ip + "|acc|" + (env.ADSLAB_SECRET || "dia")) : "";
    const w = await walGet(db, me.uid, now, body.mig, iph), due = await walStakeDue(db, me.uid, now);
    const e = Array.isArray(body.q) && body.q.length ? await walEarn(db, me.uid, w, body.q, now) : { add: 0, took: 0 };
    const o = body.op && typeof body.op === "object" ? await walOp(db, me.uid, body.op, now) : null;
    return json({ ok: true, add: e.add, took: e.took, due: due.length, op: o, w: await walView(db, me.uid, now) });
  }
  if (a === "ref") {                                       // "player X was invited by Y"
    const by = str(body.by, 64).replace(/[^A-Za-z0-9]/g, "");
    if (!by || by === me.uid) return json({ ok: false, error: "bad" }, 400);
    await db.prepare("INSERT OR IGNORE INTO refs (uid, by, at, via) VALUES (?, ?, ?, ?)").bind(me.uid, by, now, str(body.via, 10) || "code").run();
    return json({ ok: true });
  }
  if (a === "visit") return json({ ok: true, ...(await visit(db, me, body, request, env, now)) });
  if (a === "visstats") return json({ ok: true, ...(await visStats(db, me.uid, now)) });
  if (a === "dlclick") {                                   // tap on the Direct Link button (which link of the rotation)
    const i = int(body.i, 19); const day = today(now);
    await db.prepare("INSERT INTO offstat (day, k, e, n) VALUES (?, 'dl', ?, 1) ON CONFLICT(day, k, e) DO UPDATE SET n = n + 1").bind(day, String(i)).run();
    return json({ ok: true });
  }
  if (a === "setdl") {                                     // owner: Direct Links list
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const links = (Array.isArray(body.links) ? body.links : []).map(x => str(x, 500).trim()).filter(x => /^https:\/\/[^\s"'<>]+$/.test(x)).slice(0, 20);
    const v = { on: !!body.on && links.length > 0, links, label: str(body.label, 30) };
    await metaSet(db, "dlinks", v).run();
    return json({ ok: true, ...v });
  }
  if (a === "share") {                                     // a player tapped copy / WhatsApp / Telegram / Facebook / share
    const via = ["copy", "wa", "tg", "fb", "native", "banner"].includes(body.via) ? body.via : "native";
    await db.prepare("INSERT INTO vislog (at, uid, kind, via) VALUES (?, ?, 'share', ?)").bind(now, me.uid, via).run();
    return json({ ok: true });
  }
  if (a === "reflive") {                                   // owner: live view of who shares the link and who gets visits
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const d = today(now), since = now - 24 * 3600000;
    const [top, feed, sh] = await db.batch([
      db.prepare("SELECT uid, n FROM visits WHERE day = ? ORDER BY n DESC LIMIT 20").bind(d),
      db.prepare("SELECT at, uid, kind, via FROM vislog WHERE at >= ? ORDER BY at DESC LIMIT 25").bind(since),
      db.prepare("SELECT COUNT(*) AS n, COUNT(DISTINCT uid) AS u FROM vislog WHERE at >= ? AND kind = 'share'").bind(since)
    ]);
    const snap = { names: {}, heroes: {}, vips: {} };
    await namesFor(db, [...(top.results || []), ...(feed.results || [])].map(x => x.uid), snap);
    const tv = await db.prepare("SELECT COALESCE(SUM(n), 0) AS n, COUNT(*) AS u FROM visits WHERE day = ?").bind(d).first();
    return json({ ok: true, top: top.results || [], feed: feed.results || [], names: snap.names, visits: tv ? tv.n : 0, referrers: tv ? tv.u : 0, shares: ((sh.results || [])[0] || {}).n || 0, sharers: ((sh.results || [])[0] || {}).u || 0 });
  }
  if (a === "myrefs") {                                    // my referrals' earnings (+ the list every 10-30 min) + who invited me
    const q = [db.prepare("SELECT uid, base, total FROM refearn WHERE by = ?").bind(me.uid),
               db.prepare("SELECT r.by, l.code FROM refs r LEFT JOIN lb l ON l.uid = r.by WHERE r.uid = ?").bind(me.uid)];
    if (body.list) q.push(db.prepare("SELECT r.uid, r.at, r.via, l.nick, l.code, l.seen FROM refs r LEFT JOIN lb l ON l.uid = r.uid WHERE r.by = ? ORDER BY r.at DESC LIMIT 300").bind(me.uid),
                          db.prepare("SELECT COUNT(*) AS n FROM refs WHERE by = ?").bind(me.uid));
    const res = await db.batch(q), me2 = (res[1].results || [])[0] || null;
    return json({ ok: true, earn: res[0].results || [], by: me2 ? me2.by : null, byCode: me2 ? me2.code : null,
      list: body.list ? res[2].results || [] : null, n: body.list ? ((res[3].results || [])[0] || {}).n || 0 : null });
  }
  if (a === "setcfg") {                                    // owner saves game settings
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const k = String(body.k || ""); if (!["coins", "main", "ads", "xbans"].includes(k)) return json({ ok: false, error: "bad" }, 400);
    const v = JSON.stringify(body.v || {}); if (v.length > 400000) return json({ ok: false, error: "too_big" }, 400);
    await db.prepare("INSERT INTO meta (k, v, at) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, at = excluded.at").bind("cfg:" + k, v, now).run();
    return json({ ok: true });
  }
  /* ---- withdrawals, purchases, VIP and credits (moved from Firebase) ---- */
  const J = v => { try { return JSON.parse(v); } catch (e) { return {}; } };
  if (a === "payreq") {                                    // player asks for a withdrawal (one per game day; again only if it was refunded)
    if (me.anon) return json({ ok: false, error: "register" }, 403);
    const r0 = body.req || {}, date = str(r0.date, 10); if (!date) return json({ ok: false, error: "bad" }, 400);
    const lim = await getLim(db), coin = COINS_OK.test(r0.coin || "") ? r0.coin : "";
    if (!coin) return json({ ok: false, error: "bad" }, 400);
    const old = await db.prepare("SELECT st FROM pays WHERE uid = ? AND date = ?").bind(me.uid, date).first();
    if (old && old.st !== "refunded") return json({ ok: true, n: 0, dup: true });
    await walGet(db, me.uid, now); await walStakeDue(db, me.uid, now);
    if (await isBanned(db, me.uid)) return json({ ok: false, error: "banned" }, 403);
    const w = await db.prepare("SELECT bal, hold FROM wal WHERE uid = ?").bind(me.uid).first(), hold = JSON.parse(w.hold || "{}");
    const have = (w.bal || 0) + (hold[coin] || 0), units = Math.floor(Math.min(have, lim.pay * 1e5));   // the server balance, max the limit per withdrawal
    if (units < 1) return json({ ok: false, error: "nobal" }, 400);
    const fromHold = Math.min(hold[coin] || 0, units), fromBal = units - fromHold; hold[coin] = r5((hold[coin] || 0) - fromHold); if (hold[coin] <= 0) delete hold[coin];
    const pr = +r0.priceUsd > 0 ? +r0.priceUsd : 0, amountUsd = (units / 1e5).toFixed(5);
    const d = JSON.stringify({ ...r0, amountUsd, units, holdCoin: 0, amountCoin: pr ? +(units / 1e5 / pr).toFixed(8) : null, status: "pending", srv: 1 }).slice(0, 6000);
    const r = await db.batch([db.prepare("UPDATE wal SET bal = bal - ?, hold = ?, out = out + ?, at = ? WHERE uid = ? AND bal >= ?").bind(fromBal, JSON.stringify(hold), units, now, me.uid, fromBal - 1e-6),
      db.prepare("INSERT INTO pays (uid, date, st, at, d) SELECT ?, ?, 'pending', ?, ? WHERE changes() > 0 ON CONFLICT(uid, date) DO UPDATE SET st = 'pending', at = excluded.at, d = excluded.d WHERE pays.st = 'refunded'").bind(me.uid, date, now, d)]);
    if (!(r[0].meta && r[0].meta.changes)) return json({ ok: false, error: "nobal" }, 400);
    const n = (r[1].meta && r[1].meta.changes) || 0;
    return json({ ok: true, n, units, amountUsd, w: await walView(db, me.uid, now) });
  }
  if (a === "mypays") {
    const r = await db.prepare("SELECT date, st FROM pays WHERE uid = ? ORDER BY at DESC LIMIT 60").bind(me.uid).all();
    return json({ ok: true, list: r.results || [] });
  }
  if (a === "order") {                                     // player purchase waiting for the owner (crypto / FaucetPay / Cwallet / balance)
    const o = body.ord || {}, id = str(o.id, 60); if (!id) return json({ ok: false, error: "bad" }, 400);
    await db.prepare("INSERT OR IGNORE INTO ords (uid, id, st, at, d) VALUES (?, ?, 'pending', ?, ?)").bind(me.uid, id, now, JSON.stringify(o).slice(0, 6000)).run();
    return json({ ok: true });
  }
  if (a === "vipreq") {
    const v = body.req || {};
    let bal = v.method === "balance" && v.status === "active";
    if (bal) { const tier = Math.max(1, int(v.tier, 4)); await walGet(db, me.uid, now); const sp = await walOp(db, me.uid, { k: "spend", u: Math.round(VIP_USD[tier - 1] * 1e5) }, now); if (sp.error) return json({ ok: false, error: "nobal" }, 400); }
    const st = bal ? "active" : "pending";   // players can't mark their own crypto payment as approved
    const q = [db.prepare("INSERT INTO vreq (uid, st, at, d) VALUES (?, ?, ?, ?) ON CONFLICT(uid) DO UPDATE SET st = excluded.st, at = excluded.at, d = excluded.d").bind(me.uid, st, now, JSON.stringify({ ...v, status: st }).slice(0, 3000))];
    if (bal) q.push(db.prepare("INSERT INTO vips (uid, until, tier, at) VALUES (?, ?, ?, ?) ON CONFLICT(uid) DO UPDATE SET until = excluded.until, tier = excluded.tier, at = excluded.at").bind(me.uid, now + 365 * 86400000, Math.max(1, int(v.tier, 4)), now));
    await db.batch(q);
    return json({ ok: true });
  }
  if (a === "mylvl") {                                    // the player's level backup: highest claim count ever saved, or the sum of his weekly ads
    const [c, w] = await db.batch([db.prepare("SELECT cl FROM lbc WHERE uid = ?").bind(me.uid), db.prepare("SELECT COALESCE(SUM(ads), 0) AS n FROM lbw WHERE uid = ?").bind(me.uid)]);
    const cl = ((c.results || [])[0] || {}).cl || 0, sw = ((w.results || [])[0] || {}).n || 0;
    return json({ ok: true, cl: Math.max(cl, sw) });
  }
  if (a === "myvip") {
    const [v, q] = await db.batch([db.prepare("SELECT until, tier FROM vips WHERE uid = ?").bind(me.uid), db.prepare("SELECT st, d FROM vreq WHERE uid = ?").bind(me.uid)]);
    const vv = (v.results || [])[0] || null, qq = (q.results || [])[0] || null;
    return json({ ok: true, vip: vv, req: qq ? { ...J(qq.d), status: qq.st } : null, imp2: !!(await metaGet(db, "imp2")) });
  }
  if (a === "mycreds") {                                   // new credits since a time (deposits, approved purchases, refunds, prizes, tasks)
    const r = await db.prepare("SELECT id, at, d FROM creds WHERE uid = ? AND at >= ? ORDER BY at LIMIT 200").bind(me.uid, Math.max(0, +body.since || 0)).all();
    return json({ ok: true, list: (r.results || []).map(x => ({ id: x.id, at: x.at, ...J(x.d) })) });
  }
  if (["adm", "paystat", "ordstat", "vipset", "credit", "adjust", "seclim", "purge", "setpaid", "ban", "nftsales", "nftfix", "prizes", "prizeset", "acct", "imp2", "risk", "assignrefs"].includes(a)) {
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const cred = (uid, id, d) => db.prepare("INSERT OR IGNORE INTO creds (uid, id, at, d) VALUES (?, ?, ?, ?)").bind(str(uid, 64), str(id, 90), now, JSON.stringify({ ...d, at: now }).slice(0, 3000));
    if (a === "adm") {                                     // everything waiting for the owner
      const tg = await db.prepare("SELECT at, uid, st, reward FROM tlog ORDER BY at DESC, rowid DESC LIMIT 8").all();
      const [p, o, v, tk, tl] = await db.batch([
        db.prepare("SELECT uid, date, at, d FROM pays WHERE st = 'pending' ORDER BY at LIMIT 300"),
        db.prepare("SELECT uid, id, at, d FROM ords WHERE st = 'pending' ORDER BY at LIMIT 300"),
        db.prepare("SELECT uid, at, d FROM vreq WHERE st = 'pending' ORDER BY at LIMIT 100"),
        db.prepare("SELECT 0 AS n"), db.prepare("SELECT 0 AS n")
      ]);
      let tsm = await metaGet(db, "taskstat");                // the tasks summary reads the whole credits table: at most once every 10 min
      if (!tsm || now - tsm.at > 600000) {
        const [a1, a2] = await db.batch([db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(json_extract(d, '$.units')), 0) AS u, COALESCE(SUM(json_extract(d, '$.reward')), 0) AS r, COALESCE(SUM(CASE WHEN at > ? THEN 1 ELSE 0 END), 0) AS today FROM creds WHERE id LIKE 'task_%'").bind(now - 86400000),
          db.prepare("SELECT uid, at, d FROM creds WHERE id LIKE 'task_%' ORDER BY at DESC LIMIT 15")]);
        tsm = { v: { s: (a1.results || [])[0] || {}, l: a2.results || [] } }; await metaSet(db, "taskstat", tsm.v).run();
      }
      tk.results = [tsm.v.s]; tl.results = tsm.v.l;
      const snap = { names: {}, heroes: {}, vips: {} };
      await namesFor(db, [...(p.results || []), ...(o.results || []), ...(v.results || []), ...(tl.results || [])].map(x => x.uid), snap);
      return json({ ok: true, pays: (p.results || []).map(x => ({ ...J(x.d), uid: x.uid, id: x.date, date: x.date, status: "pending", src: "d1" })),
        ords: (o.results || []).map(x => ({ ...J(x.d), uid: x.uid, id: x.id, status: "pending", src: "d1" })),
        vreq: (v.results || []).map(x => ({ ...J(x.d), uid: x.uid, status: "pending", src: "d1" })), names: snap.names, tasks: (tk.results || [])[0] || {}, tlist: (tl.results || []).map(x => ({ ...J(x.d), uid: x.uid, at: x.at })), tlog: tg.results || [], imp3: !!(await metaGet(db, "imp3")), imp2: !!(await metaGet(db, "imp2")) });
    }
    if (a === "assignrefs") {                              // owner: "buy referrals" order -> give N recent players with no referrer
      const buyer = str(body.buyer, 64), n = int(body.n, 500), my = await db.prepare("SELECT by FROM refs WHERE uid = ?").bind(buyer).first();
      const r = await db.prepare("SELECT uid FROM lb WHERE uid NOT IN (SELECT uid FROM refs) AND uid != ? AND uid != ? AND uid != ? ORDER BY seen DESC LIMIT ?").bind(buyer, me.uid, (my && my.by) || "", n).all();
      const L = (r.results || []).map(x => x.uid);
      if (L.length) await db.batch(L.map(u => db.prepare("INSERT OR IGNORE INTO refs (uid, by, at, via) VALUES (?, ?, ?, 'bought')").bind(u, buyer, now)));
      return json({ ok: true, got: L.length });
    }
    if (a === "risk") {                                    // device + age info for the withdrawal risk check
      const [l, x, r] = await db.batch([db.prepare("SELECT uid, nick, code, at FROM lb"), db.prepare("SELECT uid, dev, stk FROM lbx"), db.prepare("SELECT uid, by, at, via FROM refs")]);
      return json({ ok: true, lb: l.results || [], dev: x.results || [], refs: r.results || [] });
    }
    if (a === "paystat") {                                 // owner: paid / refunded
      const st = body.st === "refunded" ? "refunded" : body.st === "rejected" ? "rejected" : "paid", uid = str(body.uid, 64), date = str(body.date, 10);   // rejected = deleted, money not returned
      const q = [db.prepare("UPDATE pays SET st = ?, d = json_set(d, '$.status', ?) WHERE uid = ? AND date = ?").bind(st, st, uid, date)];
      let ru = 0;
      if (st === "refunded") { const pr = await db.prepare("SELECT st, d FROM pays WHERE uid = ? AND date = ?").bind(uid, date).first(); const pd = pr ? J(pr.d) : {};
        if (pr && pr.st !== "refunded") ru = pd.srv ? +pd.units || 0 : int(body.units, 1e9); }      // server-made request: give back exactly what the server took
      if (ru > 0) q.push(cred(uid, "refund-" + date + "-" + now.toString(36), { type: "refund", item: date, units: ru, coin: str(body.coin, 10) }));
      await db.batch(q); if (ru > 0) await walCredit(db, uid, "refund-" + date + "-" + now.toString(36), ru, now); return json({ ok: true });
    }
    if (a === "ordstat") {                                 // owner: approve / reject a purchase
      const uid = str(body.uid, 64), id = str(body.id, 60), st = body.st === "rejected" ? "rejected" : "approved";
      const q = [db.prepare("UPDATE ords SET st = ? WHERE uid = ? AND id = ?").bind(st, uid, id)];
      let back = 0;
      if (st === "rejected") { q.push(cred(uid, "rej-" + id, { type: "reject", item: id }));
        const o = await db.prepare("SELECT st, d FROM ords WHERE uid = ? AND id = ?").bind(uid, id).first(), od = o ? J(o.d) : {};
        if (o && o.st !== "rejected" && od.method === "balance" && od.units > 0) back = Math.min(1e8, +od.units); }   // paid with balance -> money back
      else if (body.vip) q.push(db.prepare("INSERT INTO vips (uid, until, tier, at) VALUES (?, ?, ?, ?) ON CONFLICT(uid) DO UPDATE SET until = excluded.until, tier = excluded.tier, at = excluded.at").bind(uid, int(body.vip.until, 9e15), int(body.vip.tier, 4) || 1, now));
      else if (body.credit) q.push(cred(uid, id, body.credit));
      await db.batch(q);
      if (back > 0) await walCredit(db, uid, "rej-" + id, back, now);
      if (st !== "rejected" && body.credit && MONEY_T[body.credit.type] && +body.credit.units > 0) await walCredit(db, uid, "c-" + id, Math.min(1e8, +body.credit.units), now);
      return json({ ok: true });
    }
    if (a === "vipset") {                                  // owner: activate / reject a VIP payment
      const uid = str(body.uid, 64), q = [db.prepare("UPDATE vreq SET st = ? WHERE uid = ?").bind(body.ok ? "active" : "rejected", uid)];
      if (body.ok) q.push(db.prepare("INSERT INTO vips (uid, until, tier, at) VALUES (?, ?, ?, ?) ON CONFLICT(uid) DO UPDATE SET until = excluded.until, tier = excluded.tier, at = excluded.at").bind(uid, int(body.until, 9e15), int(body.tier, 4) || 1, now));
      await db.batch(q); return json({ ok: true });
    }
    if (a === "credit") { const d = body.d || {}; await cred(body.uid, body.id, d).run();
      if (MONEY_T[d.type] && +d.units > 0) await walCredit(db, str(body.uid, 64), "c-" + str(body.id, 90), Math.min(1e8, +d.units), now);   // deposits etc. go into the server wallet
      return json({ ok: true }); }
    if (a === "ban") {                                     // owner: block (money kept aside) or unblock (money back)
      let L = [str(body.uid, 64)].filter(Boolean);
      if (body.on && body.same) { const d = await db.prepare("SELECT dev FROM lbx WHERE uid = ?").bind(L[0]).first();
        if (d && d.dev && d.dev !== "nodev") L = [...new Set([...L, ...((await db.prepare("SELECT uid FROM lbx WHERE dev = ? LIMIT 30").bind(d.dev).all()).results || []).map(x => x.uid)])]; }
      L = L.filter(u => u !== me.uid);                         // never the owner
      const q = [];
      for (const u of L) {
        if (body.on) { await walGet(db, u, now);
          q.push(db.prepare("INSERT INTO ban (uid, why, bal, hold, at) SELECT uid, ?, bal, hold, ? FROM wal WHERE uid = ? ON CONFLICT(uid) DO UPDATE SET why = excluded.why").bind(str(body.why, 60) || "owner", now, u),
                 db.prepare("UPDATE wal SET bal = 0, hold = '{}' WHERE uid = ? AND EXISTS (SELECT 1 FROM ban WHERE uid = ?)").bind(u, u),
                 db.prepare("UPDATE pays SET st = 'rejected', d = json_set(d, '$.status', 'rejected') WHERE uid = ? AND st = 'pending'").bind(u));
        } else {
          q.push(db.prepare("UPDATE wal SET bal = bal + COALESCE((SELECT bal FROM ban WHERE uid = ?), 0), hold = COALESCE((SELECT hold FROM ban WHERE uid = ? AND hold != '{}'), hold) WHERE uid = ?").bind(u, u, u),
                 db.prepare("DELETE FROM ban WHERE uid = ?").bind(u));
        }
      }
      q.push(db.prepare("DELETE FROM meta WHERE k LIKE 'comp:%' OR k LIKE 'vis:%'"));
      await db.batch(q); return json({ ok: true, n: L.length, list: L });
    }
    if (a === "nftsales") {                                // owner: recent NFT sales + NFTs held by blocked accounts
      const since = now - Math.min(90, Math.max(1, int(body.days, 90) || 30)) * 86400000;
      const [sl, bn, bw, bm] = await db.batch([
        db.prepare("SELECT s.id, s.nft, s.seller, s.buyer, s.units, s.gets, s.at, n.owner, ls.code AS sc, ls.nick AS sn, lb2.code AS bc, lb2.nick AS bnk, (SELECT 1 FROM ban WHERE uid = s.buyer) AS bb, (SELECT 1 FROM ban WHERE uid = s.seller) AS sb FROM sales s LEFT JOIN nfts n ON n.id = s.nft LEFT JOIN lb ls ON ls.uid = s.seller LEFT JOIN lb lb2 ON lb2.uid = s.buyer WHERE s.at >= ? ORDER BY s.at DESC LIMIT 300").bind(since),
        db.prepare("SELECT COUNT(*) AS n FROM nfts WHERE owner IN (SELECT uid FROM ban)"),
        db.prepare("SELECT COUNT(*) AS n FROM wnft WHERE owner IN (SELECT uid FROM ban)"),
        db.prepare("SELECT COUNT(*) AS n FROM market WHERE status = 'open' AND seller IN (SELECT uid FROM ban)")
      ]);
      return json({ ok: true, sales: sl.results || [], banned: { nfts: (bn.results[0] || {}).n || 0, wnft: (bw.results[0] || {}).n || 0, listings: (bm.results[0] || {}).n || 0 } });
    }
    if (a === "nftfix") {                                  // owner: give an NFT back to who sold it / take back NFTs from blocked accounts
      if (body.op === "undo") {
        const x = await db.prepare("SELECT nft, seller, buyer FROM sales WHERE id = ?").bind(int(body.sale, 1e12)).first(); if (!x) return json({ ok: false, error: "gone" }, 404);
        const r = await db.batch([db.prepare("UPDATE nfts SET owner = ?, prev = ?, at = ? WHERE id = ? AND owner = ?").bind(x.seller, x.buyer, now, x.nft, x.buyer),
          db.prepare("UPDATE market SET status = 'cancelled' WHERE nft = ? AND status = 'open' AND seller = ?").bind(x.nft, x.buyer), db.prepare("DELETE FROM meta WHERE k = 'nft'")]);
        return json({ ok: true, done: (r[0].meta && r[0].meta.changes) || 0 });
      }
      if (body.op === "banned") {                            // NFTs of blocked accounts: back to whoever had it before (if not blocked), else free again
        const r = await db.batch([
          db.prepare("UPDATE nfts SET owner = prev, prev = owner, at = ? WHERE owner IN (SELECT uid FROM ban) AND prev IS NOT NULL AND prev != '' AND prev NOT IN (SELECT uid FROM ban)").bind(now),
          db.prepare("UPDATE nfts SET owner = NULL, at = ? WHERE owner IN (SELECT uid FROM ban)").bind(now),
          db.prepare("DELETE FROM wnft WHERE owner IN (SELECT uid FROM ban)"),
          db.prepare("UPDATE market SET status = 'cancelled' WHERE status = 'open' AND seller IN (SELECT uid FROM ban)"),
          db.prepare("DELETE FROM meta WHERE k = 'nft'")]);
        return json({ ok: true, back: (r[0].meta && r[0].meta.changes) || 0, free: (r[1].meta && r[1].meta.changes) || 0, wnft: (r[2].meta && r[2].meta.changes) || 0, listings: (r[3].meta && r[3].meta.changes) || 0 });
      }
      return json({ ok: false, error: "bad" }, 400);
    }
    if (a === "setpaid") {                                 // owner: fix the "total paid" the players see
      const st = (await metaGet(db, "stats")) || { v: {} }, s0 = { ...st.v };
      if (body.set) { const v = +body.paidUsd; if (!(v >= 0 && v < 1e7)) return json({ ok: false, error: "bad" }, 400); s0.paidUsd = Math.round(v * 100) / 100; if (body.paidN != null) s0.paidN = int(body.paidN, 1e9);
        await db.batch([metaSet(db, "stats", s0), db.prepare("DELETE FROM meta WHERE k = 'proofs'")]); }
      return json({ ok: true, paidUsd: +s0.paidUsd || 0, paidN: +s0.paidN || 0 });
    }
    if (a === "seclim") {                                  // owner: read / change the anti-cheat limits
      const cur = await getLim(db);
      if (body.set) { const v = { ads: Math.max(50, int(body.ads, 100000) || cur.ads), pay: Math.max(0.001, Math.min(1000, +body.pay || cur.pay)) }; await metaSet(db, "lim", v).run(); await db.prepare("DELETE FROM meta WHERE k LIKE 'comp:%'").run(); return json({ ok: true, lim: v }); }
      return json({ ok: true, lim: cur });
    }
    if (a === "purge") {                                   // owner: emergency clean-up (dry = only count)
      const lim = await getLim(db), wk0 = weekKey(), wk1 = weekKey(-1);
      const [ads, vp, vr, py] = await db.batch([
        db.prepare("SELECT COUNT(*) AS n FROM lbw WHERE week IN (?, ?) AND ads > ?").bind(wk0, wk1, lim.ads),
        db.prepare("SELECT COUNT(*) AS n FROM vips WHERE uid != ?").bind(me.uid),
        db.prepare("SELECT COUNT(*) AS n FROM vreq WHERE uid != ? AND st IN ('pending', 'active')").bind(me.uid),
        db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(CAST(json_extract(d, '$.amountUsd') AS REAL)), 0) AS usd FROM pays WHERE st = 'pending' AND CAST(json_extract(d, '$.amountUsd') AS REAL) > ?").bind(lim.pay + 1e-9)
      ]);
      const c = { ads: (ads.results[0] || {}).n || 0, vips: (vp.results[0] || {}).n || 0, vreq: (vr.results[0] || {}).n || 0, pays: (py.results[0] || {}).n || 0, payUsd: (py.results[0] || {}).usd || 0, lim };
      if (body.dry) return json({ ok: true, ...c });
      await db.batch([
        db.prepare("DELETE FROM vips WHERE uid != ?").bind(me.uid),
        db.prepare("UPDATE vreq SET st = 'rejected', d = json_set(d, '$.status', 'rejected') WHERE uid != ? AND st IN ('pending', 'active')").bind(me.uid),
        db.prepare("UPDATE pays SET st = 'rejected', d = json_set(d, '$.status', 'rejected') WHERE st = 'pending' AND CAST(json_extract(d, '$.amountUsd') AS REAL) > ?").bind(lim.pay + 1e-9),
        db.prepare("DELETE FROM meta WHERE k LIKE 'comp:%'")
      ]);
      return json({ ok: true, done: true, ...c });
    }
    if (a === "adjust") {                                  // owner: add (+) or remove (-) balance from one player
      const uid = str(body.uid, 64), u = Math.max(-1e9, Math.min(1e9, Math.round(+body.units || 0)));
      if (!uid || !u) return json({ ok: false, error: "bad" }, 400);
      const ok = await db.prepare("SELECT 1 AS x FROM lb WHERE uid = ?").bind(uid).first(); if (!ok) return json({ ok: false, error: "no_player" }, 404);
      const id = "adj-" + now.toString(36) + Math.random().toString(36).slice(2, 6);
      await cred(uid, id, { type: "adj", units: u, note: str(body.note, 120) }).run();
      await walCredit(db, uid, id, u, now);
      return json({ ok: true, id });
    }
    if (a === "prizes") {                                  // which weekly / 15-day / monthly prizes were already credited
      const keys = (Array.isArray(body.keys) ? body.keys : []).slice(0, 6).map(k => "prize:" + str(k, 20));
      const r = keys.length ? await db.prepare("SELECT k, v FROM meta WHERE k IN (" + keys.map(() => "?").join(",") + ")").bind(...keys).all() : { results: [] };
      const o = {}; for (const x of r.results || []) o[x.k.slice(6)] = J(x.v); return json({ ok: true, done: o });
    }
    if (a === "prizeset") {                                // credit one prize (only once)
      const k = "prize:" + str(body.k, 20), id = str(body.id, 20), old = (await metaGet(db, k)) || { v: {} };
      if (old.v[id]) return json({ ok: true, already: true });
      await db.batch([metaSet(db, k, { ...old.v, [id]: true }), cred(body.uid, "prize_" + str(body.k, 20) + "_" + id, { type: "deposit", units: int(body.units, 1e9), note: "weekly prize" })]);
      await walCredit(db, str(body.uid, 64), "prize_" + str(body.k, 20) + "_" + id, int(body.units, 1e9), now);
      return json({ ok: true });
    }
    if (a === "acct") {                                    // accounting from D1
      const [o, p, c, x] = await db.batch([db.prepare("SELECT st, d FROM ords"), db.prepare("SELECT st, d FROM pays"),
        db.prepare("SELECT d FROM creds WHERE d LIKE '%weekly prize%'"), db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(bal), 0) AS bal, COALESCE(SUM(staked), 0) AS st, COALESCE(SUM(dmt), 0) AS dmt, COALESCE(SUM(fx), 0) AS fx, COALESCE(SUM(fxn), 0) AS fxn, COALESCE(SUM(fm), 0) AS fm, COALESCE(SUM(fmn), 0) AS fmn FROM lbx")]);
      return json({ ok: true, ords: (o.results || []).map(r => ({ ...J(r.d), status: r.st })), pays: (p.results || []).map(r => ({ amountUsd: J(r.d).amountUsd, status: r.st })),
        prizes: (c.results || []).reduce((s, r) => s + (+J(r.d).units || 0), 0), lbx: await (async () => { const L = (x.results || [])[0] || {};
          const w = await db.batch([db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(bal), 0) AS bal FROM wal"), db.prepare("SELECT COALESCE(SUM(amt), 0) AS st FROM wstk WHERE asset = 'USD'")]);
          const W = (w[0].results || [])[0] || {}; if (W.n) { L.bal = W.bal; L.st = ((w[1].results || [])[0] || {}).st || 0; } return L; })() });   // what players hold now = the server wallets
    }
    if (a === "imp2") {                                    // owner, once: copy the old Firebase withdrawals / purchases / VIP into D1
      const q = [];
      for (const x of (body.pays || []).slice(0, 40)) q.push(db.prepare("INSERT OR IGNORE INTO pays (uid, date, st, at, d) VALUES (?, ?, ?, ?, ?)").bind(str(x.uid, 64), str(x.date, 10), str(x.status, 12) || "pending", int(x.at, 9e15), JSON.stringify(x.d || {}).slice(0, 6000)));
      for (const x of (body.ords || []).slice(0, 40)) q.push(db.prepare("INSERT OR IGNORE INTO ords (uid, id, st, at, d) VALUES (?, ?, ?, ?, ?)").bind(str(x.uid, 64), str(x.id, 60), str(x.status, 12) || "pending", int(x.at, 9e15), JSON.stringify(x.d || {}).slice(0, 6000)));
      for (const x of (body.vips || []).slice(0, 40)) q.push(db.prepare("INSERT OR IGNORE INTO vips (uid, until, tier, at) VALUES (?, ?, ?, ?)").bind(str(x.uid, 64), int(x.until, 9e15), int(x.tier, 4) || 1, int(x.at, 9e15)));
      for (const x of (body.vreq || []).slice(0, 40)) q.push(db.prepare("INSERT OR IGNORE INTO vreq (uid, st, at, d) VALUES (?, ?, ?, ?)").bind(str(x.uid, 64), str(x.status, 12) || "pending", int(x.at, 9e15), JSON.stringify(x.d || {}).slice(0, 3000)));
      for (const x of (body.lbx || []).slice(0, 40)) q.push(db.prepare("INSERT OR IGNORE INTO lbx (uid, bal, staked, dmt, dev, stk, at, fx, fxn, fm, fmn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(str(x.uid, 64), int(x.bal, 1e12), int(x.staked, 1e12), int(x.dmt, 1e12), str(x.dev, 40), JSON.stringify(Array.isArray(x.stk) ? x.stk.slice(0, 20) : []).slice(0, 4000), int(x.at, 9e15), Math.max(0, Math.min(1e6, +x.fx || 0)), int(x.fxn, 1e9), int(x.fm, 1e12), int(x.fmn, 1e9)));
      for (const x of (body.creds || []).slice(0, 40)) q.push(db.prepare("INSERT OR IGNORE INTO creds (uid, id, at, d) VALUES (?, ?, ?, ?)").bind(str(x.uid, 64), str(x.id, 90), int(x.at, 9e15), JSON.stringify(x.d || {}).slice(0, 3000)));
      if (body.done) q.push(metaSet(db, "imp2", { at: now }));
      if (body.done && body.v3) q.push(metaSet(db, "imp3", { at: now }));   // second copy: + player balances / stakes / tasks
      if (q.length) await db.batch(q);
      return json({ ok: true, n: q.length });
    }
  }
  /* ---- messages owner <-> player (popup in the game) ---- */
  if (a === "inbox") {                                     // player: owner messages not answered yet
    const r = await db.prepare("SELECT id, body, at FROM msgs WHERE uid = ? AND seen = 0 ORDER BY at LIMIT 5").bind(me.uid).all();
    return json({ ok: true, list: r.results || [] });
  }
  if (a === "msgreply") {                                  // player answers (or just closes with "OK")
    const r = await db.prepare("UPDATE msgs SET seen = 1, reply = ?, rat = ? WHERE id = ? AND uid = ? AND seen = 0").bind(str(body.reply, 500).trim() || null, now, int(body.id, 1e12), me.uid).run();
    return json({ ok: true, n: (r.meta && r.meta.changes) || 0 });
  }
  if (a === "spy") {                                       // owner: everything we know about one player (by code or name)
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const q = str(body.q, 64).trim(); if (!q) return json({ ok: false, error: "empty" }, 400);
    const f = await db.prepare("SELECT uid FROM lb WHERE code = ? OR uid = ? OR nick = ? ORDER BY seen DESC LIMIT 1").bind(q.toUpperCase(), q, q).first();
    if (!f) return json({ ok: true, none: true });
    const u = f.uid, d30 = today(now - 30 * 86400000);
    const x = await db.prepare("SELECT dev FROM lbx WHERE uid = ?").bind(u).first(), dev = (x && x.dev) || "";
    const [lb, lx, lc, vp, wk, dy, by, rf, sd, py, od, cr, ct, re, rs, vs, nf] = await db.batch([
      db.prepare("SELECT uid, nick, code, hero, vip, coin, seen, at FROM lb WHERE uid = ?").bind(u),
      db.prepare("SELECT bal, staked, dmt, dev, stk, at FROM lbx WHERE uid = ?").bind(u),
      db.prepare("SELECT cl FROM lbc WHERE uid = ?").bind(u),
      db.prepare("SELECT until, tier FROM vips WHERE uid = ?").bind(u),
      db.prepare("SELECT week, ads FROM lbw WHERE uid = ? ORDER BY week DESC LIMIT 8").bind(u),
      db.prepare("SELECT day, td FROM lbd WHERE uid = ? ORDER BY day DESC LIMIT 14").bind(u),
      db.prepare("SELECT r.by, r.via, r.at, l.nick, l.code FROM refs r LEFT JOIN lb l ON l.uid = r.by WHERE r.uid = ?").bind(u),
      db.prepare("SELECT r.uid, r.via, r.at, l.nick, l.code, l.seen, x.dev FROM refs r LEFT JOIN lb l ON l.uid = r.uid LEFT JOIN lbx x ON x.uid = r.uid WHERE r.by = ? ORDER BY r.at DESC LIMIT 200").bind(u),
      db.prepare("SELECT x.uid, l.nick, l.code, l.seen FROM lbx x LEFT JOIN lb l ON l.uid = x.uid WHERE x.dev = ? AND x.dev != '' AND x.dev != 'nodev' AND x.uid != ? LIMIT 20").bind(dev, u),
      db.prepare("SELECT date, st, d FROM pays WHERE uid = ? ORDER BY at DESC LIMIT 30").bind(u),
      db.prepare("SELECT id, st, at, d FROM ords WHERE uid = ? ORDER BY at DESC LIMIT 30").bind(u),
      db.prepare("SELECT id, at, d FROM creds WHERE uid = ? ORDER BY at DESC LIMIT 40").bind(u),
      db.prepare("SELECT CASE WHEN id LIKE 'prize_%' THEN 'prize' ELSE json_extract(d, '$.type') END AS t, COUNT(*) AS n, COALESCE(SUM(json_extract(d, '$.units')), 0) AS u FROM creds WHERE uid = ? GROUP BY t").bind(u),
      db.prepare("SELECT base, total FROM refearn WHERE uid = ?").bind(u),
      db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(total), 0) AS t FROM refearn WHERE by = ?").bind(u),
      db.prepare("SELECT COALESCE(SUM(n), 0) AS n FROM visits WHERE uid = ? AND day >= ?").bind(u, d30),
      db.prepare("SELECT COUNT(*) AS n FROM nfts WHERE owner = ?").bind(u)
    ]);
    const R = r => r.results || [], one = r => R(r)[0] || null, J = v => { try { return JSON.parse(v); } catch (e) { return {}; } };
    const L = one(lx), wsum = R(wk).reduce((s, w) => s + (w.ads || 0), 0);
    /* past competitions: his place every week (ads), every 15 days (referrals) and every month (visits) + prizes he got */
    const bd = new Date(now - BOG), Y = bd.getUTCFullYear(), M = bd.getUTCMonth(), H = bd.getUTCDate() <= 15 ? 0 : 1, fq = [], mq = [];
    for (let i = 0; i < 6; i++) { const idx = Y * 24 + M * 2 + H - i, y = Math.floor(idx / 24), m = Math.floor((idx % 24) / 2), h = idx % 2;
      fq.push({ key: `${y}-${String(m + 1).padStart(2, "0")}-${h ? "B" : "A"}`, fs: Date.UTC(y, m, h ? 16 : 1) + BOG, fe: (h ? Date.UTC(y, m + 1, 1) : Date.UTC(y, m, 16)) + BOG }); }
    for (let i = 0; i < 4; i++) { const d0 = new Date(Date.UTC(Y, M - i, 1)), d1 = new Date(Date.UTC(Y, M - i + 1, 1)); mq.push({ mo: d0.toISOString().slice(0, 7), a: d0.toISOString().slice(0, 10), b: d1.toISOString().slice(0, 10) }); }
    const cq = await db.batch([
      db.prepare("SELECT w.week, w.ads, (SELECT COUNT(*) FROM lbw x WHERE x.week = w.week AND x.ads > w.ads) + 1 AS rank, (SELECT COUNT(*) FROM lbw x WHERE x.week = w.week AND x.ads > 0) AS of FROM lbw w WHERE w.uid = ? ORDER BY w.week DESC LIMIT 8").bind(u),
      ...fq.map(f => db.prepare("WITH c AS (SELECT by, COUNT(*) AS n FROM refs WHERE at >= ? AND at < ? AND via != 'bought' AND by != '' GROUP BY by) SELECT COALESCE((SELECT n FROM c WHERE by = ?), 0) AS n, (SELECT COUNT(*) FROM c WHERE n > COALESCE((SELECT n FROM c WHERE by = ?), 0)) + 1 AS rank, (SELECT COUNT(*) FROM c) AS of").bind(f.fs, f.fe, u, u)),
      ...mq.map(m => db.prepare("WITH c AS (SELECT uid, SUM(n) AS n FROM visits WHERE day >= ? AND day < ? GROUP BY uid HAVING SUM(n) > 0) SELECT COALESCE((SELECT n FROM c WHERE uid = ?), 0) AS n, (SELECT COUNT(*) FROM c WHERE n > COALESCE((SELECT n FROM c WHERE uid = ?), 0)) + 1 AS rank, (SELECT COUNT(*) FROM c) AS of").bind(m.a, m.b, u, u)),
      db.prepare("SELECT id, at, d FROM creds WHERE uid = ? AND id LIKE 'prize_%' ORDER BY at DESC LIMIT 60").bind(u)
    ]);
    const [wa, ws] = await db.batch([db.prepare("SELECT bal, hold, inc, out, spent, mig, n, day FROM wal WHERE uid = ?").bind(u), db.prepare("SELECT asset, amt, rew, endt FROM wstk WHERE uid = ?").bind(u)]);
    const wal = one(wa) ? { ...one(wa), hold: J(one(wa).hold), stakes: R(ws) } : null;
    const bn = await db.prepare("SELECT why, bal, at FROM ban WHERE uid = ?").bind(u).first();
    const comp = { weeks: R(cq[0]), forts: fq.map((f, i) => ({ key: f.key, fs: f.fs, fe: f.fe, ...(one(cq[1 + i]) || {}) })), months: mq.map((m, i) => ({ mo: m.mo, ...(one(cq[1 + fq.length + i]) || {}) })),
      prizes: R(cq[cq.length - 1]).map(c => ({ id: c.id, at: c.at, ...J(c.d) })) };
    return json({ ok: true, uid: u, lb: one(lb), x: L ? { ...L, stk: J(L.stk) } : null, cl: Math.max((one(lc) || {}).cl || 0, wsum), vip: one(vp),
      weeks: R(wk), days: R(dy), by: one(by), refs: R(rf), same: R(sd), pays: R(py).map(p => ({ date: p.date, st: p.st, ...J(p.d) })),
      ords: R(od).map(o => ({ id: o.id, st: o.st, at: o.at, ...J(o.d) })), creds: R(cr).map(c => ({ id: c.id, at: c.at, ...J(c.d) })), ctot: R(ct),
      refearn: one(re), refsEarn: one(rs), visits: (one(vs) || {}).n || 0, nfts: (one(nf) || {}).n || 0, comp, wal, ban: bn || null });
  }
  if (a === "msgfind" || a === "msgsend" || a === "msglist" || a === "msgdel") {
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    if (a === "msgfind") {                                 // by ranking name or player code
      const q = str(body.q, 30).trim(); if (!q) return json({ ok: true, list: [] });
      const r = await db.prepare("SELECT uid, nick, code, seen FROM lb WHERE code = ? OR nick LIKE ? ORDER BY seen DESC LIMIT 12").bind(q.toUpperCase(), "%" + q.replace(/[%_]/g, "") + "%").all();
      return json({ ok: true, list: r.results || [] });
    }
    if (a === "msgsend") {
      const uid = str(body.uid, 64), txt = str(body.body, 800).trim();
      if (!uid || !txt) return json({ ok: false, error: "bad" }, 400);
      await db.batch([
        db.prepare("INSERT INTO msgs (uid, body, at) VALUES (?, ?, ?)").bind(uid, txt, now),
        db.prepare("DELETE FROM msgs WHERE at < ?").bind(now - 60 * 86400000)
      ]);
      return json({ ok: true });
    }
    if (a === "msgdel") { await db.prepare("DELETE FROM msgs WHERE id = ?").bind(int(body.id, 1e12)).run(); return json({ ok: true }); }
    const r = await db.prepare("SELECT id, uid, body, at, seen, reply, rat FROM msgs ORDER BY at DESC LIMIT 30").all();
    const snap = { names: {}, heroes: {}, vips: {} }, L = r.results || [];
    await namesFor(db, L.map(x => x.uid), snap);
    return json({ ok: true, list: L, names: snap.names });
  }
  if (a === "ev") {                                        // flash-sale counters: seen / tapped / bought
    const k = str(body.k, 8), e = str(body.e, 8);
    if (!["vip", "gear", "hero", "tix"].includes(k) || !["view", "click", "buy"].includes(e)) return json({ ok: false, error: "bad" }, 400);
    const day = new Date(now - BOG).toISOString().slice(0, 10);
    await db.prepare("INSERT INTO offstat (day, k, e, n) VALUES (?, ?, ?, 1) ON CONFLICT(day, k, e) DO UPDATE SET n = n + 1").bind(day, k, e).run();
    return json({ ok: true });
  }
  if (a === "offstats") {                                  // owner: last 14 days
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const from = new Date(now - BOG - 14 * 86400000).toISOString().slice(0, 10);
    const r = await db.prepare("SELECT day, k, e, n FROM offstat WHERE day >= ? ORDER BY day DESC").bind(from).all();
    return json({ ok: true, list: r.results || [] });
  }
  if (a === "pstats") {                                    // owner: panel numbers from D1 (work even when Firebase is full)
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const [p, r, wk, nf, sl, pr, mt, pe] = await db.batch([
      db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN seen > ? THEN 1 ELSE 0 END), 0) AS today, COALESCE(SUM(CASE WHEN vip > 0 AND seen > ? THEN 1 ELSE 0 END), 0) AS vip FROM lb").bind(now - 86400000, now - 30 * 86400000),
      db.prepare("SELECT COUNT(*) AS n FROM refs"),
      db.prepare("SELECT COALESCE(SUM(ads), 0) AS n FROM lbw WHERE week = ?").bind(weekKey()),
      db.prepare("SELECT COUNT(*) AS n FROM nfts WHERE owner IS NOT NULL AND owner != ''"),
      db.prepare("SELECT COUNT(*) AS n FROM sales"),
      db.prepare("SELECT COUNT(*) AS n FROM proofs"),
      db.prepare("SELECT k, v FROM meta WHERE k IN ('stats', 'fee')"),
      db.prepare("SELECT (SELECT COUNT(*) FROM pays WHERE st = 'pending') AS pp, (SELECT COUNT(*) FROM ords WHERE st = 'pending') + (SELECT COUNT(*) FROM vreq WHERE st = 'pending') AS po, (SELECT COALESCE(SUM(td), 0) FROM lbd WHERE day = ?) AS ft").bind(str(body.day, 10))
    ]);
    const one = q => ((q.results || [])[0] || {}), M = {}; for (const x of mt.results || []) M[x.k] = JSON.parse(x.v);
    const st = M.stats || {}, fee = M.fee || {};
    return json({ ok: true, players: one(p).n || 0, today: one(p).today || 0, vip: one(p).vip || 0, refs: one(r).n || 0, fWeek: one(wk).n || 0,
      nfts: one(nf).n || 0, sales: Math.max(one(sl).n || 0, +fee.n || 0), feeUnits: +fee.sum || 0, proofs30: one(pr).n || 0, paidUsd: +st.paidUsd || 0, paidN: +st.paidN || 0,
      pendPay: one(pe).pp || 0, pendOrd: one(pe).po || 0, fToday: one(pe).ft || 0, imp2: !!(await metaGet(db, "imp2")) });
  }
  if (a === "live") {                                      // owner: players online now
    if (!me.owner) return json({ ok: false, error: "owner" }, 403);
    const r = await db.prepare("SELECT coin, vip FROM lb WHERE seen > ?").bind(now - 720000).all();
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
