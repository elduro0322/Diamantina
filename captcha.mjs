import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";
const env = (k) => (globalThis.Netlify?.env?.get?.(k)) ?? process.env[k] ?? "";
const sign = (sub) => crypto.createHmac("sha256", env("ADSLAB_SECRET") || "x").update("ret:" + sub).digest("hex").slice(0, 32);
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
async function adslabInit(subId, returnUrl) {
  const r = await fetch("https://adslab.me/api/v1/captcha/init", {
    method: "POST", headers: { "content-type": "application/json", "accept": "application/json", "x-api-key": env("ADSLAB_API_KEY") },
    body: JSON.stringify({ sub_id: subId, return_url: returnUrl }),
  });
  const text = await r.text(); let d = {}; try { d = JSON.parse(text); } catch {}
  return { r, d, text };
}
export default async (req) => {
  try {
    const url = new URL(req.url), a = url.searchParams.get("a");
    if (a === "diag") {
      const out = { ok: true, hasKey: !!env("ADSLAB_API_KEY"), hasSecret: !!env("ADSLAB_SECRET") };
      try { await getStore("captcha").setJSON("diag", { at: Date.now() }); out.blobs = "ok"; } catch (e) { out.blobs = String(e && e.message || e); }
      if (out.hasKey) { const { r, text } = await adslabInit("diag-" + Date.now(), url.origin + "/"); out.adslab = { status: r.status, body: text.replace(/"token"\s*:\s*"[^"]+"/, '"token":"(ok)"').slice(0, 300) }; }
      return json(out);
    }
    const store = getStore("captcha");
    if (a === "init" && req.method === "POST") {
      if (!env("ADSLAB_API_KEY")) return json({ ok: false, error: "missing ADSLAB_API_KEY" }, 500);
      let body = {}; try { body = await req.json(); } catch {}
      const uid = String(body.uid || "anon").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 40) || "anon";
      const subId = `${uid}-${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}`;
      const { r, d, text } = await adslabInit(subId, `${url.origin}/?captcha=${encodeURIComponent(subId)}&ck=${sign(subId)}`);
      if (!r.ok || !d.success || !d.token) return json({ ok: false, error: d.message || d.error || ("adslab " + r.status + " " + text.slice(0, 60)) }, 502);
      await store.setJSON(subId, { status: "pending", at: Date.now() });
      return json({ ok: true, sub_id: subId, token: d.token, solve_url: d.solve_url || "https://adslab.me/captcha" });
    }
    if (a === "postback" && req.method === "POST") {
      const secret = env("ADSLAB_SECRET");
      if (!secret) return new Response("Missing secret", { status: 500 });
      const raw = await req.text(); let d = {};
      try { d = JSON.parse(raw); } catch { d = Object.fromEntries(new URLSearchParams(raw)); }
      const subId = String(d.sub_id || ""), ts = String(d.timestamp || ""), sig = String(d.signature || "");
      const exp = crypto.createHmac("sha256", secret).update(`${subId}:${ts}`).digest("hex");
      if (!(subId && same(sig, exp))) return new Response("Invalid Signature", { status: 403 });
      if (Math.abs(Date.now() / 1000 - Number(ts)) > 3600) return new Response("Expired", { status: 403 });
      if (d.status && d.status !== "success") return new Response("OK");
      const cur = await store.get(subId, { type: "json" });
      if (cur && cur.status === "pending") await store.setJSON(subId, { ...cur, status: "success", solvedAt: Date.now() });
      return new Response("OK");
    }
    if (a === "status") {
      const subId = url.searchParams.get("sub_id") || "", ck = url.searchParams.get("ck") || "";
      if (!/^[A-Za-z0-9_-]{5,80}$/.test(subId)) return json({ ok: false, status: "unknown" }, 400);
      const cur = await store.get(subId, { type: "json" });
      if (!cur) return json({ ok: false, status: "unknown" });
      const returned = ck && same(ck, sign(subId)) && Date.now() - cur.at < 30 * 60 * 1000;
      if (cur.status === "success" || (cur.status === "pending" && returned)) { await store.setJSON(subId, { ...cur, status: "used", usedAt: Date.now() }); return json({ ok: true, status: "success" }); }
      return json({ ok: false, status: cur.status });
    }
    return json({ ok: false, error: "bad_request" }, 400);
  } catch (e) {
    return json({ ok: false, error: "server: " + String(e && e.message || e).slice(0, 120) }, 500);
  }
};
