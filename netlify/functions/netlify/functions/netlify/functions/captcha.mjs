import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";
const env = (k) => (globalThis.Netlify?.env?.get?.(k)) ?? process.env[k] ?? "";
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
export default async (req) => {
  const url = new URL(req.url), a = url.searchParams.get("a"), store = getStore("captcha");
  if (a === "init" && req.method === "POST") {
    const apiKey = env("ADSLAB_API_KEY");
    if (!apiKey) return json({ ok: false, error: "missing ADSLAB_API_KEY" }, 500);
    let body = {}; try { body = await req.json(); } catch {}
    const uid = String(body.uid || "anon").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 40) || "anon";
    const subId = `${uid}-${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}`;
    const r = await fetch("https://adslab.me/api/v1/captcha/init", {
      method: "POST", headers: { "content-type": "application/json", "x-api-key": apiKey },
      body: JSON.stringify({ sub_id: subId, return_url: `${url.origin}/?captcha=${encodeURIComponent(subId)}` }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok || !d.success || !d.token) return json({ ok: false, error: d.message || d.error || "init_failed" }, 502);
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
    const ok = subId && sig.length === exp.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp));
    if (!ok) return new Response("Invalid Signature", { status: 403 });
    if (Math.abs(Date.now() / 1000 - Number(ts)) > 3600) return new Response("Expired", { status: 403 });
    if (d.status && d.status !== "success") return new Response("OK");
    const cur = await store.get(subId, { type: "json" });
    if (cur && cur.status === "pending") await store.setJSON(subId, { ...cur, status: "success", solvedAt: Date.now() });
    return new Response("OK");
  }
  if (a === "status") {
    const subId = url.searchParams.get("sub_id") || "";
    if (!/^[A-Za-z0-9_-]{5,80}$/.test(subId)) return json({ ok: false, status: "unknown" }, 400);
    const cur = await store.get(subId, { type: "json" });
    if (!cur) return json({ ok: false, status: "unknown" });
    if (cur.status === "success") { await store.setJSON(subId, { ...cur, status: "used", usedAt: Date.now() }); return json({ ok: true, status: "success" }); }
    return json({ ok: false, status: cur.status });
  }
  return json({ ok: false, error: "bad_request" }, 400);
};
