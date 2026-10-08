import { onRequest } from "./functions/api/captcha.js";
export default {
  async fetch(request, env) {
    const u = new URL(request.url);
    if (u.pathname === "/api/captcha") return onRequest({ request, env });
    return env.ASSETS.fetch(request);
  }
};
