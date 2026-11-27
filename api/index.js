// Touchline All-Star Association : liaison Discord + Roblox (Vercel + Supabase)
const crypto = require("crypto");
const E = process.env;

// ---- Cookie de session signé (pas de stockage serveur)
const mac = (v) => crypto.createHmac("sha256", E.SESSION_SECRET).update(v).digest("base64url");
const sign = (o) => { const b = Buffer.from(JSON.stringify(o)).toString("base64url"); return b + "." + mac(b); };
const verify = (t) => {
  if (!t) return null;
  const [b, s] = t.split(".");
  if (!b || !s) return null;
  const good = Buffer.from(mac(b));
  if (good.length !== Buffer.byteLength(s) || !crypto.timingSafeEqual(good, Buffer.from(s))) return null;
  try { const o = JSON.parse(Buffer.from(b, "base64url")); return o.exp > Date.now() ? o : null; } catch { return null; }
};
const readCookies = (req) => Object.fromEntries((req.headers.cookie || "").split(/;\s*/).filter(Boolean).map((c) => { const i = c.indexOf("="); return [c.slice(0, i), c.slice(i + 1)]; }));
const setCookie = (res, name, val, maxAge) =>
  res.setHeader("Set-Cookie", [].concat(res.getHeader("Set-Cookie") || [], `${name}=${val}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`));

// ---- Base de données Supabase (API REST)
const sb = (path, opt = {}) => fetch(`${E.SUPABASE_URL}/rest/v1/${path}`, {
  ...opt,
  headers: { apikey: E.SUPABASE_SERVICE_KEY, "Content-Type": "application/json", ...opt.headers },
});

const form = (o) => new URLSearchParams(o);
async function getToken(url, id, secret, code, redirect) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ client_id: id, client_secret: secret, grant_type: "authorization_code", code, redirect_uri: redirect }) });
  const t = (await r.json()).access_token;
  if (!t) throw new Error("Token exchange failed");
  return t;
}
const bearer = (t) => ({ headers: { Authorization: "Bearer " + t } });

module.exports = async (req, res) => {
  const q = new URL(req.url, E.BASE_URL).searchParams, r = q.get("r");
  const c = readCookies(req), sess = verify(c.sid), st = verify(c.st);
  const redirect = (u) => { res.statusCode = 302; res.setHeader("Location", u); res.end(); };
  const fail = (code, msg) => { res.statusCode = code; res.end(msg); };
  const start = (url, params) => {
    const state = crypto.randomUUID();
    setCookie(res, "st", sign({ s: state, exp: Date.now() + 600000 }), 600);
    redirect(url + "?" + form({ ...params, state }));
  };
  const stateOk = () => st && q.get("state") && st.s === q.get("state");

  try {
    if (r === "me") {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Cache-Control", "no-store");
      const rows = sess ? await (await sb(`users?discord_id=eq.${encodeURIComponent(sess.did)}&select=*`)).json() : [];
      const u = rows[0];
      return res.end(JSON.stringify(!u ? { discord: null, roblox: null } : {
        discord: { id: u.discord_id, username: u.discord_username, avatar: u.discord_avatar },
        roblox: u.roblox_id ? { id: u.roblox_id, username: u.roblox_username, avatar: "", skin: u.roblox_skin } : null,
      }));
    }

    if (r === "auth-discord")
      return start("https://discord.com/oauth2/authorize", { client_id: E.DISCORD_ID, response_type: "code", scope: "identify", redirect_uri: E.BASE_URL + "/callback/discord" });

    if (r === "cb-discord") {
      if (!stateOk()) return fail(400, "Invalid state");
      const t = await getToken("https://discord.com/api/oauth2/token", E.DISCORD_ID, E.DISCORD_SECRET, q.get("code"), E.BASE_URL + "/callback/discord");
      const u = await (await fetch("https://discord.com/api/users/@me", bearer(t))).json();
      const up = await sb("users?on_conflict=discord_id", { method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify({ discord_id: u.id, discord_username: u.username,
          discord_avatar: u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=256` : "", updated_at: new Date().toISOString() }) });
      if (!up.ok) throw new Error(await up.text());
      setCookie(res, "sid", sign({ did: u.id, exp: Date.now() + 30 * 864e5 }), 30 * 86400);
      return redirect("/");
    }

    if (r === "auth-roblox") {
      if (!sess) return redirect("/");
      return start("https://apis.roblox.com/oauth/v1/authorize", { client_id: E.ROBLOX_ID, response_type: "code", scope: "openid profile", redirect_uri: E.BASE_URL + "/callback/roblox" });
    }

    if (r === "cb-roblox") {
      if (!sess || !stateOk()) return fail(400, "Invalid state");
      const t = await getToken("https://apis.roblox.com/oauth/v1/token", E.ROBLOX_ID, E.ROBLOX_SECRET, q.get("code"), E.BASE_URL + "/callback/roblox");
      const u = await (await fetch("https://apis.roblox.com/oauth/v1/userinfo", bearer(t))).json();
      const th = await (await fetch(`https://thumbnails.roblox.com/v1/users/avatar?userIds=${u.sub}&size=420x420&format=Png`)).json();
      const p = await sb(`users?discord_id=eq.${encodeURIComponent(sess.did)}`, { method: "PATCH", headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ roblox_id: String(u.sub), roblox_username: u.preferred_username || u.name, roblox_skin: th.data?.[0]?.imageUrl || "", updated_at: new Date().toISOString() }) });
      if (p.status === 409) return fail(409, "This Roblox account is already linked to another Discord account.");
      if (!p.ok) throw new Error(await p.text());
      return redirect("/");
    }

    fail(404, "Not found");
  } catch (e) {
    console.error(e);
    fail(500, "Something went wrong");
  }
};
