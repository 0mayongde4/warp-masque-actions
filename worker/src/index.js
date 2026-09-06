// Opera VPN over Cloudflare WARP (MASQUE) —— Worker 版
//
// 职责:
//   1. 每 4 小时由 cron 触发，重新拿 Opera 凭据并重建配置
//   2. WARP 注册信息存 KV 复用，不每次重注册（设备是有限资源）
//   3. 状态页要密码，订阅路径可自定义
//
// 环境变量:
//   PASSWORD    必填。管理页密码，用 wrangler secret put PASSWORD 设置
//   SUB_PATH    可选。订阅路径，默认 /sub。设成难猜的字符串等于多一层保护
import { registerWarp } from "./warp.js";
import { fetchOpera } from "./opera.js";
import { buildConfig } from "./config.js";
import { renderUI, renderLogin } from "./ui.js";
import {
  safeEqual, signToken, verifyToken, readCookie, rateLimit, clearRateLimit,
} from "./auth.js";

const K_WARP = "warp:device";     // WARP 注册信息，长期复用
const K_CFG = "config:yaml";      // 生成好的配置
const K_STATE = "state:meta";     // 状态元数据，给 UI 用
const COOKIE = "om_session";

const json = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

function subPath(env) {
  const p = (env.SUB_PATH || "sub").replace(/^\/+|\/+$/g, "");
  return "/" + p;
}

/** 拿 WARP 设备信息，KV 里有就复用，没有才注册。 */
async function getWarp(env, force = false) {
  if (!force) {
    const cached = await env.KV.get(K_WARP, "json");
    if (cached && cached.privateKey) return cached;
  }
  const w = await registerWarp("cf-worker");
  await env.KV.put(K_WARP, JSON.stringify(w));
  return w;
}

/** 重建配置。WARP 复用，Opera 每次重取（凭据会过期）。 */
async function rebuild(env, { forceWarp = false } = {}) {
  const warp = await getWarp(env, forceWarp);
  const opera = await fetchOpera();
  const { yaml, entries, landings, combos } = buildConfig(warp, opera);

  const state = {
    updatedAt: new Date().toISOString(),
    stats: { entries, landings, combos },
    warp: {
      deviceId: warp.deviceId,
      ipv4: warp.ipv4,
      ipv6: warp.ipv6,
      registeredAt: warp.registeredAt,
    },
  };

  await env.KV.put(K_CFG, yaml);
  await env.KV.put(K_STATE, JSON.stringify(state));
  return state;
}

async function loggedIn(req, env) {
  return verifyToken(env.PASSWORD, readCookie(req, COOKIE));
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(rebuild(env).catch((e) => console.error("定时重建失败:", e.message)));
  },

  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const ip = req.headers.get("cf-connecting-ip") || "unknown";

    // 没设密码就不让跑，避免裸奔上线
    if (!env.PASSWORD) {
      return new Response(
        "未设置 PASSWORD。请执行: npx wrangler secret put PASSWORD",
        { status: 500, headers: { "content-type": "text/plain; charset=utf-8" } });
    }

    // ---- 订阅。路径可自定义，客户端不能带 cookie，所以用 ?token= ----
    if (path === subPath(env)) {
      const t = url.searchParams.get("token") || "";
      const ok = (await verifyToken(env.PASSWORD, t)) || (await loggedIn(req, env));
      if (!ok) return new Response("Not Found", { status: 404 });

      let yaml = await env.KV.get(K_CFG);
      if (!yaml) {
        await rebuild(env);
        yaml = await env.KV.get(K_CFG);
      }
      return new Response(yaml, {
        headers: {
          "content-type": "text/yaml; charset=utf-8",
          "content-disposition": 'attachment; filename="opera-masque.yaml"',
          "profile-update-interval": "4",
          "cache-control": "no-store",
        },
      });
    }

    // ---- 登录 ----
    if (path === "/login" && req.method === "POST") {
      if (!(await rateLimit(env, ip))) {
        return json({ ok: false, error: "尝试过多，15 分钟后再试" }, 429);
      }
      const body = await req.json().catch(() => ({}));
      if (!safeEqual(body.password || "", env.PASSWORD)) {
        return json({ ok: false, error: "密码错误" }, 401);
      }
      await clearRateLimit(env, ip);
      const token = await signToken(env.PASSWORD);
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "content-type": "application/json; charset=utf-8",
          "set-cookie": `${COOKIE}=${token}; Path=/; HttpOnly; Secure; ` +
                        `SameSite=Lax; Max-Age=${7 * 24 * 3600}`,
        },
      });
    }

    if (path === "/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          location: "/",
          "set-cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
        },
      });
    }

    // ---- 以下都要登录 ----
    const authed = await loggedIn(req, env);

    if (path === "/") {
      if (!authed) {
        return new Response(renderLogin(), {
          headers: { "content-type": "text/html; charset=utf-8" },
        });
      }
      const state = await env.KV.get(K_STATE, "json");
      const token = await signToken(env.PASSWORD);
      return new Response(renderUI(state, url.host, subPath(env), token), {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
        },
      });
    }

    // 未登录一律 404，不用 401 —— 401 会告诉探测者"这个路径是存在的"，
    // 等于把订阅路径的存在性泄露出去
    if (!authed) return new Response("Not Found", { status: 404 });

    if (path === "/api/state") {
      return json((await env.KV.get(K_STATE, "json")) || {});
    }

    // 只换 Opera 凭据，WARP 设备保留
    if (path === "/api/refresh" && req.method === "POST") {
      try {
        const s = await rebuild(env);
        return json({ ok: true, msg: `已刷新，${s.stats.combos} 个组合` });
      } catch (e) {
        return json({ ok: false, error: e.message }, 500);
      }
    }

    // 重注册 WARP 设备，MASQUE 整体不通时才用
    if (path === "/api/reset-warp" && req.method === "POST") {
      try {
        const s = await rebuild(env, { forceWarp: true });
        return json({ ok: true, msg: `WARP 已重注册，${s.stats.combos} 个组合` });
      } catch (e) {
        return json({ ok: false, error: e.message }, 500);
      }
    }

    return new Response("Not Found", { status: 404 });
  },
};
