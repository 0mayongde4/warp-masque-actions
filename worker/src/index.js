// Opera VPN over Cloudflare WARP (MASQUE) —— Worker 版
//
// 职责:
//   1. 每 4 小时由 cron 触发，重新拿 Opera 凭据并重建配置
//   2. WARP 注册信息存 KV 复用，不每次重注册（设备是有限资源）
//   3. /sub 出订阅，/ 出状态页
import { registerWarp } from "./warp.js";
import { fetchOpera } from "./opera.js";
import { buildConfig } from "./config.js";
import { renderUI } from "./ui.js";

const K_WARP = "warp:device";     // WARP 注册信息，长期复用
const K_CFG = "config:yaml";      // 生成好的配置
const K_STATE = "state:meta";     // 状态元数据，给 UI 用

const json = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

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

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(rebuild(env).catch((e) => console.error("定时重建失败:", e.message)));
  },

  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    // 订阅：没有就现生成一份
    if (path === "/sub" || path === "/config" || path === "/clash") {
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
        },
      });
    }

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

    if (path === "/") {
      const state = await env.KV.get(K_STATE, "json");
      return new Response(renderUI(state, url.host), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};
