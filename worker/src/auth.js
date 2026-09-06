// 鉴权。线上跑的东西，几个点必须做到：
//   - 常数时间比较，别让密码长度和内容从响应时间里漏出去
//   - 会话用签名 token，不是把密码存 cookie
//   - 登录失败要限速，否则弱密码几分钟就被爆出来
const enc = new TextEncoder();

/** 常数时间字符串比较。长度不同直接败，但仍走完比较避免时序差异。 */
export function safeEqual(a, b) {
  const x = enc.encode(a || "");
  const y = enc.encode(b || "");
  // 长度本身会泄露，但比逐字符提前返回好得多；
  // 这里用固定轮数把长度差异也吃进去
  const n = Math.max(x.length, y.length);
  let diff = x.length ^ y.length;
  for (let i = 0; i < n; i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const TTL = 7 * 24 * 3600 * 1000;   // 会话 7 天

/** 签一个会话 token，内容只有过期时间戳。 */
export async function signToken(secret) {
  const exp = Date.now() + TTL;
  return `${exp}.${await hmac(secret, String(exp))}`;
}

export async function verifyToken(secret, token) {
  if (!token || !token.includes(".")) return false;
  const i = token.lastIndexOf(".");
  const exp = token.slice(0, i);
  const sig = token.slice(i + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  return safeEqual(sig, await hmac(secret, exp));
}

export function readCookie(req, name) {
  const raw = req.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

/** 登录限速：同一 IP 15 分钟内失败 8 次就锁 15 分钟。 */
export async function rateLimit(env, ip) {
  const key = `rl:${ip}`;
  const n = Number((await env.KV.get(key)) || 0);
  if (n >= 8) return false;
  await env.KV.put(key, String(n + 1), { expirationTtl: 900 });
  return true;
}

export async function clearRateLimit(env, ip) {
  await env.KV.delete(`rl:${ip}`);
}
