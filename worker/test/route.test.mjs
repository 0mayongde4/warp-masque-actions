// 路由级测试：mock env，验证首次初始化、鉴权、UI 改配置都对。
// 跑: node test/route.test.mjs
import worker from "../src/index.js";

const PW = "test-password-123";
let kv, env;

function reset() {
  kv = new Map();
  env = {
    KV: {
      async get(k, t) { const v = kv.get(k); return t === "json" && v ? JSON.parse(v) : v ?? null; },
      async put(k, v) { kv.set(k, v); },
      async delete(k) { kv.delete(k); },
    },
  };
}

const req = (path, opt = {}) => new Request(`https://x.dev${path}`, {
  headers: { "cf-connecting-ip": "9.9.9.9", ...(opt.headers || {}) },
  method: opt.method || "GET",
  body: opt.body,
});
const post = (p, body, headers) =>
  req(p, { method: "POST", body: JSON.stringify(body), headers });

let pass = 0, fail = 0;
const t = (n, c) => { c ? (pass++, console.log("  ✓", n)) : (fail++, console.log("  ✗", n)); };

// ---- KV 未绑 ----
t("KV 未绑给指引页",
  (await (await worker.fetch(req("/"), {})).text()).includes("KV Not Bound"));

// ---- 首次初始化 ----
reset();
t("没设密码时 / 出初始化页",
  (await (await worker.fetch(req("/"), env)).text()).includes("First Run"));
t("没设密码时其他路径 404",
  (await worker.fetch(req("/api/state"), env)).status === 404);
t("密码太短被拒",
  (await worker.fetch(post("/api/setup", { password: "short", confirm: "short" }), env)).status === 400);
t("两次不一致被拒",
  (await worker.fetch(post("/api/setup", { password: "longenough1", confirm: "other" }), env)).status === 400);

const setup = await worker.fetch(post("/api/setup", { password: PW, confirm: PW }), env);
const setc = setup.headers.get("set-cookie") || "";
t("设置密码成功", setup.status === 200);
t("直接下发会话 cookie", setc.includes("om_session="));
t("cookie 带 HttpOnly", setc.includes("HttpOnly"));
t("cookie 带 Secure", setc.includes("Secure"));
t("cookie 带 SameSite", setc.includes("SameSite"));
t("cookie 不含密码明文", !setc.includes(PW));
t("KV 里不存密码明文", !JSON.stringify([...kv.values()]).includes(PW));
// 已初始化后 /api/setup 走未登录分支返回 404 —— 不泄露"已初始化"这个事实
t("已初始化后 /api/setup 不可用",
  (await worker.fetch(post("/api/setup", { password: "another123", confirm: "another123" }), env)).status === 404);

// 真正的竞态：两个请求同时读到 cred 为空
{
  const k2 = new Map();
  const e2 = { KV: {
    async get(k, t) { const v = k2.get(k); return t === "json" && v ? JSON.parse(v) : v ?? null; },
    async put(k, v) { k2.set(k, v); },
    async delete(k) { k2.delete(k); } } };
  const [a, b] = await Promise.all([
    worker.fetch(post("/api/setup", { password: "racer-aaa1", confirm: "racer-aaa1" }), e2),
    worker.fetch(post("/api/setup", { password: "racer-bbb1", confirm: "racer-bbb1" }), e2),
  ]);
  const codes = [a.status, b.status].sort();
  t(`并发初始化只成功一个 (${codes.join("/")})`, codes[0] === 200 && codes[1] === 409);
}

const cookie = setc.split(";")[0];
const auth = { cookie };

// ---- 已初始化后的鉴权 ----
t("设完密码后 / 出状态页",
  (await (await worker.fetch(req("/", { headers: auth }), env)).text()).includes("Opera over MASQUE"));
t("退出后 / 出登录页",
  (await (await worker.fetch(req("/"), env)).text()).includes("Auth Required"));
t("未登录 /api/state 404",
  (await worker.fetch(req("/api/state"), env)).status === 404);
t("错密码登录 401",
  (await worker.fetch(post("/login", { password: "nope" }), env)).status === 401);
t("对密码登录 200",
  (await worker.fetch(post("/login", { password: PW }), env)).status === 200);

// ---- 订阅 ----
kv.set("config:yaml", "# fake\nproxies: []");
const home = await (await worker.fetch(req("/", { headers: auth }), env)).text();
const tok = (home.match(/token=([\w.\-]+)/) || [])[1];
t("状态页给出带 token 的订阅链接", !!tok);

const sub = await worker.fetch(req(`/sub?token=${tok}`), env);
t("默认路径 /sub 带 token 可取", sub.status === 200);
t("订阅是 yaml", (sub.headers.get("content-type") || "").includes("yaml"));
t("订阅带更新间隔头", sub.headers.get("profile-update-interval") === "4");
// 文件名不能带引号：部分客户端不解析，会把 \"x\" 当成文件名显示出来
t("文件名不带引号",
  sub.headers.get("content-disposition") === "attachment; filename=opera-masque.yaml");
t("无 token 取订阅 404", (await worker.fetch(req("/sub"), env)).status === 404);
t("错 token 取订阅 404", (await worker.fetch(req("/sub?token=bad.sig"), env)).status === 404);

// ---- UI 改订阅路径 ----
t("非法路径被拒",
  (await worker.fetch(post("/api/sub-path", { path: "a/b" }, auth), env)).status === 400);
t("保留字被拒",
  (await worker.fetch(post("/api/sub-path", { path: "api" }, auth), env)).status === 400);
t("改路径成功",
  (await worker.fetch(post("/api/sub-path", { path: "my-secret" }, auth), env)).status === 200);
t("新路径生效", (await worker.fetch(req(`/my-secret?token=${tok}`), env)).status === 200);
t("旧路径失效", (await worker.fetch(req(`/sub?token=${tok}`), env)).status === 404);


// ---- UI 改密码 ----
t("当前密码不对时拒绝改",
  (await worker.fetch(post("/api/password",
    { current: "wrong", password: "brandnew123", confirm: "brandnew123" }, auth), env)).status === 401);
t("新密码太短被拒",
  (await worker.fetch(post("/api/password",
    { current: PW, password: "x1", confirm: "x1" }, auth), env)).status === 400);

const chg = await worker.fetch(post("/api/password",
  { current: PW, password: "brandnew123", confirm: "brandnew123" }, auth), env);
t("改密码成功", chg.status === 200);
t("改密码后重新下发 cookie", (chg.headers.get("set-cookie") || "").includes("om_session="));
t("改密码后旧订阅 token 失效",
  (await worker.fetch(req(`/my-secret?token=${tok}`), env)).status === 404);
t("旧密码登不上",
  (await worker.fetch(post("/login", { password: PW }), env)).status === 401);
t("新密码能登上",
  (await worker.fetch(post("/login", { password: "brandnew123" }), env)).status === 200);

// ---- 按需重建：没过期用缓存，过期才重建 ----
{
  reset();
  await worker.fetch(post("/api/setup", { password: PW, confirm: PW }), env);
  const c2 = (await worker.fetch(post("/login", { password: PW }), env))
    .headers.get("set-cookie").split(";")[0];
  const a2 = { cookie: c2 };
  const h2 = await (await worker.fetch(req("/", { headers: a2 }), env)).text();
  const tk = (h2.match(/token=([\w.\-]+)/) || [])[1];

  // 放一份"还没过期"的配置，访问订阅不应触发重建
  kv.set("config:yaml", "# cached\nproxies: []");
  kv.set("state:meta", JSON.stringify({
    updatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3 * 3600 * 1000).toISOString(),
    stats: {}, warp: {},
  }));
  const r1 = await worker.fetch(req(`/sub?token=${tk}`), env);
  t("未过期直接给缓存", (await r1.text()).includes("# cached"));

  // 标记为已过期，此时该重建。这里不真的联网，用锁占住来验证走了重建分支
  kv.set("state:meta", JSON.stringify({
    updatedAt: new Date(Date.now() - 5 * 3600 * 1000).toISOString(),
    expiresAt: new Date(Date.now() - 3600 * 1000).toISOString(),
    stats: {}, warp: {},
  }));
  kv.set("rebuild:lock", String(Date.now()));   // 假装别人在重建
  const r2 = await worker.fetch(req(`/sub?token=${tk}`), env);
  t("过期但有人在重建时用旧配置顶住", (await r2.text()).includes("# cached"));

  kv.delete("rebuild:lock");
  kv.delete("config:yaml");
  kv.set("state:meta", JSON.stringify({ expiresAt: new Date(Date.now() - 1).toISOString() }));
  kv.set("rebuild:lock", String(Date.now()));
  const r3 = await worker.fetch(req(`/sub?token=${tk}`), env);
  t("过期且无缓存又拿不到锁时给 503", r3.status === 503);
}

// ---- 过期判定 ----
{
  reset();
  await worker.fetch(post("/api/setup", { password: PW, confirm: PW }), env);
  const st = await (await worker.fetch(req("/api/state",
    { headers: { cookie: (await worker.fetch(post("/login", { password: PW }), env))
      .headers.get("set-cookie").split(";")[0] } }), env)).json();
  t("初始无配置时 state 为空", Object.keys(st).length === 0);
}

console.log(`\n通过 ${pass} 失败 ${fail}`);
if (fail) process.exit(1);
