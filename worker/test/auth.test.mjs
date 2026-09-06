// 鉴权底层函数测试。跑: node test/auth.test.mjs
import { safeEqual, signToken, verifyToken, rateLimit, clearRateLimit } from "../src/auth.js";

const S = "correct-horse-battery";
let pass = 0, fail = 0;
const t = (n, c) => { c ? (pass++, console.log("  ✓", n)) : (fail++, console.log("  ✗", n)); };

t("相同串相等", safeEqual("abc", "abc"));
t("不同串不等", !safeEqual("abc", "abd"));
t("长度不同不等", !safeEqual("abc", "abcd"));
t("空值不等", !safeEqual("", "x"));

const tok = await signToken(S);
t("签发的 token 通过", await verifyToken(S, tok));
t("错密码不通过", !(await verifyToken("wrong", tok)));
t("篡改签名不通过", !(await verifyToken(S, tok.slice(0, -2) + "xy")));
t("伪造时间戳不通过", !(await verifyToken(S, "99999999999999." + tok.split(".")[1])));
t("过期 token 不通过", !(await verifyToken(S, "1000000000000.abc")));
t("空 token 不通过", !(await verifyToken(S, "")));
t("无点号不通过", !(await verifyToken(S, "garbage")));

const kv = { m: new Map(),
  async get(k) { return this.m.get(k); },
  async put(k, v) { this.m.set(k, v); },
  async delete(k) { this.m.delete(k); } };
let allowed = 0;
for (let i = 0; i < 12; i++) if (await rateLimit({ KV: kv }, "1.2.3.4")) allowed++;
t(`限速第 8 次后拦截 (放行 ${allowed} 次)`, allowed === 8);
await clearRateLimit({ KV: kv }, "1.2.3.4");
t("登录成功后重置限速", await rateLimit({ KV: kv }, "1.2.3.4"));

console.log(`\n通过 ${pass} 失败 ${fail}`);
if (fail) process.exit(1);
