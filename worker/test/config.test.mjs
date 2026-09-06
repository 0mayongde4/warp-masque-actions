// 配置结构测试。跑: node test/config.test.mjs
import { buildConfig } from "../src/config.js";

const warp = {
  privateKey: "MGsCAQEEIFAKE", peerPublicKey: "MFkwEwFAKE",
  ipv4: "172.16.0.2", ipv6: "2606:4700:110::1",
  deviceId: "x", registeredAt: new Date().toISOString(),
};
const opera = {
  username: "USER", password: "PASS",
  landings: [
    { tag: "亚洲1", loc: "亚洲", ip: "77.111.245.1", port: 443, host: "as0.sec-tunnel.com" },
    { tag: "欧洲1", loc: "欧洲", ip: "77.111.247.1", port: 443, host: "eu0.sec-tunnel.com" },
  ],
};

let pass = 0, fail = 0;
const t = (n, c) => { c ? (pass++, console.log("  ✓", n)) : (fail++, console.log("  ✗", n)); };

const { yaml, entries, combos } = buildConfig(warp, opera);
const groups = [...yaml.matchAll(/^  - name: (.+)$/gm)].map((m) => m[1]);
const proxyNames = [...yaml.matchAll(/^  - \{name: "([^"]+)"/gm)].map((m) => m[1]);
const entryNames = [...yaml.matchAll(/^  - name: (\S+)\n    type: masque$/gm)].map((m) => m[1]);

t(`接入点 ${entries} 个`, entries === 41);
t(`组合 ${combos} 个 (41 x 2)`, combos === 82);
t("有 WARP直连 组", groups.includes("WARP直连"));
t("有三个地区组",
  ["亚洲线路", "欧洲线路"].every((g) => groups.includes(g)));

// WARP直连 组的成员必须都是接入点，不能混进组合节点
const warpGroup = yaml.split("  - name: WARP直连")[1].split("\n  - name:")[0];
const members = [...warpGroup.matchAll(/^      - "([^"]+)"$/gm)].map((m) => m[1]);
t(`WARP直连 有 ${members.length} 个成员`, members.length === 41);
t("成员都是接入点(不含 @)", members.every((m) => !m.includes("@")));
t("成员都在 proxies 里定义", members.every((m) => entryNames.includes(m)));

// 节点选择里要同时有地区组和直连
const sel = yaml.split("  - name: 🚀 节点选择")[1].split("\n  - name:")[0];
t("节点选择含 WARP直连", sel.includes("WARP直连"));
t("节点选择含地区线路", sel.includes("亚洲线路"));

// 组合节点必须带 dialer-proxy，直连节点必须不带
t("组合节点都带 dialer-proxy",
  (yaml.match(/dialer-proxy:/g) || []).length === combos);
t("组合节点名格式正确", proxyNames.every((n) => /^[\u4e00-\u9fa5]+\d+@/.test(n)));

// 不能有悬空引用
const groupSection = yaml.slice(yaml.indexOf("proxy-groups:"), yaml.indexOf("rule-providers:"));
const allRefs = [...groupSection.matchAll(/^      - "?([^"\n]+)"?$/gm)].map((m) => m[1].trim());
const defined = new Set([...groups, ...proxyNames, ...entryNames, "DIRECT", "REJECT"]);
const dangling = [...new Set(allRefs.filter((r) => !defined.has(r)))];
t(`无悬空引用${dangling.length ? " (" + dangling.slice(0, 3) + ")" : ""}`, dangling.length === 0);

console.log(`\n通过 ${pass} 失败 ${fail}`);
if (fail) process.exit(1);
