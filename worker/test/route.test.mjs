// 路由级测试：mock env，验证鉴权真的挡住了该挡的
import worker from '../src/index.js';
import { signToken } from '../src/auth.js';

const PW = 'test-password-123';
const kv = new Map();
const env = {
  PASSWORD: PW,
  SUB_PATH: 'my-secret',
  KV: {
    async get(k, t) { const v = kv.get(k); return t === 'json' && v ? JSON.parse(v) : v ?? null; },
    async put(k, v) { kv.set(k, v); },
    async delete(k) { kv.delete(k); },
  },
};
kv.set('config:yaml', '# fake config\nproxies: []');
kv.set('state:meta', JSON.stringify({ updatedAt: new Date().toISOString(), stats: { entries: 41, landings: 12, combos: 492 }, warp: {} }));

const req = (path, opt = {}) => new Request(`https://x.dev${path}`, {
  headers: { 'cf-connecting-ip': '9.9.9.9', ...(opt.headers || {}) },
  method: opt.method || 'GET',
  body: opt.body,
});

let pass = 0, fail = 0;
const t = (n, c) => { c ? (pass++, console.log('  ✓', n)) : (fail++, console.log('  ✗', n)); };

// 未登录
t('未登录访问 / 返回登录页',
  (await worker.fetch(req('/'), env)).status === 200 &&
  (await (await worker.fetch(req('/'), env)).text()).includes('Auth Required'));

t('未登录 /api/state 404',
  (await worker.fetch(req('/api/state'), env)).status === 404);

t('未登录 /api/refresh 404',
  (await worker.fetch(req('/api/refresh', { method: 'POST' }), env)).status === 404);

t('无 token 访问订阅 404',
  (await worker.fetch(req('/my-secret'), env)).status === 404);

t('错 token 访问订阅 404',
  (await worker.fetch(req('/my-secret?token=bogus.sig'), env)).status === 404);

t('默认 /sub 路径不存在(已改名) 404',
  (await worker.fetch(req('/sub'), env)).status === 404);

// 登录
const bad = await worker.fetch(req('/login', {
  method: 'POST', body: JSON.stringify({ password: 'wrong' }) }), env);
t('错密码登录 401', bad.status === 401);

const ok = await worker.fetch(req('/login', {
  method: 'POST', body: JSON.stringify({ password: PW }) }), env);
const setc = ok.headers.get('set-cookie') || '';
t('对密码登录 200', ok.status === 200);
t('cookie 带 HttpOnly', setc.includes('HttpOnly'));
t('cookie 带 Secure', setc.includes('Secure'));
t('cookie 带 SameSite', setc.includes('SameSite'));
t('cookie 里不含密码明文', !setc.includes(PW));

const cookie = setc.split(';')[0];
const authed = { headers: { cookie } };

t('登录后 / 出状态页',
  (await (await worker.fetch(req('/', authed), env)).text()).includes('Opera over MASQUE'));
t('登录后 /api/state 200',
  (await worker.fetch(req('/api/state', authed), env)).status === 200);

// 订阅 token
const tok = await signToken(PW);
const sub = await worker.fetch(req(`/my-secret?token=${tok}`), env);
t('有效 token 拿到订阅', sub.status === 200);
t('订阅是 yaml', (sub.headers.get('content-type') || '').includes('yaml'));
t('订阅带更新间隔头', sub.headers.get('profile-update-interval') === '4');
t('订阅 no-store', (sub.headers.get('cache-control') || '').includes('no-store'));

// 改密码应使旧 token 失效
const tok2 = await signToken('another-password');
t('别的密码签的 token 无效',
  (await worker.fetch(req(`/my-secret?token=${tok2}`), env)).status === 404);

// 未设密码
t('未设 PASSWORD 时拒绝服务',
  (await worker.fetch(req('/'), { ...env, PASSWORD: '' })).status === 500);

console.log(`\n通过 ${pass} 失败 ${fail}`);
if (fail) process.exit(1);
