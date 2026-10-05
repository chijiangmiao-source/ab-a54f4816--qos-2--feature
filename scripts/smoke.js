// API/HTTP 冒烟测试：
//   - GET /health 返回健康响应；
//   - 合法断链重发（DUP=1 载荷一致）经 API 裁决为 ACCEPTED 且仅一次交付；
//   - 冲突重发（闭合后再发 / 载荷冲突 / 清除会话后旧确认）经 API 裁决为 REJECTED；
//   - 同标识同输入回放原裁决、改输入复用标识被 409 拒绝且原证据保留；
//   - 未闭合会话被识别。
// 用法：BASE_URL=http://app:8080 node scripts/smoke.js
//       不设 BASE_URL 时自动在本地随机端口拉起服务。
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

let base = process.env.BASE_URL || '';
let child = null;
let tmpDir = null;

function freePort() {
  return new Promise((resolve, reject) => {
    import('node:net').then((net) => {
      const srv = net.createServer();
      srv.listen(0, '127.0.0.1', () => {
        const p = srv.address().port;
        srv.close(() => resolve(p));
      });
      srv.on('error', reject);
    });
  });
}

async function waitHealth(url, deadline = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < deadline) {
    try {
      const r = await fetch(url + '/health');
      if (r.ok) return;
    } catch { /* 尚未启动 */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('服务健康检查在时限内未就绪');
}

if (!base) {
  const port = await freePort();
  tmpDir = await mkdtemp(join(tmpdir(), 'smoke-evidence-'));
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, [join(root, 'server', 'server.js')], {
    cwd: root,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', EVIDENCE_FILE: join(tmpDir, 'evidence.jsonl') },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', () => {});
  child.stderr.on('data', (d) => process.stderr.write('[server] ' + d));
}

let passed = 0;
let failed = 0;
const failures = [];
const check = (name, cond, detail = '') => {
  if (cond) { passed++; console.log(' ✓ ' + name); }
  else { failed++; failures.push(`${name}${detail ? ` —— ${detail}` : ''}`); console.error(' ✗ ' + name + (detail ? ` —— ${detail}` : '')); }
};

const C = (cleanStart = true) => ({ type: 'CONNECT', direction: 'C2S', cleanStart });
const CA = (sessionPresent = false) => ({ type: 'CONNACK', direction: 'S2C', sessionPresent });
const P = (packetId, o = {}) => ({ type: 'PUBLISH', direction: 'C2S', qos: 2, packetId,
  topic: o.topic ?? 'sat/temp', payload: o.payload ?? '{"t":1}', dup: o.dup ?? false });
const REC = (packetId) => ({ type: 'PUBREC', direction: 'S2C', packetId });
const REL = (packetId) => ({ type: 'PUBREL', direction: 'C2S', packetId });
const COMP = (packetId) => ({ type: 'PUBCOMP', direction: 'S2C', packetId });
const DISC = (reasonCode = 0) => ({ type: 'DISCONNECT', direction: 'C2S', reasonCode });

// 每轮唯一运行标识，保证 verify 可重复执行（证据库追加不去重案例列表）
const RUN = process.env.SMOKE_UID || String(Date.now());
const uid = (name) => `${name}-${RUN}`;

async function api(path, body) {
  const r = await fetch(base + path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
  });
  return { status: r.status, json: await r.json() };
}

try {
  await waitHealth(base);

  // 1. 健康检查
  const h = await fetch(base + '/health');
  const hj = await h.json();
  check('GET /health 返回 200 且 status=ok', h.status === 200 && hj.status === 'ok',
    `实际 ${h.status}/${hj.status}`);

  // 2. 页面可获取
  const pg = await fetch(base + '/');
  const pgt = await pg.text();
  check('GET / 返回联调页面', pg.status === 200 && pgt.includes('MQTT 5 QoS'));

  // 3. 合法断链重发：PUBREC 丢失后 DUP 重发，精确交付一次
  const legal = {
    auditId: uid('SMOKE-LEGAL-ONCE'),
    clientId: 'relay-smoke-1',
    packets: [C(true), CA(false),
      P(1001), P(1001, { dup: true }), REC(1001), REL(1001), COMP(1001), DISC()]
  };
  const r1 = await api('/api/audits', legal);
  check('合法重发被固化(201)', r1.status === 201 && r1.json.status === 'SEALED');
  check('合法重发裁决 ACCEPTED', r1.json.record.evidence.verdict.verdict === 'ACCEPTED',
    r1.json.record?.evidence.verdict.reason);
  check('合法重发仅一次交付(deliveredOnce=1)',
    r1.json.record.evidence.verdict.summary.deliveredOnce === 1);

  // 4. 相同标识完全相同输入 => 回放
  const r2 = await api('/api/audits/reopen', legal);
  check('同标识同输入重开放回原裁决(REPLAYED)', r2.status === 200 && r2.json.status === 'REPLAYED');

  // 5. 相同标识改动输入 => 409 冲突拒绝，原证据保留
  const changed = JSON.parse(JSON.stringify(legal));
  changed.packets[3].payload = '{"t":999}'; // 重发载荷冲突
  const r3 = await api('/api/audits', changed);
  check('改输入复用标识返回 409', r3.status === 409 && r3.json.status === 'CONFLICT_REJECTED');
  check('冲突响应保留原裁决信息', r3.json.original?.verdict === 'ACCEPTED');

  // 6. 冲突重发被拒绝：闭合后再发同一标识（新 auditId）
  const doubleDelivery = {
    auditId: uid('SMOKE-CONFLICT-DOUBLE'),
    clientId: 'relay-smoke-1',
    packets: [C(true), CA(false),
      P(2002), REC(2002), REL(2002), COMP(2002),
      P(2002, { dup: true })]
  };
  const r4 = await api('/api/audits', doubleDelivery);
  check('闭合后冲突重发固化但裁决 REJECTED',
    r4.status === 201 && r4.json.record.evidence.verdict.verdict === 'REJECTED');
  check('冲突重发判定 DOUBLE_DELIVERY',
    r4.json.record.evidence.verdict.reason === 'DOUBLE_DELIVERY');
  check('稳定定位违规包序号=7', r4.json.record.evidence.verdict.reasonSeq === 7);

  // 7. 载荷冲突重发被拒绝
  const payloadClash = {
    auditId: uid('SMOKE-CONFLICT-PAYLOAD'), clientId: 'c',
    packets: [C(true), CA(false), P(3, { payload: 'A' }), P(3, { dup: true, payload: 'B' })]
  };
  const r5 = await api('/api/audits', payloadClash);
  check('载荷冲突重发裁决 REJECTED/PAYLOAD_CONFLICT@4',
    r5.json.record.evidence.verdict.verdict === 'REJECTED' &&
    r5.json.record.evidence.verdict.reason === 'PAYLOAD_CONFLICT' &&
    r5.json.record.evidence.verdict.reasonSeq === 4);

  // 8. Clean Start 后继续旧确认被拒绝
  const stale = {
    auditId: uid('SMOKE-CONFLICT-STALE'), clientId: 'c',
    packets: [C(false), CA(false), P(7), DISC(),
      C(true), CA(false), REL(7)]
  };
  const r6 = await api('/api/audits', stale);
  check('清除会话后继续旧确认 STALE_SESSION_USE@7',
    r6.json.record.evidence.verdict.reason === 'STALE_SESSION_USE' &&
    r6.json.record.evidence.verdict.reasonSeq === 7);

  // 9. PUBCOMP 丢失重连恢复闭合（合法）
  const recover = {
    auditId: uid('SMOKE-RECOVER-OK'), clientId: 'c',
    packets: [C(false), CA(false), P(22), REC(22), REL(22), DISC(142),
      C(false), CA(true), REL(22), COMP(22), DISC()]
  };
  const r7 = await api('/api/audits', recover);
  check('PUBCOMP丢失重连恢复裁决 ACCEPTED',
    r7.json.record.evidence.verdict.verdict === 'ACCEPTED',
    r7.json.record?.evidence.verdict.reason);
  check('恢复后仍只交付一次', r7.json.record.evidence.verdict.summary.deliveredOnce === 1);

  // 10. 未闭合会话识别（PUBCOMP 丢失且未重连）
  const unclosed = {
    auditId: uid('SMOKE-UNCLOSED'), clientId: 'c',
    packets: [C(false), CA(false), P(9), REC(9), REL(9), DISC(142)]
  };
  const r8 = await api('/api/audits', unclosed);
  check('未闭合会话裁决 REJECTED/UNCLOSED_EXCHANGE',
    r8.json.record.evidence.verdict.reason === 'UNCLOSED_EXCHANGE');
  check('未闭合定位于 PUBREL 包序号=5', r8.json.record.evidence.verdict.reasonSeq === 5);

  // 11. 录入校验错误返回 400
  const bad = { auditId: '', clientId: '', packets: [] };
  const r9 = await api('/api/audits', bad);
  check('非法录入返回 400 与字段错误', r9.status === 400 && Array.isArray(r9.json.errors));

  // 12. 案例列表包含本轮 6 条固化记录（verify 可重复运行）
  const list = await (await fetch(base + '/api/audits')).json();
  const mine = list.audits.filter((a) => a.auditId.endsWith('-' + RUN));
  check('证据列表包含本轮 6 条固化记录', mine.length === 6, `实际 ${mine.length}`);

  // 13. 原证据在冲突后仍可单独取回且仍为 ACCEPTED
  const one = await (await fetch(base + '/api/audits/' + encodeURIComponent(uid('SMOKE-LEGAL-ONCE')))).json();
  check('原证据保留: 合法重发案例仍 ACCEPTED',
    one.record.evidence.verdict.verdict === 'ACCEPTED');
} catch (e) {
  check('冒烟执行无异常: ' + e.message, false, e.stack);
} finally {
  if (child) { try { child.kill('SIGTERM'); } catch {} }
  if (tmpDir) { await rm(tmpDir, { recursive: true, force: true }); }
}

console.log(`\nAPI/HTTP 冒烟：${passed} 通过，${failed} 失败`);
if (failed) {
  console.error('失败项：');
  failures.forEach((f) => console.error(' ✗ ' + f));
  process.exit(1);
}
console.log('冒烟全部通过 ✓');
