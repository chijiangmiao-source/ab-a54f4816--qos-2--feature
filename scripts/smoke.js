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

  // 12. 案例列表包含本轮 6 条固化记录（第 14 项起的链路追溯用例在其后才固化）
  const list = await (await fetch(base + '/api/audits')).json();
  const mine = list.audits.filter((a) => a.auditId.endsWith('-' + RUN));
  check('证据列表包含本轮 6 条固化记录', mine.length === 6, `实际 ${mine.length}`);

  // 13. 原证据在冲突后仍可单独取回且仍为 ACCEPTED
  const one = await (await fetch(base + '/api/audits/' + encodeURIComponent(uid('SMOKE-LEGAL-ONCE')))).json();
  check('原证据保留: 合法重发案例仍 ACCEPTED',
    one.record.evidence.verdict.verdict === 'ACCEPTED');

  // ==================== 首发交换链路追溯（经真实 HTTP，只读） ====================
  const getJson = async (pathname) => {
    const r = await fetch(base + pathname);
    return { status: r.status, json: await r.json() };
  };
  const traceUrl = (id, seq) => '/api/audits/' + encodeURIComponent(id) + '/trace?seq=' + seq;
  const idOnly = (t) => t.steps.filter((s) => s.role !== 'SESSION_BOUNDARY').map((s) => s.seq);

  // 14. 正常闭合链路
  const tNormal = {
    auditId: uid('SMOKE-TRACE-NORMAL'), clientId: 'c',
    packets: [C(true), CA(false), P(11), REC(11), REL(11), COMP(11), DISC()]
  };
  await api('/api/audits', tNormal);
  const o1 = await getJson('/api/audits/' + encodeURIComponent(tNormal.auditId) + '/trace/origins');
  check('追溯: origins 接口 200 且列首发@3', o1.status === 200 &&
    Array.isArray(o1.json.origins) && o1.json.origins[0].seq === 3 && o1.json.origins[0].packetId === 11);
  const g1 = await getJson(traceUrl(tNormal.auditId, 3));
  check('追溯: 正常闭合 200 TRACED', g1.status === 200 && g1.json.status === 'TRACED');
  const tr1 = g1.json.trace;
  check('追溯: 正常闭合 CLOSED@6 唯一交付',
    tr1.termination.kind === 'CLOSED' && tr1.termination.seq === 6 && tr1.deliveredOnce === true &&
    tr1.uniqueDelivery.pubcompSeq === 6);
  check('追溯: 逐项原始序号 [3,4,5,6]', JSON.stringify(idOnly(tr1)) === '[3,4,5,6]');
  check('追溯: 逐项连接编号均为 1', tr1.steps.every((s) => s.connection === 1));
  check('追溯: 阶段变化 INFLIGHT→REC_RCVD→REL_SENT→CLOSED',
    JSON.stringify(tr1.steps.filter((s) => s.role !== 'SESSION_BOUNDARY').map((s) => s.phase))
      === '["INFLIGHT","REC_RCVD","REL_SENT","CLOSED"]');
  check('追溯: 确认关系 PUBREL 应答 PUBREC@4 / PUBCOMP 应答 PUBREL@5',
    tr1.steps.find((s) => s.seq === 5).acknowledges === 4 &&
    tr1.steps.find((s) => s.seq === 6).acknowledges === 5);

  // 15. 跨重连恢复链路（PUBCOMP 丢失，CS=0/SP=1，重传 PUBREL）
  const tRecover = {
    auditId: uid('SMOKE-TRACE-RECOVER'), clientId: 'c',
    packets: [C(false), CA(false), P(33), REC(33), REL(33), DISC(142),
      C(false), CA(true), REL(33), COMP(33), DISC()]
  };
  await api('/api/audits', tRecover);
  const g2 = await getJson(traceUrl(tRecover.auditId, 3));
  const tr2 = g2.json.trace;
  check('追溯: 重连恢复 CLOSED@10 且唯一交付',
    g2.status === 200 && tr2.termination.kind === 'CLOSED' &&
    tr2.termination.seq === 10 && tr2.deliveredOnce === true);
  check('追溯: 跨连接衔接序号 [3,4,5,9,10]', JSON.stringify(idOnly(tr2)) === '[3,4,5,9,10]');
  check('追溯: PUBREL@9 属第 2 条连接且 ack 前一 PUBREL@5',
    tr2.steps.find((s) => s.seq === 9).connection === 2 &&
    tr2.steps.find((s) => s.seq === 9).acknowledges === 5);
  check('追溯: 恢复段 CS=0/SP=1 沿用首发@3',
    tr2.crossConnection === true && tr2.recovery.length === 1 &&
    tr2.recovery[0].resumed === true && tr2.recovery[0].cleanStart === false &&
    tr2.recovery[0].sessionPresent === true && tr2.recovery[0].continuesFirstDeliverySeq === 3);
  check('追溯: 恢复说明声明沿用首次交付且不产生新交付',
    /沿用第 3 包首发的同一交付/.test(tr2.recovery[0].note));

  // 16. 标识复用边界：闭合后 DUP 重用，链路终止于拒绝
  const tReuse = {
    auditId: uid('SMOKE-TRACE-REUSE'), clientId: 'c',
    packets: [C(true), CA(false), P(44), REC(44), REL(44), COMP(44), P(44, { dup: true })]
  };
  await api('/api/audits', tReuse);
  const g3 = await getJson(traceUrl(tReuse.auditId, 3));
  const tr3 = g3.json.trace;
  check('追溯: 闭合后重用终止 REJECTED@7/DOUBLE_DELIVERY',
    tr3.termination.kind === 'REJECTED' && tr3.termination.seq === 7 &&
    tr3.termination.code === 'DOUBLE_DELIVERY');
  check('追溯: 首发唯一交付仍成立(PUBCOMP@6)', tr3.deliveredOnce === true);
  check('追溯: 重用包不被当作合法重放',
    tr3.steps.find((s) => s.seq === 7).role === 'REUSE_AFTER_TERMINATION' &&
    tr3.steps.find((s) => s.seq === 7).violation.code === 'DOUBLE_DELIVERY');

  // 17. 同标识两次不同首发（未交付被 Clean Start 清除，新会话复用）互不混淆
  const tMulti = {
    auditId: uid('SMOKE-TRACE-MULTI'), clientId: 'c',
    packets: [C(false), CA(false), P(55), DISC(), C(true), CA(false),
      P(55), REC(55), REL(55), COMP(55), DISC()]
  };
  await api('/api/audits', tMulti);
  const o4 = await getJson('/api/audits/' + encodeURIComponent(tMulti.auditId) + '/trace/origins');
  check('追溯: 同标识列两个首发 @3/@7', o4.status === 200 &&
    o4.json.origins.length === 2 && o4.json.origins.every((x) => x.packetId === 55) &&
    o4.json.origins[0].seq === 3 && o4.json.origins[1].seq === 7);
  const g4a = await getJson(traceUrl(tMulti.auditId, 3));
  const g4b = await getJson(traceUrl(tMulti.auditId, 7));
  check('追溯: 首发@3 链路终止 CLEAN_START@5 无交付',
    g4a.json.trace.termination.kind === 'CLEAN_START' &&
    g4a.json.trace.termination.seq === 5 && g4a.json.trace.deliveredOnce === false);
  check('追溯: 首发@7 链路 CLOSED@10 唯一交付',
    g4b.json.trace.termination.kind === 'CLOSED' &&
    g4b.json.trace.termination.seq === 10 && g4b.json.trace.deliveredOnce === true);
  const sa = new Set(idOnly(g4a.json.trace)); const sb = new Set(idOnly(g4b.json.trace));
  check('追溯: 两条链路标识报文互不相交', [...sa].every((x) => !sb.has(x)));
  check('追溯: 首发@3 排除新首发报文(7..10)',
    JSON.stringify(g4a.json.trace.excludedSameIdPackets.map((e) => e.seq)) === '[7,8,9,10]');
  check('追溯: 首发@7 排除旧首发@3',
    JSON.stringify(g4b.json.trace.excludedSameIdPackets.map((e) => e.seq)) === '[3]');

  // 18. 错误查询：未知审计 / 越界 / 非首发 / 缺 seq —— 且冻结证据不被改写
  const recordsBefore = (await (await fetch(base + '/health')).json()).records;
  const e1 = await getJson('/api/audits/' + encodeURIComponent(uid('NO-SUCH-AUDIT')) + '/trace?seq=1');
  check('追溯: 未知审计 404', e1.status === 404 && e1.json.code === 'AUDIT_ID_NOT_FOUND');
  const e2 = await getJson(traceUrl(tNormal.auditId, 999));
  check('追溯: 越界序号 400 SEQ_OUT_OF_RANGE', e2.status === 400 && e2.json.code === 'SEQ_OUT_OF_RANGE');
  const e3 = await getJson(traceUrl(tNormal.auditId, 4)); // 第 4 包是 PUBREC
  check('追溯: 非首发(PUBREC) 422 NOT_AN_ORIGIN', e3.status === 422 && e3.json.code === 'NOT_AN_ORIGIN');
  const e4 = await getJson('/api/audits/' + encodeURIComponent(tNormal.auditId) + '/trace');
  check('追溯: 缺 seq 422 SEQ_REQUIRED', e4.status === 422 && e4.json.code === 'SEQ_REQUIRED');
  const e5 = await getJson(traceUrl(tReuse.auditId, 7)); // 闭合后重用包
  check('追溯: 重用包不能作为首发 422', e5.status === 422 && e5.json.code === 'NOT_AN_ORIGIN');
  const recordsAfter = (await (await fetch(base + '/health')).json()).records;
  check('追溯: 只读不改写冻结证据(记录数不变)', recordsBefore === recordsAfter,
    `${recordsBefore} -> ${recordsAfter}`);
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
