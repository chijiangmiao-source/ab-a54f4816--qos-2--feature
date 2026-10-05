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

  // ================= 首发交换链路追溯（真实只读接口） =================
  const apiGet = async (p) => {
    const r = await fetch(base + p);
    return { status: r.status, json: await r.json() };
  };

  // 14. 正常闭合链路
  {
    const id = uid('SMOKE-TRACE-NORMAL');
    const body = { auditId: id, clientId: 'c',
      packets: [C(true), CA(false), P(1), REC(1), REL(1), COMP(1), DISC()] };
    const seal = await api('/api/audits', body);
    const o = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace-origins`);
    check('正常闭合: 首发清单仅首发#3 CLOSED',
      o.status === 200 && o.json.traceOrigins.length === 1 &&
      o.json.traceOrigins[0].originSeq === 3 && o.json.traceOrigins[0].status === 'CLOSED' &&
      o.json.traceOrigins[0].deliverySeq === 6);
    const t = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/3`);
    const c = t.json.chain;
    check('正常闭合: 链路 CLOSED@6 且唯一交付',
      t.status === 200 && c.endReason === 'CLOSED' && c.endSeq === 6 &&
      c.uniqueDelivery.produced === true && c.uniqueDelivery.deliverySeq === 6);
    const real = c.steps.filter((s) => !s.bridge).map((s) => s.seq);
    check('正常闭合: 有序成员 3..6', JSON.stringify(real) === JSON.stringify([3, 4, 5, 6]), JSON.stringify(real));
    check('正常闭合: 逐项带连接编号/阶段变化/确认关系',
      c.steps.every((s) => Number.isInteger(s.connection) && !!s.phaseChange) &&
      c.steps.find((s) => s.seq === 5).acknowledgesSeq === 4 &&
      c.steps.find((s) => s.seq === 6).acknowledgesSeq === 5);
    check('正常闭合: 标记 frozen（派生只读）', c.frozen === true);
  }

  // 15. 跨重连恢复链路（PUBCOMP 丢失，CS=0/SP=1，重传 PUBREL 跨连接衔接）
  {
    const id = uid('SMOKE-TRACE-RECOVER');
    const body = { auditId: id, clientId: 'c', packets: [
      C(false), CA(false), P(22), REC(22), REL(22), DISC(142),
      C(false), CA(true), REL(22), COMP(22), DISC()] };
    await api('/api/audits', body);
    const t = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/3`);
    const c = t.json.chain;
    check('跨重连: CLOSED@10 仍唯一交付',
      c.endReason === 'CLOSED' && c.uniqueDelivery.produced === true && c.uniqueDelivery.deliverySeq === 10);
    const bridges = c.steps.filter((s) => s.bridge).map((s) => s.seq);
    check('跨重连: 桥接含 CONNECT#2(7)/CONNACK(8)', JSON.stringify(bridges) === JSON.stringify([7, 8]));
    const connStep = c.steps.find((s) => s.seq === 7);
    const ackStep = c.steps.find((s) => s.seq === 8);
    const retry = c.steps.find((s) => s.seq === 9);
    check('跨重连: 桥接 CS=0 + SP=1', connStep.cleanStart === false && ackStep.sessionPresent === true);
    check('跨重连: 重传 PUBREL 跨连接并重传第5包',
      retry.crossConnection === true && retry.ackRole === 'PUBREL_RETRY' && retry.retransmitsSeq === 5);
    check('跨重连: 说明沿用第3包首次交付', /沿用第 3 包首发/.test(retry.crossRecovery));
    check('跨重连: 首发连接1→重传连接2',
      c.steps.find((s) => s.seq === 3).connection === 1 && retry.connection === 2);
  }

  // 16. 标识复用边界：旧链被 Clean Start 终止，新首发独立闭合，两链互不混淆
  {
    const id = uid('SMOKE-TRACE-REUSE');
    const body = { auditId: id, clientId: 'c', packets: [
      C(false), CA(false), P(8), REC(8), DISC(),
      C(true), CA(false), P(8), REC(8), REL(8), COMP(8), DISC()] };
    const seal = await api('/api/audits', body);
    check('标识复用: 整案仍可固化(新链合法)', seal.status === 201);
    const o = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace-origins`);
    check('标识复用: 同标识列出两个首发(3 与 8)',
      o.json.traceOrigins.length === 2 &&
      JSON.stringify(o.json.traceOrigins.map((x) => x.originSeq)) === JSON.stringify([3, 8]));
    const oldT = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/3`);
    const oldC = oldT.json.chain;
    check('旧链: 被 Clean Start 终止@6', oldC.endReason === 'TERMINATED_CLEAN_START' && oldC.endSeq === 6);
    check('旧链: 不含新首发/新确认(8..11)',
      oldC.steps.filter((s) => !s.bridge).every((s) => s.seq < 8));
    check('旧链: 边界指向新首发且不并入',
      oldC.boundaryEvents.some((b) => b.seq === 8 && b.relation === 'REUSED_BY_NEW_ORIGIN' && b.otherOriginSeq === 8));
    check('旧链: 无唯一交付', oldC.uniqueDelivery.produced === false);
    const newT = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/8`);
    const newC = newT.json.chain;
    check('新链: 独立 CLOSED@11 唯一交付',
      newC.endReason === 'CLOSED' && newC.uniqueDelivery.deliverySeq === 11 &&
      JSON.stringify(newC.steps.filter((s) => !s.bridge).map((s) => s.seq)) === JSON.stringify([8, 9, 10, 11]));
  }

  // 17. 闭合后重用标识：前一链止于闭合，重用为边界
  {
    const id = uid('SMOKE-TRACE-AFTERCLOSE');
    const body = { auditId: id, clientId: 'c',
      packets: [C(true), CA(false), P(5), REC(5), REL(5), COMP(5), P(5, { dup: true })] };
    await api('/api/audits', body);
    const t = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/3`);
    const c = t.json.chain;
    check('闭合后重用: 链止于闭合@6', c.endReason === 'CLOSED' && c.endSeq === 6);
    check('闭合后重用: 重发包#7 仅作 REUSE_AFTER_CLOSE 边界',
      !c.steps.some((s) => s.seq === 7) &&
      c.boundaryEvents.some((b) => b.seq === 7 && b.relation === 'REUSE_AFTER_CLOSE'));
  }

  // 18. 错误查询：未知审计 / 越界序号 / 非首发 / 非整数，均明确反馈且证据不变
  {
    const id = uid('SMOKE-TRACE-ERRORS');
    const body = { auditId: id, clientId: 'c',
      packets: [C(true), CA(false), P(1), REC(1), REL(1), COMP(1), DISC()] };
    await api('/api/audits', body);
    const nf = await apiGet('/api/audits/NO-SUCH-AUDIT-999/trace-origins');
    check('未知审计: 首发清单 404', nf.status === 404 && nf.json.code === 'AUDIT_ID_NOT_FOUND');
    const nf2 = await apiGet('/api/audits/NO-SUCH-AUDIT-999/trace/3');
    check('未知审计: 链路 404', nf2.status === 404 && nf2.json.code === 'AUDIT_ID_NOT_FOUND');
    const oor = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/99`);
    check('越界序号: 400 ORIGIN_SEQ_OUT_OF_RANGE',
      oor.status === 400 && oor.json.code === 'ORIGIN_SEQ_OUT_OF_RANGE');
    const neg = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/0`);
    check('序号0: 400 越界', neg.status === 400 && neg.json.code === 'ORIGIN_SEQ_OUT_OF_RANGE');
    const notOrigin = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/4`);
    check('非首发(PUBREC): 400 NOT_TRACEABLE_ORIGIN',
      notOrigin.status === 400 && notOrigin.json.code === 'NOT_TRACEABLE_ORIGIN');
    const nan = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/abc`);
    check('非整数序号: 400 ORIGIN_SEQ_INVALID',
      nan.status === 400 && nan.json.code === 'ORIGIN_SEQ_INVALID');
  }

  // 19. 错误链路查询不改写冻结证据：记录数与哈希链不变，原证据可回放
  {
    const id = uid('SMOKE-TRACE-READONLY');
    const body = { auditId: id, clientId: 'c',
      packets: [C(true), CA(false), P(1), REC(1), REL(1), COMP(1), DISC()] };
    const sealed = await api('/api/audits', body);
    const caseId = sealed.json.record.caseId;
    await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/99`);
    await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/4`);
    const t = await apiGet(`/api/audits/${encodeURIComponent(id)}/trace/3`);
    check('只读: 错误查询后正常链路仍返回同一裁决编号', t.json.caseId === caseId);
    const re = await api('/api/audits/reopen', body);
    check('只读: 原证据仍可 REPLAYED 且编号不变',
      re.status === 200 && re.json.status === 'REPLAYED' && re.json.record.caseId === caseId);
  }
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
