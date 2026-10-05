// 首发链路追溯测试：
//   - 可追溯首发选择入口（仅首发 PUBLISH；同标识多首发并列、互不混淆）；
//   - 从首发起的有序链路：原始序号 / 连接编号 / 阶段变化 / 确认关系 / 是否唯一交付；
//   - 持久会话 CS=false + SP=true 跨连接衔接重传 PUBREL / PUBLISH，沿用首次交付；
//   - Clean Start 清除、闭合后标识重用作为前一链路终止依据，不归入新首发；
//   - 非首发 / 未知审计（无裁决）/ 越界 / 非整数序号给出明确错误；
//   - 链路派生只读，不改写冻结裁决。
// 运行：node test/trace.test.js
import { adjudicate, listTraceOrigins, buildTraceChain, TraceQueryError } from '../server/engine.js';

let passed = 0;
let failed = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { passed++; }
  else { failed++; failures.push(`${name}${detail ? ` —— ${detail}` : ''}`); }
}
function expectThrow(name, fn, code) {
  try { fn(); check(name, false, '未抛出预期错误'); }
  catch (e) {
    if (!(e instanceof TraceQueryError)) { check(name, false, `抛出非 TraceQueryError: ${e.constructor.name}`); return; }
    check(name, e.code === code, `实际 ${e.code}（期望 ${code}）：${e.message}`);
  }
}

const A = (packets) => ({ auditId: 'A', clientId: 'c1', packets });
const C = (cs = true) => ({ type: 'CONNECT', direction: 'C2S', cleanStart: cs });
const CA = (sp = false) => ({ type: 'CONNACK', direction: 'S2C', sessionPresent: sp });
const P = (pid, o = {}) => ({ type: 'PUBLISH', direction: 'C2S', qos: 2, packetId: pid,
  topic: o.topic ?? 'sat/t', payload: o.payload ?? 'P', dup: o.dup ?? false });
const REC = (pid) => ({ type: 'PUBREC', direction: 'S2C', packetId: pid });
const REL = (pid) => ({ type: 'PUBREL', direction: 'C2S', packetId: pid });
const COMP = (pid) => ({ type: 'PUBCOMP', direction: 'S2C', packetId: pid });
const D = (rc = 0) => ({ type: 'DISCONNECT', direction: 'C2S', reasonCode: rc });

const seqsOf = (chain) => chain.steps.filter((s) => !s.bridge).map((s) => s.seq);
const bridgeSeqs = (chain) => chain.steps.filter((s) => s.bridge).map((s) => s.seq);
const bySeq = (chain, seq) => chain.steps.find((s) => s.seq === seq);

// ---------- 1. 正常闭合链路 ----------
{
  const v = adjudicate(A([C(), CA(), P(1), REC(1), REL(1), COMP(1), D()]));
  const origins = listTraceOrigins(v);
  check('正常：仅 1 个可追溯首发(seq=3)', origins.length === 1 && origins[0].originSeq === 3);
  check('正常：首发状态 CLOSED', origins[0].status === 'CLOSED' && origins[0].deliverySeq === 6);
  const c = buildTraceChain(v, 3);
  check('正常：链路有序', c.ordered === true);
  check('正常：成员序号 3..6', JSON.stringify(seqsOf(c)) === JSON.stringify([3, 4, 5, 6]),
    JSON.stringify(seqsOf(c)));
  check('正常：终止原因 CLOSED@6', c.endReason === 'CLOSED' && c.endSeq === 6);
  check('正常：产生唯一交付@6', c.uniqueDelivery.produced === true && c.uniqueDelivery.deliverySeq === 6);
  check('正常：唯一交付步仅 PUBCOMP', c.steps.filter((s) => s.deliveredOnce).map((s) => s.seq).join() === '6');
  check('正常：首发连接编号=1', bySeq(c, 3).connection === 1);
  check('正常：首发角色', bySeq(c, 3).ackRole === 'PUBLISH_ORIGIN');
  check('正常：PUBREC 确认第3包', bySeq(c, 4).ackRole === 'PUBREC' && bySeq(c, 4).acknowledgesSeq === 3);
  check('正常：PUBREL 确认第4包', bySeq(c, 5).ackRole === 'PUBREL' && bySeq(c, 5).acknowledgesSeq === 4);
  check('正常：PUBCOMP 确认第5包', bySeq(c, 6).ackRole === 'PUBCOMP' && bySeq(c, 6).acknowledgesSeq === 5);
  check('正常：无跨连接步', c.steps.some((s) => s.crossConnection) === false);
  check('正常：无边界事件', c.boundaryEvents.length === 0);
}

// ---------- 2. PUBREC 丢失：DUP 重放，确认关系链 ----------
{
  const v = adjudicate(A([C(), CA(), P(10), P(10, { dup: true }), REC(10), REL(10), COMP(10), D()]));
  const c = buildTraceChain(v, 3);
  check('重放：成员含重发包 seq4', seqsOf(c).join() === '3,4,5,6,7');
  check('重放：seq4 重传第3包', bySeq(c, 4).retransmitsSeq === 3 && bySeq(c, 4).ackRole === 'PUBLISH_RESEND');
  check('重放：PUBREC 确认最新发布(第4包)', bySeq(c, 5).acknowledgesSeq === 4);
  check('重放：重放步不产生交付', bySeq(c, 4).deliveredOnce === false);
  check('重放：唯一交付仍为1次@7', c.uniqueDelivery.produced && c.uniqueDelivery.deliverySeq === 7);
}

// ---------- 3. PUBCOMP 丢失：CS=0/SP=1 跨连接重传 PUBREL ----------
{
  const v = adjudicate(A([
    C(false), CA(false), P(22), REC(22), REL(22), D(142),
    C(false), CA(true), REL(22), COMP(22), D()
  ]));
  check('跨连接恢复：裁决 ACCEPTED', v.verdict === 'ACCEPTED', v.reason);
  const c = buildTraceChain(v, 3);
  check('跨连接恢复：终止 CLOSED@10', c.endReason === 'CLOSED' && c.endSeq === 10);
  check('跨连接恢复：桥接含 CONNECT#2(seq7)/CONNACK(seq8)',
    JSON.stringify(bridgeSeqs(c)) === JSON.stringify([7, 8]));
  const connectStep = bySeq(c, 7);
  const connackStep = bySeq(c, 8);
  check('跨连接恢复：桥接 CONNECT 为 Clean Start=0', connectStep.bridge && connectStep.cleanStart === false);
  check('跨连接恢复：桥接 CONNACK 为 Session Present=1', connackStep.bridge && connackStep.sessionPresent === true);
  const retry = bySeq(c, 9);
  check('跨连接恢复：重传 PUBREL 标记跨连接', retry.ackRole === 'PUBREL_RETRY' && retry.crossConnection === true);
  check('跨连接恢复：重传 PUBREL 重传第5包', retry.retransmitsSeq === 5);
  check('跨连接恢复：跨连接说明沿用首发', /沿用第 3 包首发/.test(retry.crossRecovery));
  check('跨连接恢复：comp 确认重传(第9包)', bySeq(c, 10).acknowledgesSeq === 9);
  check('跨连接恢复：仍唯一交付一次', c.uniqueDelivery.produced && c.uniqueDelivery.deliverySeq === 10);
  check('跨连接恢复：首发步在连接1、重传步在连接2',
    bySeq(c, 3).connection === 1 && retry.connection === 2);
}

// ---------- 4. PUBREC 丢失后跨连接 DUP 重发 PUBLISH 恢复 ----------
{
  const v = adjudicate(A([
    C(false), CA(), P(30), D(142),
    C(false), CA(true), P(30, { dup: true }), REC(30), REL(30), COMP(30), D()
  ]));
  const c = buildTraceChain(v, 3);
  check('跨连接重发：CLOSED', c.endReason === 'CLOSED' && c.uniqueDelivery.produced);
  const resend = bySeq(c, 7);
  check('跨连接重发：重发 PUBLISH 跨连接且重传第3包',
    resend.crossConnection === true && resend.ackRole === 'PUBLISH_RESEND' && resend.retransmitsSeq === 3);
  check('跨连接重发：桥接为 CS=0/SP=1',
    bridgeSeqs(c).length === 2 && bySeq(c, 5).cleanStart === false && bySeq(c, 6).sessionPresent === true);
  check('跨连接重发：唯一交付@10', c.uniqueDelivery.deliverySeq === 10);
}

// ---------- 5. 闭合后重用同一标识：前一链止于闭合，重用仅作边界 ----------
{
  const v = adjudicate(A([C(), CA(), P(5), REC(5), REL(5), COMP(5), P(5, { dup: true })]));
  const c = buildTraceChain(v, 3);
  check('闭合后重用：链止于 PUBCOMP@6', c.endReason === 'CLOSED' && c.endSeq === 6);
  check('闭合后重用：重发包 seq7 不并入链路', seqsOf(c).includes(7) === false);
  check('闭合后重用：边界标记 REUSE_AFTER_CLOSE@7',
    c.boundaryEvents.length === 1 && c.boundaryEvents[0].seq === 7 &&
    c.boundaryEvents[0].relation === 'REUSE_AFTER_CLOSE');
  check('闭合后重用：首发仍唯一交付一次', c.uniqueDelivery.produced && c.uniqueDelivery.deliverySeq === 6);
}

// ---------- 6. Clean Start 清除后旧确认：旧链终止、新首发独立 ----------
{
  const v = adjudicate(A([
    C(false), CA(), P(7), D(),
    C(true), CA(false), REL(7)
  ]));
  const origins = listTraceOrigins(v);
  check('CS清除：仅 1 个首发（旧 PUBREL 不是首发）', origins.length === 1 && origins[0].originSeq === 3);
  const c = buildTraceChain(v, 3);
  check('CS清除：终止于 ClearStart CONNECT@5',
    c.endReason === 'TERMINATED_CLEAN_START' && c.endSeq === 5);
  const term = c.steps[c.steps.length - 1];
  check('CS清除：末步为 Clean Start 终止步', term.seq === 5 && term.termination === 'TERMINATED_CLEAN_START' && term.cleanStart === true);
  check('CS清除：旧 PUBREL(seq7) 不并入链路', seqsOf(c).includes(7) === false);
  check('CS清除：边界 STALE_AFTER_CLEAN_START@7',
    c.boundaryEvents.some((b) => b.seq === 7 && b.relation === 'STALE_AFTER_CLEAN_START'));
  check('CS清除：未产生唯一交付', c.uniqueDelivery.produced === false);
}

// ---------- 6b. 持久会话恢复失败（CS=0 却 SP=0）：在途链终止于 CONNACK ----------
{
  const v = adjudicate(A([
    C(false), CA(), P(8), D(),
    C(false), CA(false) // SESSION_EXPIRED @ seq6
  ]));
  check('会话过期：裁决 REJECTED/SESSION_EXPIRED@6',
    v.verdict === 'REJECTED' && v.reason === 'SESSION_EXPIRED' && v.reasonSeq === 6, v.reason);
  const origins = listTraceOrigins(v);
  check('会话过期：首发状态 TERMINATED_SESSION_EXPIRED',
    origins.length === 1 && origins[0].status === 'TERMINATED_SESSION_EXPIRED' && origins[0].endSeq === 6);
  const c = buildTraceChain(v, 3);
  check('会话过期：链终止于 CONNACK@6',
    c.endReason === 'TERMINATED_SESSION_EXPIRED' && c.endSeq === 6);
  const term = c.steps[c.steps.length - 1];
  check('会话过期：终止步为 CONNACK(SP=0)',
    term.seq === 6 && term.type === 'CONNACK' && term.termination === 'TERMINATED_SESSION_EXPIRED' &&
    term.sessionPresent === false);
  check('会话过期：无唯一交付', c.uniqueDelivery.produced === false);
}

// ---------- 7. 同一标识两次首发：互不混淆、各自链路 ----------
{
  const v = adjudicate(A([
    C(false), CA(), P(8), REC(8), D(),
    C(true), CA(false),
    P(8), REC(8), REL(8), COMP(8), D()
  ]));
  const origins = listTraceOrigins(v);
  check('标识复用：列出 2 个首发', origins.map((o) => o.originSeq).join() === '3,8');
  check('标识复用：两首发互为同标识兄弟',
    JSON.stringify(origins[0].samePacketIdOrigins) === JSON.stringify([3, 8]) &&
    JSON.stringify(origins[1].samePacketIdOrigins) === JSON.stringify([3, 8]));
  check('标识复用：旧首发 CLEAN_START 终止', origins[0].status === 'TERMINATED_CLEAN_START');
  check('标识复用：新首发 CLOSED', origins[1].status === 'CLOSED' && origins[1].deliverySeq === 11);

  const oldC = buildTraceChain(v, 3);
  check('旧链：终止于 ClearStart@6', oldC.endReason === 'TERMINATED_CLEAN_START' && oldC.endSeq === 6);
  check('旧链：不含新首发及其确认(8..11)', seqsOf(oldC).every((s) => s < 8));
  check('旧链：边界指向新首发 REUSED_BY_NEW_ORIGIN@8',
    oldC.boundaryEvents.some((b) => b.seq === 8 && b.relation === 'REUSED_BY_NEW_ORIGIN' && b.otherOriginSeq === 8));

  const newC = buildTraceChain(v, 8);
  check('新链：成员为 8..11', seqsOf(newC).join() === '8,9,10,11');
  check('新链：独立闭合、唯一交付@11', newC.endReason === 'CLOSED' && newC.uniqueDelivery.deliverySeq === 11);
  check('新链：不含旧首发(seq3)', seqsOf(newC).includes(3) === false);
  check('新旧链成员互不相交',
    seqsOf(oldC).filter((s) => seqsOf(newC).includes(s)).length === 0);
}

// ---------- 8. 拒绝（载荷冲突）链路终止于拒绝包 ----------
{
  const v = adjudicate(A([C(), CA(), P(3, { payload: 'A' }), P(3, { dup: true, payload: 'B' })]));
  const c = buildTraceChain(v, 3);
  check('载荷冲突：终止 REJECTED@4', c.endReason === 'REJECTED' && c.endSeq === 4);
  check('载荷冲突：未产生唯一交付', c.uniqueDelivery.produced === false);
  check('载荷冲突：拒绝步携带违规', !!bySeq(c, 4).violation && bySeq(c, 4).violation.code === 'PAYLOAD_CONFLICT');
}

// ---------- 9. 捕获结束未闭合 ----------
{
  const v = adjudicate(A([C(false), CA(), P(9), REC(9), REL(9), D(142)]));
  const c = buildTraceChain(v, 3);
  check('未闭合：CAPTURE_END_UNCLOSED@5', c.endReason === 'CAPTURE_END_UNCLOSED' && c.endSeq === 5);
  check('未闭合：无唯一交付', c.uniqueDelivery.produced === false);
}

// ---------- 10. 选择入口：非首发 / 越界 / 非整数 / 未知审计 ----------
{
  const v = adjudicate(A([C(), CA(), P(1), REC(1), REL(1), COMP(1), D()]));
  expectThrow('DUP 之外的 PUBREC 不能作首发', () => buildTraceChain(v, 4), 'NOT_TRACEABLE_ORIGIN');
  expectThrow('CONNECT 不能作首发', () => buildTraceChain(v, 1), 'NOT_TRACEABLE_ORIGIN');
  expectThrow('PUBCOMP 不能作首发', () => buildTraceChain(v, 6), 'NOT_TRACEABLE_ORIGIN');
  expectThrow('序号 0 越界', () => buildTraceChain(v, 0), 'ORIGIN_SEQ_OUT_OF_RANGE');
  expectThrow('序号超界', () => buildTraceChain(v, 99), 'ORIGIN_SEQ_OUT_OF_RANGE');
  expectThrow('非整数序号', () => buildTraceChain(v, 'abc'), 'ORIGIN_SEQ_INVALID');
  expectThrow('未知审计(无裁决)', () => buildTraceChain(null, 3), 'NO_VERDICT');
  expectThrow('清单对无裁决报错', () => listTraceOrigins(undefined), 'NO_VERDICT');
  // DUP=1 重发包（若存在）不能作首发
  const v2 = adjudicate(A([C(), CA(), P(10), P(10, { dup: true }), REC(10), REL(10), COMP(10), D()]));
  expectThrow('DUP 重发包不能作首发', () => buildTraceChain(v2, 4), 'NOT_TRACEABLE_ORIGIN');
}

// ---------- 11. 链路派生只读：不改写冻结裁决 ----------
{
  const v = adjudicate(A([
    C(false), CA(false), P(22), REC(22), REL(22), D(142),
    C(false), CA(true), REL(22), COMP(22), D()
  ]));
  const before = JSON.stringify(v);
  buildTraceChain(v, 3);
  listTraceOrigins(v);
  expectThrow('错误查询也不改证据', () => buildTraceChain(v, 99), 'ORIGIN_SEQ_OUT_OF_RANGE');
  const after = JSON.stringify(v);
  check('派生链路不修改冻结裁决', before === after);
}

// ---------- 12. 多标识并行：各自首发各自链路 ----------
{
  const v = adjudicate(A([C(), CA(),
    P(1), P(2), REC(1), REC(2), REL(1), REL(2), COMP(1), COMP(2), D()]));
  const origins = listTraceOrigins(v);
  check('并行：2 个首发 seq3/seq4', origins.map((o) => o.originSeq).join() === '3,4');
  const c1 = buildTraceChain(v, 3);
  const c2 = buildTraceChain(v, 4);
  check('并行：链路1 仅标识1成员', seqsOf(c1).join() === '3,5,7,9');
  check('并行：链路2 仅标识2成员', seqsOf(c2).join() === '4,6,8,10');
  check('并行：两链各自唯一交付', c1.uniqueDelivery.deliverySeq === 9 && c2.uniqueDelivery.deliverySeq === 10);
}

console.log(`\n链路追溯测试：${passed} 通过，${failed} 失败`);
if (failures.length) {
  console.error('\n失败项：');
  failures.forEach((f) => console.error(' ✗ ' + f));
  process.exit(1);
}
console.log('全部通过 ✓');
