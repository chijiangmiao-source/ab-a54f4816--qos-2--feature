// 裁决引擎测试：围绕重连恢复 / 合法重放 / 未闭合交换 / 精确一次交付
// 运行：node test/engine.test.js （零依赖，失败时退出码非 0）
import { adjudicate, validateInput, normalizeInput, inputFingerprint, InputValidationError, MAX_PACKETS } from '../server/engine.js';

let passed = 0;
let failed = 0;
const failures = [];

function check(name, cond, detail = '') {
  if (cond) { passed += 1; }
  else { failed += 1; failures.push(`${name}${detail ? ` —— ${detail}` : ''}`); }
}

function run(name, input, { verdict, reason, reasonSeq, deliveredOnce, openIds, closedIds }) {
  let r;
  try { r = adjudicate(input); }
  catch (e) { check(name, false, `裁决抛异常: ${e.message}`); return; }
  check(`${name}: 裁决=${verdict}`, r.verdict === verdict,
    `实际 ${r.verdict}/${r.reason}@${r.reasonSeq}`);
  if (reason) check(`${name}: 违规码`, r.reason === reason, `实际 ${r.reason}`);
  if (reasonSeq != null) check(`${name}: 首个违规包序号=${reasonSeq}`, r.reasonSeq === reasonSeq,
    `实际 ${r.reasonSeq}`);
  if (deliveredOnce != null) check(`${name}: 精确交付数=${deliveredOnce}`, r.summary.deliveredOnce === deliveredOnce,
    `实际 ${r.summary.deliveredOnce}`);
  if (openIds) check(`${name}: 未闭合标识`, JSON.stringify(r.summary.openPacketIds) === JSON.stringify(openIds),
    `实际 ${JSON.stringify(r.summary.openPacketIds)}`);
  if (closedIds) check(`${name}: 已闭合标识`, JSON.stringify(r.summary.closedPacketIds) === JSON.stringify(closedIds),
    `实际 ${JSON.stringify(r.summary.closedPacketIds)}`);
  return r;
}

const A = (id) => ({ auditId: 'A', clientId: 'c1', packets: id });
const C = (o = {}) => ({ type: 'CONNECT', direction: 'C2S', cleanStart: o.cleanStart ?? true });
const CA = (o = {}) => ({ type: 'CONNACK', direction: 'S2C', sessionPresent: o.sessionPresent ?? false });
const P = (pid, o = {}) => ({ type: 'PUBLISH', direction: 'C2S', qos: 2, packetId: pid,
  topic: o.topic ?? 'sat/t', payload: o.payload ?? 'P', dup: o.dup ?? false });
const REC = (pid) => ({ type: 'PUBREC', direction: 'S2C', packetId: pid });
const REL = (pid) => ({ type: 'PUBREL', direction: 'C2S', packetId: pid });
const COMP = (pid) => ({ type: 'PUBCOMP', direction: 'S2C', packetId: pid });
const D = (o = {}) => ({ type: 'DISCONNECT', direction: 'C2S', reasonCode: o.reasonCode ?? 0 });

// 1. 正常 QoS2 四次握手闭合
run('正常闭合', A([C(), CA(), P(1), REC(1), REL(1), COMP(1), D()]),
  { verdict: 'ACCEPTED', reason: 'OK', reasonSeq: 0, deliveredOnce: 1, closedIds: [1], openIds: [] });

// 2. PUBREC 丢失：DUP=1 合法重发，载荷一致 → 仍然只交付一次
run('PUBREC丢失-合法重放-仅一次交付', A([C(), CA(), P(10), P(10, { dup: true }), REC(10), REL(10), COMP(10), D()]),
  { verdict: 'ACCEPTED', deliveredOnce: 1, closedIds: [10] });

// 3. PUBCOMP 丢失：断链后 Clean Start=0 重连，SP=1 恢复，重传 PUBREL→PUBCOMP 闭合
run('PUBCOMP丢失-持久会话重连恢复-闭合', A([
  C({ cleanStart: false }), CA({ sessionPresent: false }), P(22), REC(22), REL(22),
  D({ reasonCode: 142 }),
  C({ cleanStart: false }), CA({ sessionPresent: true }), REL(22), COMP(22), D()
]), { verdict: 'ACCEPTED', deliveredOnce: 1, closedIds: [22] });

// 4. PUBREC 丢失后跨重连重发 DUP PUBLISH，再闭合
run('断链重连后DUP重发-闭合', A([
  C({ cleanStart: false }), CA(), P(30),
  D({ reasonCode: 142 }),
  C({ cleanStart: false }), CA({ sessionPresent: true }),
  P(30, { dup: true }), REC(30), REL(30), COMP(30), D()
]), { verdict: 'ACCEPTED', deliveredOnce: 1, closedIds: [30] });

// 5. 闭合后持久会话内重发同一标识 → 双投，拒绝，定位重发包
run('闭合后重发-双投拒绝', A([C(), CA(), P(5), REC(5), REL(5), COMP(5), P(5, { dup: true })]),
  { verdict: 'REJECTED', reason: 'DOUBLE_DELIVERY', reasonSeq: 7, deliveredOnce: 1 });

// 6. 闭合后 Clean Start 新会话以非 DUP 首发重用旧标识 → 二次交付，拒绝
run('CleanStart新会话重用已交付标识-拒绝', A([
  C({ cleanStart: true }), CA(), P(5), REC(5), REL(5), COMP(5), D(),
  C({ cleanStart: true }), CA({ sessionPresent: false }), P(5)
]), { verdict: 'REJECTED', reason: 'DOUBLE_DELIVERY', reasonSeq: 10 });

// 7. Clean Start=1 后继续旧 PUBREL → STALE_SESSION_USE，定位该包
run('清除会话后继续旧PUBREL-拒绝', A([
  C({ cleanStart: false }), CA(), P(7), D(),
  C({ cleanStart: true }), CA({ sessionPresent: false }), REL(7)
]), { verdict: 'REJECTED', reason: 'STALE_SESSION_USE', reasonSeq: 7 });

// 8. Clean Start=1 后继续旧 PUBCOMP → STALE_SESSION_USE
run('清除会话后继续旧PUBCOMP-拒绝', A([
  C({ cleanStart: false }), CA(), P(7), REC(7), REL(7), D(),
  C({ cleanStart: true }), CA(), COMP(7)
]), { verdict: 'REJECTED', reason: 'STALE_SESSION_USE', reasonSeq: 9 });

// 9. 重发载荷冲突 → PAYLOAD_CONFLICT，定位重发包
run('重发载荷冲突-拒绝', A([C(), CA(),
  P(3, { payload: 'A' }), P(3, { dup: true, payload: 'B' })]),
  { verdict: 'REJECTED', reason: 'PAYLOAD_CONFLICT', reasonSeq: 4 });

// 10. 重发主题冲突
run('重发主题冲突-拒绝', A([C(), CA(),
  P(3, { topic: 'sat/a' }), P(3, { dup: true, topic: 'sat/b' })]),
  { verdict: 'REJECTED', reason: 'PAYLOAD_CONFLICT', reasonSeq: 4 });

// 11. 重发未置 DUP → RESEND_WITHOUT_DUP
run('重发未置DUP-拒绝', A([C(), CA(), P(1), P(1)]),
  { verdict: 'REJECTED', reason: 'RESEND_WITHOUT_DUP', reasonSeq: 4 });

// 12. DUP=1 但无首发 → DUP_WITHOUT_ORIGINAL
run('DUP无首发-拒绝', A([C(), CA(), P(1, { dup: true })]),
  { verdict: 'REJECTED', reason: 'DUP_WITHOUT_ORIGINAL', reasonSeq: 3 });

// 13. 未闭合：仅 PUBLISH（PUBREC 丢失，断链结束）
run('INFLIGHT未闭合-拒绝', A([C({ cleanStart: false }), CA(), P(9), D({ reasonCode: 142 })]),
  { verdict: 'REJECTED', reason: 'UNCLOSED_EXCHANGE', reasonSeq: 3, openIds: [9] });

// 14. 未闭合：REC_RCVD 后断开
run('REC_RCVD未闭合-拒绝', A([C({ cleanStart: false }), CA(), P(9), REC(9), D()]),
  { verdict: 'REJECTED', reason: 'UNCLOSED_EXCHANGE', reasonSeq: 4 });

// 15. 未闭合：REL_SENT（PUBCOMP 丢失）——注意：无重连即结束才叫未闭合
run('REL_SENT未闭合(PUBCOMP丢失)-拒绝', A([C({ cleanStart: false }), CA(), P(9), REC(9), REL(9), D()]),
  { verdict: 'REJECTED', reason: 'UNCLOSED_EXCHANGE', reasonSeq: 5 });

// 16. 方向错误：PUBLISH S2C
run('PUBLISH方向错误-拒绝', A([C(), CA(), { ...P(1), direction: 'S2C' }]),
  { verdict: 'REJECTED', reason: 'WRONG_DIRECTION', reasonSeq: 3 });

// 17. 方向错误：CONNACK C2S
run('CONNACK方向错误-拒绝', A([C(), { ...CA(), direction: 'C2S' }]),
  { verdict: 'REJECTED', reason: 'WRONG_DIRECTION', reasonSeq: 2 });

// 18. 阶段跳跃：首包即 PUBLISH
run('建连前PUBLISH-阶段跳跃', A([P(1)]),
  { verdict: 'REJECTED', reason: 'PHASE_SKIP', reasonSeq: 1 });

// 19. CONNACK 先于 CONNECT
run('CONNACK先于CONNECT-阶段跳跃', A([CA()]),
  { verdict: 'REJECTED', reason: 'PHASE_SKIP', reasonSeq: 1 });

// 20. PUBREL 先于 PUBREC
run('PUBREL先于PUBREC-阶段跳跃', A([C(), CA(), P(1), REL(1)]),
  { verdict: 'REJECTED', reason: 'PHASE_SKIP', reasonSeq: 4 });

// 21. PUBCOMP 先于 PUBREL
run('PUBCOMP先于PUBREL-阶段跳跃', A([C(), CA(), P(1), REC(1), COMP(1)]),
  { verdict: 'REJECTED', reason: 'PHASE_SKIP', reasonSeq: 5 });

// 22. CleanStart=1 却收到 SP=1 → 矛盾
run('CleanStart与SP矛盾-拒绝', A([C({ cleanStart: true }), CA({ sessionPresent: true })]),
  { verdict: 'REJECTED', reason: 'SESSION_PRESENT_CONFLICT', reasonSeq: 2 });

// 23. 首次连接 CS=0 收到 SP=1
run('首次连接SP=1-矛盾拒绝', A([C({ cleanStart: false }), CA({ sessionPresent: true })]),
  { verdict: 'REJECTED', reason: 'SESSION_PRESENT_CONFLICT', reasonSeq: 2 });

// 24. 重连 CS=0 但 SP=0（会话过期）
run('重连会话过期-拒绝', A([
  C({ cleanStart: false }), CA(), P(8), D(),
  C({ cleanStart: false }), CA({ sessionPresent: false })]),
  { verdict: 'REJECTED', reason: 'SESSION_EXPIRED', reasonSeq: 6 });

// 25. DISCONNECT 后继续旧确认（未重连）
run('断连后继续旧确认-拒绝', A([
  C({ cleanStart: false }), CA(), P(1), REC(1), D(), REL(1)]),
  { verdict: 'REJECTED', reason: 'PACKET_AFTER_DISCONNECT', reasonSeq: 6 });

// 26. 重复 PUBCOMP → REPEATED_PUBCOMP（构造：REL_SENT 后两个 PUBCOMP；
//     第二个出现时流已 CLOSED）
run('重复PUBCOMP-拒绝', A([C(), CA(), P(1), REC(1), REL(1), COMP(1), COMP(1)]),
  { verdict: 'REJECTED', reason: 'REPEATED_PUBCOMP', reasonSeq: 7 });

// 27. 无对应重发的重复 PUBREC → DUPLICATE_ACK
run('重复PUBREC-拒绝', A([C(), CA(), P(1), REC(1), REC(1)]),
  { verdict: 'REJECTED', reason: 'DUPLICATE_ACK', reasonSeq: 5 });

// 28. PUBREC 引用未知标识
run('PUBREC未知标识-拒绝', A([C(), CA(), REC(99)]),
  { verdict: 'REJECTED', reason: 'UNKNOWN_PACKET_ID', reasonSeq: 3 });

// 29. 多标识并行交换，各自闭合一次
run('多遥测各自精确一次', A([C(), CA(),
  P(1), P(2), REC(1), REC(2), REL(1), REL(2), COMP(1), COMP(2), D()]),
  { verdict: 'ACCEPTED', deliveredOnce: 2, closedIds: [1, 2], openIds: [] });

// 30. 已收 PUBREC 后重发整个 PUBLISH → 阶段跳跃
run('PUBREC后重发PUBLISH-拒绝', A([C(), CA(), P(1), REC(1), P(1, { dup: true })]),
  { verdict: 'REJECTED', reason: 'PHASE_SKIP', reasonSeq: 5 });

// 31. 异常断开无 DISCONNECT 直接 CONNECT 重连（隐式重连）CS=0 + SP=1 可恢复
run('无DISCONNECT隐式重连恢复-合法', A([
  C({ cleanStart: false }), CA(), P(4), REC(4),
  C({ cleanStart: false }), CA({ sessionPresent: true }), REL(4), COMP(4), D()]),
  { verdict: 'ACCEPTED', deliveredOnce: 1, closedIds: [4] });

// 32. 重发后 Broker 重放 PUBREC（pubrecPending），再正常闭合
run('DUP重发后PUBREC重放-闭合', A([C(), CA(),
  P(1), P(1, { dup: true }), REC(1), REL(1), COMP(1), D()]),
  { verdict: 'ACCEPTED', deliveredOnce: 1 });

// ---------- 录入校验 ----------
try { validateInput({ auditId: '', clientId: 'c', packets: [C()] }); check('缺少审计标识应报错', false); }
catch (e) { check('缺少审计标识应报错', e instanceof InputValidationError && e.errors.some(x => x.field === 'auditId')); }

try { validateInput({ auditId: 'a', clientId: '', packets: [C()] }); check('缺少客户端标识应报错', false); }
catch (e) { check('缺少客户端标识应报错', e instanceof InputValidationError && e.errors.some(x => x.field === 'clientId')); }

try {
  validateInput({ auditId: 'a', clientId: 'c', packets: [{ type: 'SUBSCRIBE', direction: 'C2S' }] });
  check('不支持的报文类型应报错', false);
} catch (e) { check('不支持的报文类型应报错', e.errors.some(x => /不支持/.test(x.message))); }

try {
  validateInput({ auditId: 'a', clientId: 'c', packets: [P(1, { payload: '' })] });
  check('空载荷应报错', false);
} catch (e) { check('空载荷应报错', e.errors.some(x => /载荷/.test(x.message))); }

try {
  validateInput({ auditId: 'a', clientId: 'c', packets: [{ ...P(1), qos: 1 }] });
  check('非 QoS2 的 PUBLISH 应报错', false);
} catch (e) { check('非 QoS2 的 PUBLISH 应报错', e.errors.some(x => /QoS 2/.test(x.message))); }

try {
  validateInput({ auditId: 'a', clientId: 'c', packets: Array.from({ length: MAX_PACKETS + 1 }, () => C()) });
  check(`超过 ${MAX_PACKETS} 包应报错`, false);
} catch (e) { check(`超过 ${MAX_PACKETS} 包应报错`, e.errors.some(x => x.message.includes(MAX_PACKETS))); }

try {
  validateInput({ auditId: 'a', clientId: 'c', packets: [] });
  check('空捕获应报错', false);
} catch (e) { check('空捕获应报错', e.errors.some(x => /至少/.test(x.message))); }

// ---------- 指纹稳定性 ----------
const i1 = { auditId: 'X', clientId: 'c', packets: [P(1)] };
const i2 = { auditId: 'X', clientId: 'c', packets: [{ ...P(1), dup: false }] };
check('规范化后等价输入指纹一致', inputFingerprint(i1) === inputFingerprint(i2));
const i3 = { auditId: 'X', clientId: 'c', packets: [P(1), P(2)] };
check('不同输入指纹不同', inputFingerprint(i1) !== inputFingerprint(i3));
// 键顺序不影响指纹
const n1 = normalizeInput({ auditId: 'X', clientId: 'c', packets: [P(1)] });
const n2 = normalizeInput({ packets: [P(1)], clientId: 'c', auditId: 'X' });
check('字段顺序不影响规范化', JSON.stringify(n1) === JSON.stringify(n2));

// ---------- 逐包证据 ----------
const ev = adjudicate(A([C(), CA(), P(1), REC(1), REL(1), COMP(1), D()]));
check('逐包证据条数=7', ev.packets.length === 7);
check('PUBLISH 首包标记 FIRST', ev.packets[2].firstDelivery === 'FIRST');
check('PUBCOMP 包标记 DELIVERED_ONCE', ev.packets[5].firstDelivery === 'DELIVERED_ONCE');
const dup = adjudicate(A([C(), CA(), P(10), P(10, { dup: true }), REC(10), REL(10), COMP(10), D()]));
check('合法重放包标记 RESEND', dup.packets[3].firstDelivery === 'RESEND');
check('合法重放不计入交付数', dup.summary.deliveredOnce === 1);
// 违规包证据落在该序号
const bad = adjudicate(A([C(), CA(), P(5), REC(5), REL(5), COMP(5), P(5, { dup: true })]));
check('违规包携带 violation 详情', !!bad.packets[6].violation && bad.packets[6].violation.code === 'DOUBLE_DELIVERY');

console.log(`\n引擎测试：${passed} 通过，${failed} 失败`);
if (failures.length) {
  console.error('\n失败项：');
  failures.forEach((f) => console.error(' ✗ ' + f));
  process.exit(1);
}
console.log('全部通过 ✓');
