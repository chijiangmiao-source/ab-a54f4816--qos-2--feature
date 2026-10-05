// 首发交换链路追溯测试：
//   正常闭合 / 跨重连恢复（CS=0,SP=1 重传 PUBREL、PUBLISH）/ 标识复用边界
//   / 同标识多首发互不混淆 / 错误查询（非首发、未知、越界）/ 只读不改写
// 运行：node test/trace.test.js
import {
  traceExchange, traceableOrigins, TraceQueryError, adjudicate
} from '../server/engine.js';

let passed = 0;
let failed = 0;
const failures = [];
const check = (name, cond, detail = '') => {
  if (cond) passed++;
  else {
    failed++;
    failures.push(`${name}${detail ? ` —— ${detail}` : ''}`);
    console.error(' ✗ ' + name + (detail ? ` —— ${detail}` : ''));
  }
};

const C = (cleanStart = true) => ({ type: 'CONNECT', direction: 'C2S', cleanStart });
const CA = (sessionPresent = false) => ({ type: 'CONNACK', direction: 'S2C', sessionPresent });
const P = (pid, o = {}) => ({ type: 'PUBLISH', direction: 'C2S', qos: 2, packetId: pid,
  topic: o.topic ?? 'sat/t', payload: o.payload ?? 'X', dup: o.dup ?? false });
const REC = (pid) => ({ type: 'PUBREC', direction: 'S2C', packetId: pid });
const REL = (pid) => ({ type: 'PUBREL', direction: 'C2S', packetId: pid });
const COMP = (pid) => ({ type: 'PUBCOMP', direction: 'S2C', packetId: pid });
const D = (reasonCode = 0) => ({ type: 'DISCONNECT', direction: 'C2S', reasonCode });
const A = (packets, auditId = 'TRACE-1') => ({ auditId, clientId: 'relay-t', packets });

const seqsOf = (t, pred) => t.steps.filter(pred).map((s) => s.seq);
const idSeqs = (t) => t.steps.filter((s) => s.role !== 'SESSION_BOUNDARY').map((s) => s.seq);

// ---------- 1. 正常闭合 ----------
{
  const input = A([C(true), CA(false), P(1), REC(1), REL(1), COMP(1), D()]);
  const t = traceExchange(input, 3);
  check('正常闭合: origins 仅 seq=3', JSON.stringify(traceableOrigins(input).map((o) => o.seq)) === '[3]');
  check('正常闭合: termination=CLOSED@6', t.termination.kind === 'CLOSED' && t.termination.seq === 6);
  check('正常闭合: deliveredOnce=true', t.deliveredOnce === true);
  check('正常闭合: uniqueDelivery 指向 PUBCOMP@6 首发@3',
    t.uniqueDelivery && t.uniqueDelivery.pubcompSeq === 6 && t.uniqueDelivery.originSeq === 3);
  check('正常闭合: 链路有序序号 3..6', JSON.stringify(idSeqs(t)) === '[3,4,5,6]');
  const [pub, rec, rel, comp] = t.steps;
  check('正常闭合: 逐项角色', pub.role === 'FIRST_PUBLISH' && rec.role === 'ACK' &&
    rel.role === 'RELAY' && comp.role === 'COMPLETE');
  check('正常闭合: 连接编号均为 1', t.steps.every((s) => s.connection === 1));
  check('正常闭合: 阶段变化 INFLIGHT/REC_RCVD/REL_SENT/CLOSED',
    JSON.stringify([pub.phase, rec.phase, rel.phase, comp.phase]) === '["INFLIGHT","REC_RCVD","REL_SENT","CLOSED"]');
  check('正常闭合: 确认关系 PUBREC→3 PUBREL→4 PUBCOMP→5',
    rec.acknowledges === 3 && rel.acknowledges === 4 && comp.acknowledges === 5);
  check('正常闭合: 仅首发为候选、PUBCOMP 为唯一交付',
    pub.deliveryEffect === 'FIRST_DELIVERY_CANDIDATE' && comp.deliveryEffect === 'UNIQUE_DELIVERY');
  check('正常闭合: 无跨连接', t.crossConnection === false && t.recovery.length === 0);
  check('正常闭合: 无排除包', t.excludedSameIdPackets.length === 0);
  check('正常闭合: 裁决 ACCEPTED', t.verdict.verdict === 'ACCEPTED');
}

// ---------- 2. PUBCOMP 丢失后持久会话重连恢复（重传 PUBREL） ----------
{
  const input = A([C(false), CA(false), P(22), REC(22), REL(22), D(142),
    C(false), CA(true), REL(22), COMP(22), D()]);
  const t = traceExchange(input, 3);
  check('重连恢复: origins 仅 seq=3', traceableOrigins(input).length === 1);
  check('重连恢复: CLOSED@10 且唯一交付', t.termination.kind === 'CLOSED' && t.termination.seq === 10 && t.deliveredOnce);
  check('重连恢复: 链路序号 [3,4,5,9,10]（跨连接衔接）', JSON.stringify(idSeqs(t)) === '[3,4,5,9,10]');
  check('重连恢复: 含跨连接边界 DISCONNECT@6/CONNECT@7/CONNACK@8',
    JSON.stringify(seqsOf(t, (s) => s.type === 'DISCONNECT')) === '[6]' &&
    JSON.stringify(seqsOf(t, (s) => s.type === 'CONNECT')) === '[7]' &&
    JSON.stringify(seqsOf(t, (s) => s.type === 'CONNACK')) === '[8]');
  check('重连恢复: crossConnection=true', t.crossConnection === true);
  check('重连恢复: 两条连接跨度', t.connectionSpans.length === 2 &&
    t.connectionSpans[0].connection === 1 && t.connectionSpans[1].connection === 2);
  const rec2 = t.recovery[0];
  check('重连恢复: 恢复段 CS=0/SP=1/resumed=true',
    rec2 && rec2.cleanStart === false && rec2.sessionPresent === true && rec2.resumed === true);
  check('重连恢复: 重传 PUBREL@9 且沿用首发@3',
    rec2.retransmitted.length === 1 && rec2.retransmitted[0].seq === 9 &&
    rec2.continuesFirstDeliverySeq === 3);
  check('重连恢复: 第二个 PUBREL 确认关系指向前一 PUBREL@5（重传）',
    t.steps.find((s) => s.seq === 9).acknowledges === 5);
  check('重连恢复: 仅一次 UNIQUE_DELIVERY@10',
    t.steps.filter((s) => s.deliveryEffect === 'UNIQUE_DELIVERY').map((s) => s.seq).join() === '10');
}

// ---------- 3. PUBREC 丢失跨重连 DUP PUBLISH 重发恢复 ----------
{
  const input = A([C(false), CA(false), P(30), D(142),
    C(false), CA(true), P(30, { dup: true }), REC(30), REL(30), COMP(30), D()]);
  const t = traceExchange(input, 3);
  check('跨重连DUP: CLOSED 且唯一交付', t.termination.kind === 'CLOSED' && t.deliveredOnce);
  check('跨重连DUP: 链路含首发@3 与重发@7', JSON.stringify(idSeqs(t)) === '[3,7,8,9,10]');
  const dup = t.steps.find((s) => s.seq === 7);
  check('跨重连DUP: 重发角色 RESEND/DEDUPED_RESEND 且确认首发@3',
    dup.role === 'RESEND' && dup.deliveryEffect === 'DEDUPED_RESEND' && dup.acknowledges === 3);
  check('跨重连DUP: 恢复段记录 PUBLISH 重传',
    t.recovery[0].retransmitted.some((r) => r.seq === 7 && r.type === 'PUBLISH'));
}

// ---------- 4. 同连接内 PUBREC 丢失 DUP 重放 ----------
{
  const input = A([C(true), CA(false), P(10), P(10, { dup: true }), REC(10), REL(10), COMP(10), D()]);
  const t = traceExchange(input, 3);
  check('同连接DUP重放: CLOSED', t.termination.kind === 'CLOSED' && t.deliveredOnce);
  const dup = t.steps.find((s) => s.seq === 4);
  check('同连接DUP重放: RESEND 去重不交付', dup.role === 'RESEND' && dup.deliveryEffect === 'DEDUPED_RESEND');
  check('同连接DUP重放: PUBREC 应答最近 PUBLISH@4',
    t.steps.find((s) => s.seq === 5).acknowledges === 4);
}

// ---------- 5. 闭合后重用同一标识：前一链路终止于拒绝 ----------
{
  const input = A([C(true), CA(false), P(5), REC(5), REL(5), COMP(5), P(5, { dup: true })]);
  const t = traceExchange(input, 3);
  check('闭合后重用: origins 只有首发@3（重用包不是首发）',
    JSON.stringify(traceableOrigins(input).map((o) => o.seq)) === '[3]');
  check('闭合后重用: termination=REJECTED@7/DOUBLE_DELIVERY',
    t.termination.kind === 'REJECTED' && t.termination.seq === 7 && t.termination.code === 'DOUBLE_DELIVERY');
  check('闭合后重用: 首发链路仍记录已唯一交付', t.deliveredOnce === true && t.uniqueDelivery.pubcompSeq === 6);
  const reuse = t.steps.find((s) => s.seq === 7);
  check('闭合后重用: 重用包角色 REUSE_AFTER_TERMINATION 且未再交付',
    reuse.role === 'REUSE_AFTER_TERMINATION' && reuse.deliveryEffect === 'REJECTED_BEFORE_DELIVERY');
  check('闭合后重用: 违规依据挂在第 7 项', reuse.violation && reuse.violation.code === 'DOUBLE_DELIVERY');
}

// ---------- 6. Clean Start 清除后旧确认：前一链路终止于拒绝，不并入新首发 ----------
{
  const input = A([C(false), CA(false), P(7), D(), C(true), CA(false), REL(7)]);
  const t = traceExchange(input, 3);
  check('清除后旧PUBREL: REJECTED@7/STALE_SESSION_USE',
    t.termination.kind === 'REJECTED' && t.termination.seq === 7 && t.termination.code === 'STALE_SESSION_USE');
  check('清除后旧PUBREL: 未产生交付', t.deliveredOnce === false && t.uniqueDelivery === null);
  check('清除后旧PUBREL: 链路跨连接但仅一条首发', t.crossConnection === true && traceableOrigins(input).length === 1);
  check('清除后旧PUBREL: PUBREL 违规依据入链',
    t.steps.find((s) => s.seq === 7).violation.code === 'STALE_SESSION_USE');
}

// ---------- 7. 同标识两次合法首发（未交付流被 Clean Start 清除后新会话复用） ----------
{
  const input = A([
    C(false), CA(false), P(8),                 // 3  第一首发（未闭合）
    D(), C(true), CA(false),                  // 4,5,6 清除
    P(8), REC(8), REL(8), COMP(8), D()        // 7  第二首发；8,9,10,11,12
  ]);
  const origins = traceableOrigins(input);
  check('多首发: 列出 seq=3 与 seq=7（同 packetId=8）',
    origins.length === 2 && origins.every((o) => o.packetId === 8) &&
    origins[0].seq === 3 && origins[1].seq === 7 && origins[0].connection === 1 && origins[1].connection === 2);

  const t1 = traceExchange(input, 3);
  const t2 = traceExchange(input, 7);
  check('多首发: 链路1 终止于 CLEAN_START@5 且无交付',
    t1.termination.kind === 'CLEAN_START' && t1.termination.seq === 5 && t1.deliveredOnce === false);
  check('多首发: 链路1 只含首发@3', JSON.stringify(idSeqs(t1)) === '[3]');
  check('多首发: 链路2 闭合@10 且唯一交付', t2.termination.kind === 'CLOSED' && t2.deliveredOnce &&
    t2.uniqueDelivery.originSeq === 7 && t2.uniqueDelivery.pubcompSeq === 10);
  check('多首发: 链路2 序号 [7,8,9,10]', JSON.stringify(idSeqs(t2)) === '[7,8,9,10]');
  // 两条链路成员（标识报文）互不相交
  const s1 = new Set(idSeqs(t1)); const s2 = new Set(idSeqs(t2));
  check('多首发: 两条链路标识报文互不相交', [...s1].every((x) => !s2.has(x)));
  check('多首发: 链路1 排除新首发全部报文(7..10)',
    JSON.stringify(t1.excludedSameIdPackets.map((e) => e.seq)) === '[7,8,9,10]');
  check('多首发: 链路2 排除旧首发@3',
    JSON.stringify(t2.excludedSameIdPackets.map((e) => e.seq)) === '[3]');
  check('多首发: 链路1 排除说明指明另一首发', /另一首发链路/.test(t1.excludedSameIdPackets[0].reason));
}

// ---------- 8. 载荷冲突：链路在重发包处拒绝 ----------
{
  const input = A([C(true), CA(false), P(3, { payload: 'A' }), P(3, { dup: true, payload: 'B' })]);
  const t = traceExchange(input, 3);
  check('载荷冲突: REJECTED@4/PAYLOAD_CONFLICT',
    t.termination.kind === 'REJECTED' && t.termination.code === 'PAYLOAD_CONFLICT' && t.termination.seq === 4);
  check('载荷冲突: 链路止于重发包', JSON.stringify(idSeqs(t)) === '[3,4]');
}

// ---------- 9. 捕获结束未闭合 ----------
{
  const input = A([C(false), CA(false), P(9), REC(9), REL(9), D(142)]);
  const t = traceExchange(input, 3);
  check('未闭合: CAPTURE_END', t.termination.kind === 'CAPTURE_END' && t.termination.seq === null);
  check('未闭合: unclosed=true 且无交付', t.unclosed === true && t.deliveredOnce === false);
  check('未闭合: 裁决原因 UNCLOSED_EXCHANGE', t.termination.code === 'UNCLOSED_EXCHANGE');
}

// ---------- 9b. 会话级拒绝截断在途首发链路（重连 SP=0 会话过期） ----------
{
  const input = A([C(false), CA(false), P(8), D(), C(false), CA(false)]);
  const t = traceExchange(input, 3);
  check('会话过期截断: termination=REJECTED@6/SESSION_EXPIRED',
    t.termination.kind === 'REJECTED' && t.termination.seq === 6 && t.termination.code === 'SESSION_EXPIRED');
  check('会话过期截断: 无交付', t.deliveredOnce === false);
  check('会话过期截断: 链路序号止于首发@3（拒绝包 CONNACK 作为边界入链@6）',
    JSON.stringify(idSeqs(t)) === '[3]' &&
    t.steps.some((s) => s.seq === 6 && s.type === 'CONNACK' && s.violation?.code === 'SESSION_EXPIRED'));
}

// ---------- 10. 错误查询 ----------
{
  const input = A([C(true), CA(false), P(10), P(10, { dup: true }), REC(10), REL(10), COMP(10)]);
  const expectErr = (name, seq, code) => {
    try { traceExchange(input, seq); check(name, false, '未抛错'); }
    catch (e) { check(name, e instanceof TraceQueryError && e.code === code, `${e.code}/${e.message}`); }
  };
  expectErr('DUP 重发包不能作为首发', 4, 'NOT_AN_ORIGIN');
  expectErr('CONNACK 不能作为首发', 2, 'NOT_AN_ORIGIN');
  expectErr('CONNECT 不能作为首发', 1, 'NOT_AN_ORIGIN');
  expectErr('越界序号 99', 99, 'SEQ_OUT_OF_RANGE');
  expectErr('序号 0', 0, 'SEQ_OUT_OF_RANGE');
  expectErr('非整数序号 abc', 'abc', 'SEQ_INVALID');
  expectErr('小数序号 2.5', 2.5, 'SEQ_INVALID');

  // 冻结证据不被改写：trace 反复调用，裁决结果稳定
  const t1 = JSON.stringify(traceExchange(input, 3).steps);
  const t2 = JSON.stringify(traceExchange(input, 3).steps);
  check('追溯为只读重算：重复查询结果一致', t1 === t2);
}

// ---------- 11. 多标识并行：各自首发可独立追溯 ----------
{
  const input = A([C(true), CA(false),
    P(1), P(2), REC(1), REC(2), REL(1), REL(2), COMP(1), COMP(2), D()]);
  const origins = traceableOrigins(input);
  check('并行: origins 为 seq=3(pid1) seq=4(pid2)',
    origins.length === 2 && origins[0].seq === 3 && origins[0].packetId === 1 &&
    origins[1].seq === 4 && origins[1].packetId === 2);
  const t2 = traceExchange(input, 4);
  check('并行: pid2 链路 [4,6,8,10]', JSON.stringify(idSeqs(t2)) === '[4,6,8,10]');
  check('并行: pid2 链路不含 pid1 报文',
    t2.excludedSameIdPackets.length === 0 && idSeqs(t2).every((s) => [4, 6, 8, 10].includes(s)));
}

// ---------- 12. 追溯结果与冻结裁决逐包证据一致 ----------
{
  const input = A([C(false), CA(false), P(22), REC(22), REL(22), D(142),
    C(false), CA(true), REL(22), COMP(22), D()]);
  const v = adjudicate(input);
  const t = traceExchange(input, 3);
  const consistent = t.steps.filter((s) => s.role !== 'SESSION_BOUNDARY').every((s) => {
    const ev = v.packets[s.seq - 1];
    return ev.connection === s.connection && ev.phase === s.phase;
  });
  check('追溯逐项的连接编号/阶段与逐包裁决一致', consistent);
}

console.log(`\n链路追溯测试：${passed} 通过，${failed} 失败`);
if (failures.length) {
  console.error('\n失败项：');
  failures.forEach((f) => console.error(' ✗ ' + f));
  process.exit(1);
}
console.log('全部通过 ✓');
