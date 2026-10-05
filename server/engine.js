// MQTT 5 QoS 2 遥测交付审计裁决引擎（纯函数，零外部依赖）
//
// 审计目标：
//   1. 判定同一遥测（clientId + Packet Identifier）在断链重发后是否只精确交付一次；
//   2. 识别丢失确认（PUBREC / PUBCOMP）导致的未闭合 QoS 2 交换；
//   3. 依据 Clean Start / Session Present / DUP / Packet Identifier 校验
//      重连恢复、合法重放、阶段跳跃、方向错误、载荷冲突、清除会话后继续旧确认。
//
// 输入包类型白名单：CONNECT、CONNACK、PUBLISH(仅 QoS 2)、PUBREC、PUBREL、PUBCOMP、DISCONNECT
// 方向：C2S（中继→Broker）、S2C（Broker→中继）

export const PACKET_TYPES = Object.freeze([
  'CONNECT',
  'CONNACK',
  'PUBLISH',
  'PUBREC',
  'PUBREL',
  'PUBCOMP',
  'DISCONNECT'
]);

export const PACKET_TYPE_SET = new Set(PACKET_TYPES);
export const MAX_PACKETS = 48;
const ID_BEARING = new Set(['PUBLISH', 'PUBREC', 'PUBREL', 'PUBCOMP']);

// 违规码 => 中文释义（页面与报告共用，保证依据文案稳定）
export const REASON_CODES = Object.freeze({
  OK: '合法：同一遥测精确交付一次，全部 QoS 2 交换闭合',
  EMPTY_CAPTURE: '捕获为空：没有任何可裁决的控制包',
  INPUT_INVALID: '录入数据未通过校验',
  PHASE_SKIP: '阶段跳跃：报文出现在错误的会话阶段',
  WRONG_DIRECTION: '方向错误：报文方向与 MQTT 5 规定相反',
  UNSUPPORTED_PACKET: '报文类型不在审计处理范围内',
  SESSION_PRESENT_CONFLICT: 'Clean Start 与 Session Present 相互矛盾',
  SESSION_EXPIRED: '持久会话重连但 Broker 已无会话（Session Present=0），旧交换不可继续',
  DUP_WITHOUT_ORIGINAL: 'DUP=1 的 PUBLISH 找不到同一包标识的首次发布',
  RESEND_WITHOUT_DUP: '重复 PUBLISH 未置 DUP=1，无法与新交付区分',
  PAYLOAD_CONFLICT: '重发遥测的主题/载荷与首次发布不一致',
  DOUBLE_DELIVERY: '同一遥测存在二次交付风险，违反只交付一次',
  STALE_SESSION_USE: '清除会话（Clean Start=1）后继续旧包标识的确认/重发',
  UNKNOWN_PACKET_ID: '确认报文引用了当前会话中从未发布的包标识',
  DUPLICATE_ACK: '无对应重发即重复收到确认，协议状态异常',
  REPEATED_PUBCOMP: 'PUBCOMP 重复：交换已闭合，再次完成确认会掩盖重复交付',
  PACKET_AFTER_DISCONNECT: 'DISCONNECT 之后未经 CONNECT 直接继续收发',
  UNCLOSED_EXCHANGE: '捕获结束仍存在未闭合的 QoS 2 交换（存在丢失的确认）'
});

export class InputValidationError extends Error {
  constructor(errors) {
    super('录入数据未通过校验');
    this.name = 'InputValidationError';
    this.errors = errors;
  }
}

const asBool = (v) => v === true || v === 'true' || v === 1 || v === '1';

// ---------- 录入校验 ----------
export function validateInput(raw) {
  const errors = [];
  const auditId = raw == null ? null : raw.auditId;
  const clientId = raw == null ? null : raw.clientId;
  const packets = raw == null ? null : raw.packets;

  if (typeof auditId !== 'string' || !auditId.trim()) {
    errors.push({ field: 'auditId', message: '必须录入稳定审计标识' });
  } else if (auditId.trim().length > 128) {
    errors.push({ field: 'auditId', message: '审计标识最长 128 字符' });
  }
  if (typeof clientId !== 'string' || !clientId.trim()) {
    errors.push({ field: 'clientId', message: '必须录入客户端标识' });
  } else if (clientId.trim().length > 512) {
    errors.push({ field: 'clientId', message: '客户端标识最长 512 字符' });
  }
  if (!Array.isArray(packets)) {
    errors.push({ field: 'packets', message: '必须提供按捕获顺序排列的控制包列表' });
    throw new InputValidationError(errors);
  }
  if (packets.length === 0) {
    errors.push({ field: 'packets', message: '至少录入 1 个控制包' });
  }
  if (packets.length > MAX_PACKETS) {
    errors.push({ field: 'packets', message: `最多录入 ${MAX_PACKETS} 条控制包，实际 ${packets.length} 条` });
  }

  packets.forEach((p, i) => {
    const seq = i + 1;
    const where = `第 ${seq} 包`;
    if (p == null || typeof p !== 'object') {
      errors.push({ field: `packets[${i}]`, message: `${where}：不是有效的报文对象` });
      return;
    }
    const type = String(p.type ?? '').toUpperCase();
    const dir = String(p.direction ?? '').toUpperCase();
    if (!PACKET_TYPE_SET.has(type)) {
      errors.push({ field: `packets[${i}].type`, message: `${where}：不支持的报文类型「${p.type}」（仅 ${PACKET_TYPES.join('、')}）` });
    }
    if (dir !== 'C2S' && dir !== 'S2C') {
      errors.push({ field: `packets[${i}].direction`, message: `${where}：方向必须为 C2S 或 S2C` });
    }
    if (type === 'PUBLISH') {
      if (Number(p.qos) !== 2) {
        errors.push({ field: `packets[${i}].qos`, message: `${where}：仅处理 QoS 2 的 PUBLISH，实际 QoS=${p.qos}` });
      }
      if (p.payload == null || String(p.payload).length === 0) {
        errors.push({ field: `packets[${i}].payload`, message: `${where}：遥测载荷不能为空` });
      }
    }
    if (ID_BEARING.has(type)) {
      const pid = Number(p.packetId);
      if (!Number.isInteger(pid) || pid < 1 || pid > 65535) {
        errors.push({ field: `packets[${i}].packetId`, message: `${where}：包标识必须为 1..65535 的整数` });
      }
    }
    if (type === 'CONNECT' && p.cleanStart != null && typeof p.cleanStart !== 'boolean' && p.cleanStart !== 'true' && p.cleanStart !== 'false') {
      errors.push({ field: `packets[${i}].cleanStart`, message: `${where}：Clean Start 必须为布尔值` });
    }
    if (type === 'CONNACK' && p.sessionPresent != null && typeof p.sessionPresent !== 'boolean' && p.sessionPresent !== 'true' && p.sessionPresent !== 'false') {
      errors.push({ field: `packets[${i}].sessionPresent`, message: `${where}：Session Present 必须为布尔值` });
    }
  });

  if (errors.length) throw new InputValidationError(errors);
}

// ---------- 规范化（决定指纹与回放的唯一形态） ----------
export function normalizeInput(raw) {
  return {
    auditId: String(raw.auditId).trim(),
    clientId: String(raw.clientId).trim(),
    packets: raw.packets.map((p) => {
      const type = String(p.type).toUpperCase();
      const n = {
        type,
        direction: String(p.direction).toUpperCase(),
        packetId: ID_BEARING.has(type) ? Number(p.packetId) : null,
        qos: type === 'PUBLISH' ? 2 : null,
        dup: type === 'PUBLISH' ? asBool(p.dup) : null,
        cleanStart: type === 'CONNECT' ? asBool(p.cleanStart) : null,
        sessionPresent: type === 'CONNACK' ? asBool(p.sessionPresent) : null,
        topic: type === 'PUBLISH' ? String(p.topic ?? '') : null,
        payload: type === 'PUBLISH' ? String(p.payload) : null,
        reasonCode: type === 'DISCONNECT' && p.reasonCode != null ? Number(p.reasonCode) : null
      };
      return n;
    })
  };
}

export function stableStringify(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(',')}]`;
  return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

// 输入指纹：相同审计标识 + 完全相同输入 必须命中同一指纹
export function inputFingerprint(raw) {
  return stableStringify(normalizeInput(raw));
}

// ---------- 裁决状态机 ----------
// 单个 Packet Identifier 的 QoS 2 流相：
//   INFLIGHT  已发 PUBLISH，等待/可能已重发（PUBREC 丢失模型）
//   REC_RCVD  已收 PUBREC，等待 PUBREL
//   REL_SENT  已发 PUBREL，等待 PUBCOMP（PUBCOMP 丢失模型）
//   CLOSED    已收 PUBCOMP —— 遥测对应用层精确交付一次完成
function createFlowState() {
  return {
    phase: 'INFLIGHT',
    bornConnection: 0,
    originSeq: null, // 该流实例的首发 PUBLISH 序号（链路追溯原点）
    publishSeq: null,
    firstPublishSeq: null,
    resendSeqs: [],
    pubrecSeqs: [],
    pubrelSeqs: [],
    pubcompSeq: null,
    pubrecPending: false, // DUP 重发后等待 Broker 重放 PUBREC
    topic: null,
    payload: null
  };
}

// 追踪钩子（可选，第二参数）：裁决主循环在不改变任何裁决行为的前提下，
// 向追踪器播报流创建/交换事件/Clean Start 清除/拒绝/未闭合，供 traceExchange 重建链路。
export function adjudicate(rawInput, hooks = null) {
  const input = normalizeInput(rawInput);
  validateInput(input);

  const m = {
    connection: 0, // 当前连接序号（见 CONNECT 自增）
    acknowledged: false, // 当前连接是否已 CONNACK
    disconnected: false, // 当前连接是否已显式 DISCONNECT
    cleanStart: null,
    sessionPresent: null,
    prevConnectionClean: null, // 上一条成功建立的连接是否 Clean Start
    flows: new Map(), // packetId -> flow（持久会话重连保留；Clean Start 清空）
    everDelivered: new Map(), // `${clientId}|${pid}` -> 首次 PUBCOMP 序号（跨连接、不清空）
    deliveryOrigin: new Map(), // `${clientId}|${pid}` -> 完成该交付的首发序号
    retiredByClean: new Map(), // pid -> { originSeq, connectSeq }：被 Clean Start 清除的流
    lastConnectSeq: 0
  };

  const evidence = input.packets.map((p, i) => ({
    seq: i + 1,
    connection: 0,
    type: p.type,
    direction: p.direction,
    packetId: p.packetId,
    dup: p.dup,
    phase: '—',
    firstDelivery: null, // FIRST / RESEND / DELIVERED_ONCE / null
    note: '',
    violation: null
  }));

  const reject = (seq, code, detail) => {
    evidence[seq - 1].violation = { code, detail };
    if (hooks && typeof hooks.onReject === 'function') {
      hooks.onReject({ seq, code, detail, packet: input.packets[seq - 1], state: m });
    }
    return {
      verdict: 'REJECTED',
      reason: code,
      reasonText: REASON_CODES[code] ?? code,
      reasonSeq: seq,
      packets: evidence,
      summary: buildSummary(m)
    };
  };

  const requireEstablished = (seq) => {
    if (m.connection === 0) {
      return reject(seq, 'PHASE_SKIP', `第 ${seq} 包出现在 CONNECT/CONNACK 建连之前（阶段跳跃）`);
    }
    if (!m.acknowledged) {
      return reject(seq, 'PHASE_SKIP', `第 ${seq} 包出现在 CONNACK 之前：第 ${m.connection} 条连接尚未确认（阶段跳跃）`);
    }
    return null;
  };

  // 追溯钩子：把归属某流实例的报文序号播报给追踪器（不影响裁决）
  const touchFlow = (seq, f) => {
    if (hooks && typeof hooks.onFlowPacket === 'function') {
      hooks.onFlowPacket({ seq, originSeq: f.originSeq });
    }
  };

  for (const [i, p] of input.packets.entries()) {
    const seq = i + 1;
    const e = evidence[i];

    // ---------- CONNECT：显式重连或断链（无 DISCONNECT）隐式重连 ----------
    if (p.type === 'CONNECT') {
      if (p.direction !== 'C2S') {
        return reject(seq, 'WRONG_DIRECTION', `第 ${seq} 包 CONNECT 必须 C2S（中继→Broker），实际为 S2C`);
      }
      if (m.disconnected) {
        // DISCONNECT 之后的 CONNECT 是合法的显式重连
        m.disconnected = false;
      }
      m.connection += 1;
      m.lastConnectSeq = seq;
      m.cleanStart = p.cleanStart;
      m.sessionPresent = null;
      m.acknowledged = false;
      e.connection = m.connection;
      e.phase = `CONNECT #${m.connection}`;
      e.note = p.cleanStart ? 'Clean Start=1：请求全新会话，Broker 必须清除旧会话状态'
        : 'Clean Start=0：请求恢复持久会话';

      if (p.cleanStart) {
        // Broker 侧旧会话状态被清除：在途流与发布记忆全部失效。
        // everDelivered 保留——它是审计侧"同一遥测曾经交付"的事实，用于拦截新会话双投。
        for (const [pid, of] of m.flows) {
          // 记录被清除的旧链路，供追溯：旧确认只能终止于该 CONNECT
          m.retiredByClean.set(pid, { originSeq: of.originSeq, connectSeq: seq });
          if (hooks && typeof hooks.onFlowRetired === 'function') {
            hooks.onFlowRetired({ pid, originSeq: of.originSeq, connectSeq: seq });
          }
        }
        m.flows.clear();
      }
      continue;
    }

    // 非 CONNECT 报文：DISCONNECT 后未重连即继续收发 => 违规
    if (m.disconnected) {
      return reject(seq, 'PACKET_AFTER_DISCONNECT',
        `第 ${seq} 包(${p.type})出现在 DISCONNECT(第 ${m.lastConnectSeq ? '前' : ''}一连接)之后且未重新 CONNECT；断开后须先建连才能继续旧确认或重发`);
    }
    if (m.connection === 0) {
      return reject(seq, 'PHASE_SKIP', `第 ${seq} 包(${p.type})之前缺少 CONNECT（阶段跳跃）`);
    }
    e.connection = m.connection;

    // ---------- CONNACK ----------
    if (p.type === 'CONNACK') {
      if (p.direction !== 'S2C') {
        return reject(seq, 'WRONG_DIRECTION', `第 ${seq} 包 CONNACK 必须 S2C（Broker→中继），实际为 C2S`);
      }
      if (m.acknowledged) {
        return reject(seq, 'PHASE_SKIP', `第 ${seq} 包重复 CONNACK：第 ${m.connection} 条连接已确认过（阶段跳跃）`);
      }
      const sp = p.sessionPresent;
      if (m.cleanStart === true && sp === true) {
        return reject(seq, 'SESSION_PRESENT_CONFLICT',
          `第 ${seq} 包 CONNACK Session Present=1 与 CONNECT Clean Start=1 矛盾：MQTT 5 规定 Clean Start 时 Broker 必须回 SP=0`);
      }
      if (m.cleanStart === false && m.connection === 1 && sp === true) {
        return reject(seq, 'SESSION_PRESENT_CONFLICT',
          `第 ${seq} 包首次连接(Clean Start=0)即收到 Session Present=1：Broker 不可能预先存在该客户端的持久会话`);
      }
      if (m.connection > 1 && m.cleanStart === false && m.prevConnectionClean === true && sp === true) {
        return reject(seq, 'SESSION_PRESENT_CONFLICT',
          `第 ${seq} 包上一条连接以 Clean Start=1 清除了会话，Broker 不可能对本次重连宣告 Session Present=1`);
      }
      if (m.connection > 1 && m.cleanStart === false && sp === false) {
        return reject(seq, 'SESSION_EXPIRED',
          `第 ${seq} 包重连请求恢复持久会话(Clean Start=0)，但 CONNACK Session Present=0：Broker 侧会话已过期/被清除，旧包标识的确认与重放均无状态可依`);
      }
      m.sessionPresent = sp;
      m.acknowledged = true;
      e.phase = `CONNACK #${m.connection}`;
      e.note = `Session Present=${sp ? 1 : 0}` + (sp ? '：持久会话恢复成功，在途交换可继续' : '：无既有会话');
      m.prevConnectionClean = m.cleanStart;
      continue;
    }

    const est = requireEstablished(seq);
    if (est) return est;
    const pid = p.packetId;

    // ---------- PUBLISH (QoS 2) ----------
    if (p.type === 'PUBLISH') {
      if (p.direction !== 'C2S') {
        return reject(seq, 'WRONG_DIRECTION', `第 ${seq} 包 PUBLISH(QoS2) 必须 C2S（中继遥测上行），实际为 S2C`);
      }
      const f = m.flows.get(pid);

      if (!f) {
        // 当前会话中该标识首次出现
        if (p.dup) {
          return reject(seq, 'DUP_WITHOUT_ORIGINAL',
            `第 ${seq} 包 PUBLISH 包标识 ${pid} 置 DUP=1，但当前会话没有同标识的首次 PUBLISH（${m.cleanStart ? '会话已被 Clean Start 清除，' : ''}首发缺失或捕获不全），不能认定为合法重放`);
        }
        // 新会话（含 Clean Start 重连）重发一个"曾经交付完成"的标识 => 同一遥测二次交付
        const dkey = `${input.clientId}|${pid}`;
        if (m.everDelivered.has(dkey)) {
          return reject(seq, 'DOUBLE_DELIVERY',
            `第 ${seq} 包在${m.connection > 1 ? '重连后的' : ''}会话中首次出现包标识 ${pid}，但该遥测已于第 ${m.everDelivered.get(dkey)} 包 PUBCOMP 完成交付；Broker 此次将当作新报文再次交付，违反只交付一次`);
        }
        const nf = createFlowState();
        nf.bornConnection = m.connection;
        nf.originSeq = seq;
        nf.firstPublishSeq = seq;
        nf.publishSeq = seq;
        nf.topic = p.topic;
        nf.payload = p.payload;
        m.flows.set(pid, nf);
        e.phase = 'INFLIGHT';
        e.firstDelivery = 'FIRST';
        e.note = '首次发布：等待 PUBREC';
        touchFlow(seq, nf);
        if (hooks && typeof hooks.onOrigin === 'function') {
          hooks.onOrigin({ seq, pid, connection: m.connection, packet: p });
        }
        continue;
      }

      // 同标识再次 PUBLISH —— 必为断链重发
      if (!p.dup) {
        return reject(seq, 'RESEND_WITHOUT_DUP',
          `第 ${seq} 包对在途包标识 ${pid} 再次 PUBLISH 却未置 DUP=1；重发必须显式标记，否则无法与新遥测区分，破坏精确一次判定`);
      }
      if (f.phase === 'CLOSED') {
        return reject(seq, 'DOUBLE_DELIVERY',
          `第 ${seq} 包重发包标识 ${pid}：该交换已由第 ${f.pubcompSeq} 包 PUBCOMP 闭合且遥测已交付，持久会话内重发将导致同一遥测二次交付`);
      }
      if (f.topic !== p.topic || f.payload !== p.payload) {
        return reject(seq, 'PAYLOAD_CONFLICT',
          `第 ${seq} 包重发包标识 ${pid} 的${f.topic !== p.topic ? `主题(首包「${f.topic}」/重发「${p.topic}」)` : `载荷(首包「${f.payload}」/重发「${p.payload}」)`}与第 ${f.firstPublishSeq} 包首次发布不一致；合法重放必须携带完全相同的遥测`);
      }
      if (f.phase === 'REC_RCVD') {
        return reject(seq, 'PHASE_SKIP',
          `第 ${seq} 包在已收 PUBREC(第 ${f.pubrecSeqs[f.pubrecSeqs.length - 1]} 包)后重发整个 PUBLISH 包标识 ${pid}：应发送 PUBREL 完成后半程，而非重发报文`);
      }
      if (f.phase === 'REL_SENT') {
        return reject(seq, 'PHASE_SKIP',
          `第 ${seq} 包在已发 PUBREL(第 ${f.pubrelSeqs[f.pubrelSeqs.length - 1]} 包)后重发整个 PUBLISH 包标识 ${pid}：QoS 2 后半程只能重传 PUBREL，不得重发报文`);
      }
      // INFLIGHT + DUP=1 + 载荷一致 => 合法重放（PUBREC 丢失 / 断链恢复），Broker 去重，不产生二次交付
      f.resendSeqs.push(seq);
      f.publishSeq = seq;
      f.pubrecPending = true;
      e.phase = 'INFLIGHT';
      e.firstDelivery = 'RESEND';
      e.note = '合法重放：DUP=1 且载荷与首包一致，Broker 按包标识去重，不重复交付';
      touchFlow(seq, f);
      continue;
    }

    // ---------- PUBREC ----------
    if (p.type === 'PUBREC') {
      if (p.direction !== 'S2C') {
        return reject(seq, 'WRONG_DIRECTION', `第 ${seq} 包 PUBREC 必须 S2C（Broker→中继），实际为 C2S`);
      }
      const f = m.flows.get(pid);
      if (!f) {
        return reject(seq, 'UNKNOWN_PACKET_ID',
          `第 ${seq} 包 PUBREC 引用包标识 ${pid}，但当前会话从未发布该标识报文${m.cleanStart ? '（Clean Start=1 已清除旧会话，属清除会话后继续旧确认）' : ''}`);
      }
      if (f.phase === 'CLOSED') {
        return reject(seq, 'DOUBLE_DELIVERY',
          `第 ${seq} 包对已闭合包标识 ${pid}(PUBCOMP@${f.pubcompSeq})重发 PUBREC：重复启动 QoS 2 应答链，存在二次交付风险`);
      }
      if (f.phase === 'REC_RCVD' || f.phase === 'REL_SENT') {
        // 仅在存在对应 DUP 重发时，重复 PUBREC 才是 Broker 对重发的合法重放
        if (f.phase === 'REC_RCVD' && f.pubrecPending) {
          f.pubrecPending = false;
          f.pubrecSeqs.push(seq);
          e.phase = 'REC_RCVD';
          e.note = '对 DUP 重发的 PUBREC 重放（合法重传确认）';
          touchFlow(seq, f);
          continue;
        }
        return reject(seq, 'DUPLICATE_ACK',
          `第 ${seq} 包重复 PUBREC 包标识 ${pid}：此前已于第 ${f.pubrecSeqs[f.pubrecSeqs.length - 1]} 包确认，且区间内没有对应的 DUP=1 重发`);
      }
      f.phase = 'REC_RCVD';
      f.pubrecSeqs.push(seq);
      f.pubrecPending = false;
      e.phase = 'REC_RCVD';
      e.note = 'Broker 已收齐遥测，等待中继发送 PUBREL';
      touchFlow(seq, f);
      continue;
    }

    // ---------- PUBREL ----------
    if (p.type === 'PUBREL') {
      if (p.direction !== 'C2S') {
        return reject(seq, 'WRONG_DIRECTION', `第 ${seq} 包 PUBREL 必须 C2S（中继→Broker），实际为 S2C`);
      }
      const f = m.flows.get(pid);
      if (!f) {
        return reject(seq, 'STALE_SESSION_USE',
          `第 ${seq} 包 PUBREL 引用包标识 ${pid}，但当前会话无该在途交换${m.cleanStart ? '：Clean Start=1 已清除会话，属清除会话后继续旧确认' : '（旧确认无状态可依）'}`);
      }
      if (f.phase === 'CLOSED') {
        return reject(seq, 'DOUBLE_DELIVERY',
          `第 ${seq} 包对已闭合包标识 ${pid}(PUBCOMP@${f.pubcompSeq})重发 PUBREL：重复释放将诱导 Broker 重复完成处理`);
      }
      if (f.phase === 'REL_SENT') {
        // PUBCOMP 丢失后的 PUBREL 重传（含重连恢复），MQTT 5 允许，合法
        f.pubrelSeqs.push(seq);
        e.phase = 'REL_SENT';
        e.note = 'PUBREL 重传：此前 PUBCOMP 丢失/未达，等待 Broker 重发 PUBCOMP';
        touchFlow(seq, f);
        continue;
      }
      // INFLIGHT 直接到 PUBREL：捕获缺失 PUBREC。中继不应在未收 PUBREC 时发 PUBREL，
      // 属阶段跳跃（即便个别 Broker 容忍，审计证据链不闭合）。
      if (f.phase === 'INFLIGHT') {
        return reject(seq, 'PHASE_SKIP',
          `第 ${seq} 包 PUBREL 包标识 ${pid} 先于 PUBREC：尚未收到 Broker 的 PUBREC 即进入释放阶段（阶段跳跃，疑似伪造/丢失中间确认）`);
      }
      f.phase = 'REL_SENT';
      f.pubrelSeqs.push(seq);
      e.phase = 'REL_SENT';
      e.note = '中继请求释放报文副本，等待 PUBCOMP';
      touchFlow(seq, f);
      continue;
    }

    // ---------- PUBCOMP ----------
    if (p.type === 'PUBCOMP') {
      if (p.direction !== 'S2C') {
        return reject(seq, 'WRONG_DIRECTION', `第 ${seq} 包 PUBCOMP 必须 S2C（Broker→中继），实际为 C2S`);
      }
      const f = m.flows.get(pid);
      if (!f) {
        return reject(seq, 'STALE_SESSION_USE',
          `第 ${seq} 包 PUBCOMP 引用包标识 ${pid}，但当前会话无该在途交换${m.cleanStart ? '：Clean Start=1 已清除会话，属清除会话后继续旧确认' : '（伪造的完成确认）'}`);
      }
      if (f.phase === 'CLOSED') {
        return reject(seq, 'REPEATED_PUBCOMP',
          `第 ${seq} 包重复 PUBCOMP 包标识 ${pid}：该遥测已于第 ${f.pubcompSeq} 包精确交付一次，重复完成确认无协议依据并会掩盖双投`);
      }
      if (f.phase !== 'REL_SENT') {
        return reject(seq, 'PHASE_SKIP',
          `第 ${seq} 包 PUBCOMP 包标识 ${pid} 阶段错误：当前为 ${f.phase}，必须先有 PUBREL 才能完成交付`);
      }
      const dkey = `${input.clientId}|${pid}`;
      if (m.everDelivered.has(dkey)) {
        return reject(seq, 'DOUBLE_DELIVERY',
          `第 ${seq} 包 PUBCOMP 包标识 ${pid}：同一遥测已于第 ${m.everDelivered.get(dkey)} 包完成交付，再次 PUBCOMP 构成二次交付`);
      }
      f.phase = 'CLOSED';
      f.pubcompSeq = seq;
      m.everDelivered.set(dkey, seq);
      m.deliveryOrigin.set(dkey, f.originSeq);
      e.phase = 'CLOSED';
      e.firstDelivery = 'DELIVERED_ONCE';
      e.note = '精确一次交付完成：该遥测仅此一次交付给应用方';
      touchFlow(seq, f);
      if (hooks && typeof hooks.onClosed === 'function') {
        hooks.onClosed({ seq, pid, originSeq: f.originSeq, connection: m.connection });
      }
      continue;
    }

    // ---------- DISCONNECT ----------
    if (p.type === 'DISCONNECT') {
      if (p.direction !== 'C2S') {
        return reject(seq, 'WRONG_DIRECTION', `第 ${seq} 包 DISCONNECT 必须 C2S（中继→Broker），实际为 S2C`);
      }
      m.disconnected = true;
      e.phase = `DISCONNECT #${m.connection}`;
      e.note = p.reasonCode != null && p.reasonCode !== 0
        ? `异常断开（Reason Code=${p.reasonCode}）`
        : '正常断开';
      continue;
    }

    return reject(seq, 'UNSUPPORTED_PACKET', `第 ${seq} 包类型 ${p.type} 不在审计处理范围内`);
  }

  // ---------- 收尾：未闭合交换（丢失确认） ----------
  for (const [pid, f] of m.flows) {
    let seq;
    let detail;
    switch (f.phase) {
      case 'INFLIGHT':
        seq = f.publishSeq;
        detail = `未闭合会话：包标识 ${pid} 的遥测停留在 PUBLISH 已发、PUBREC 未收阶段（链路中断导致 PUBREC${f.resendSeqs.length ? '/重发响应' : ''}丢失），遥测是否已到达 Broker 不可确认`;
        break;
      case 'REC_RCVD':
        seq = f.pubrecSeqs[f.pubrecSeqs.length - 1];
        detail = `未闭合会话：包标识 ${pid} 已收 PUBREC(第 ${seq} 包)但未见 PUBREL/PUBCOMP，交换未走完释放阶段`;
        break;
      case 'REL_SENT':
        seq = f.pubrelSeqs[f.pubrelSeqs.length - 1];
        detail = `未闭合会话：包标识 ${pid} 已发 PUBREL(第 ${seq} 包)但 PUBCOMP 丢失，Broker 侧副本尚未释放、应用交付未得到确认`;
        break;
      default:
        continue;
    }
    evidence[seq - 1].violation = { code: 'UNCLOSED_EXCHANGE', detail };
    if (hooks && typeof hooks.onUnclosed === 'function') {
      hooks.onUnclosed({ pid, originSeq: f.firstPublishSeq, phase: f.phase, seq });
    }
    return {
      verdict: 'REJECTED',
      reason: 'UNCLOSED_EXCHANGE',
      reasonText: REASON_CODES.UNCLOSED_EXCHANGE,
      reasonSeq: seq,
      packets: evidence,
      summary: buildSummary(m)
    };
  }

  return {
    verdict: 'ACCEPTED',
    reason: 'OK',
    reasonText: REASON_CODES.OK,
    reasonSeq: 0,
    packets: evidence,
    summary: buildSummary(m)
  };
}

function buildSummary(m) {
  const ids = [...m.flows.keys()];
  return {
    connections: m.connection,
    lastCleanStart: m.cleanStart,
    lastSessionPresent: m.sessionPresent,
    deliveredOnce: m.everDelivered.size,
    closedPacketIds: ids.filter((id) => m.flows.get(id).phase === 'CLOSED'),
    openPacketIds: ids.filter((id) => m.flows.get(id).phase !== 'CLOSED')
  };
}

// ==================== 首发交换链路追溯（冻结证据只读重算） ====================
//
// 「首发」= 一个 QoS 2 流实例的第一条非 DUP PUBLISH（逐包证据 firstDelivery==='FIRST'）。
// 持久会话重连（Clean Start=0 / CONNACK Session Present=1）沿用同一个流实例，跨连接的
// PUBLISH(DUP=1) 重发、PUBREL 重传都挂在同一条首发链路下；Clean Start=1 清除流，
// 此后同标识报文属于前一链路的终止边界，不得并入新的首发。
//
// 链路终点 termination.kind：
//   CLOSED       正常闭合（PUBCOMP），首发产生唯一交付
//   REJECTED     在归属该首发的报文上裁决拒绝（闭合后重用、清除后旧确认、载荷冲突等）
//   CLEAN_START  在途流被后续 Clean Start=1 的 CONNECT 清除且其后无归属旧确认被拒
//   CAPTURE_END  捕获结束仍未闭合（UNCLOSED_EXCHANGE 或裁决被其他包提前截断）
//
// 追溯对同一输入再跑一遍裁决（带采集钩子），只读、绝不固化或改写证据。

export class TraceQueryError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'TraceQueryError';
    this.code = code;
    Object.assign(this, extra);
  }
}

const TRACE_ACK_RELATION = Object.freeze({
  PUBLISH: 'PUBLISH→PUBREC（中继发布，等待 Broker 接收确认）',
  PUBREC: 'PUBLISH→PUBREC（Broker 确认已收齐遥测）',
  PUBREL: 'PUBREC→PUBREL（中继请求释放副本）',
  PUBCOMP: 'PUBREL→PUBCOMP（Broker 完成释放，交付应用方）'
});

const BOUNDARY_TYPES = new Set(['CONNECT', 'CONNACK', 'DISCONNECT']);
const ID_TYPES = new Set(['PUBLISH', 'PUBREC', 'PUBREL', 'PUBCOMP']);

// 对输入再跑一遍裁决并采集追溯所需的中间事实
function collectTraceFacts(normalized) {
  const clientId = normalized.clientId;
  const facts = {
    verdict: null,
    origins: new Map(),      // originSeq -> { pid, connection }
    owner: new Map(),        // 报文序号 -> 所属首发序号（同一流实例）
    closed: new Map(),       // originSeq -> { seq, pid }
    retired: new Map(),      // originSeq -> { pid, connectSeq }
    unclosed: null,          // { pid, originSeq, phase, seq }
    reject: null             // { seq, pid, originSeq, deliveredOriginSeq, retiredOriginSeq, openOriginSeqs }
  };

  facts.verdict = adjudicate(normalized, {
    onOrigin: ({ seq, pid, connection }) => facts.origins.set(seq, { pid, connection }),
    onFlowPacket: ({ seq, originSeq }) => facts.owner.set(seq, originSeq),
    onClosed: ({ seq, pid, originSeq }) => facts.closed.set(originSeq, { seq, pid }),
    onFlowRetired: ({ pid, originSeq, connectSeq }) =>
      facts.retired.set(originSeq, { pid, connectSeq }),
    onUnclosed: (u) => { facts.unclosed = u; },
    onReject: ({ seq, packet, state }) => {
      const rec = { seq, pid: null, originSeq: null, deliveredOriginSeq: null, retiredOriginSeq: null, openOriginSeqs: [] };
      for (const [fpid, f] of state.flows) {
        if (f.phase !== 'CLOSED') rec.openOriginSeqs.push(f.originSeq);
        void fpid;
      }
      if (packet && ID_TYPES.has(packet.type)) {
        rec.pid = packet.packetId;
        const f = state.flows.get(packet.packetId);
        rec.originSeq = f ? f.originSeq : null;
        const dkey = `${clientId}|${packet.packetId}`;
        if (state.everDelivered.has(dkey)) rec.deliveredOriginSeq = state.deliveryOrigin.get(dkey);
        const rt = state.retiredByClean.get(packet.packetId);
        rec.retiredOriginSeq = rt ? rt.originSeq : null;
      }
      facts.reject = rec;
    }
  });
  return facts;
}

// 列出全部可作为追溯原点的首发 PUBLISH（保持捕获顺序）
export function traceableOrigins(rawInput) {
  const normalized = normalizeInput(rawInput);
  validateInput(normalized);
  const verdict = adjudicate(normalized);
  return verdict.packets
    .filter((p) => p.type === 'PUBLISH' && p.firstDelivery === 'FIRST')
    .map((p) => ({ seq: p.seq, packetId: p.packetId, connection: p.connection }));
}

// 从指定首发序号重建有序交换链路（纯函数、只读）
export function traceExchange(rawInput, seqRaw) {
  const normalized = normalizeInput(rawInput);
  validateInput(normalized);
  const total = normalized.packets.length;

  const seq = Number(seqRaw);
  if (!Number.isInteger(seq)) {
    throw new TraceQueryError('SEQ_INVALID',
      `首发序号必须为 1..${total} 的整数，实际为「${seqRaw}」`);
  }
  if (seq < 1 || seq > total) {
    throw new TraceQueryError('SEQ_OUT_OF_RANGE',
      `首发序号 ${seq} 越界：该审计共 ${total} 包，合法范围 1..${total}`,
      { seq, packetCount: total });
  }

  const facts = collectTraceFacts(normalized);
  const verdict = facts.verdict;
  const originInfo = facts.origins.get(seq);

  if (!originInfo) {
    const pk = normalized.packets[seq - 1];
    const ev = verdict.packets[seq - 1];
    let reason;
    if (pk.type !== 'PUBLISH') {
      reason = `第 ${seq} 包是 ${pk.type} 而不是 PUBLISH：交换链路只能从首发 PUBLISH 开始追查`;
    } else if (pk.dup) {
      reason = `第 ${seq} 包是 DUP=1 的重发 PUBLISH（包标识 ${pk.packetId}），重发不是首发；请选择该标识本次会话最早的非 DUP PUBLISH 作为链路原点`;
    } else if (ev.violation) {
      reason = `第 ${seq} 包 PUBLISH（包标识 ${pk.packetId}）在建立流实例前即被判 ${ev.violation.code}，未形成可追溯的首发`;
    } else {
      reason = `第 ${seq} 包不构成可追溯的首发 PUBLISH`;
    }
    throw new TraceQueryError('NOT_AN_ORIGIN', reason, {
      seq, packetType: pk.type, packetId: pk.packetId ?? null, dup: pk.dup
    });
  }

  const pid = originInfo.pid;

  // ---------- 终止点归属 ----------
  // 全局拒绝是否归属本首发：
  //   (a) 拒绝报文直接引用本 pid，且其流/已交付/被清除记录指向本首发；或
  //   (b) 会话级拒绝（违规包无 packetId，如 SESSION_EXPIRED/SESSION_PRESENT_CONFLICT）
  //       发生时本首发仍 open —— 链路被该拒绝截断。
  const rj = facts.reject;
  const rejectAttributed = !!(rj && rj.seq != null && rj.pid === pid &&
    (rj.originSeq === seq || rj.deliveredOriginSeq === seq || rj.retiredOriginSeq === seq));
  const rejectTruncates = !!(rj && rj.seq != null && !rejectAttributed &&
    rj.openOriginSeqs.includes(seq) && rj.seq >= seq &&
    !(facts.closed.has(seq)));
  const closed = facts.closed.get(seq) || null;
  const retired = facts.retired.get(seq) || null;

  let endSeq;
  let termination;
  if (rejectAttributed || rejectTruncates) {
    endSeq = rj.seq;
    const violEv = verdict.packets[rj.seq - 1];
    termination = {
      kind: 'REJECTED',
      seq: rj.seq,
      code: verdict.reason,
      reason: violEv.violation?.detail || verdict.reasonText
    };
  } else if (closed) {
    endSeq = closed.seq;
    termination = {
      kind: 'CLOSED',
      seq: closed.seq,
      code: null,
      reason: `第 ${closed.seq} 包 PUBCOMP 闭合：包标识 ${pid} 的首发遥测完成唯一一次应用交付`
    };
  } else if (retired) {
    endSeq = retired.connectSeq;
    termination = {
      kind: 'CLEAN_START',
      seq: retired.connectSeq,
      code: null,
      reason: `第 ${retired.connectSeq} 包 CONNECT 以 Clean Start=1 建立全新会话，包标识 ${pid} 的旧会话状态被清除；旧链路到此终止，之后同标识报文不得并入本首发`
    };
  } else {
    endSeq = total;
    const u = facts.unclosed && facts.unclosed.originSeq === seq ? facts.unclosed : null;
    termination = {
      kind: 'CAPTURE_END',
      seq: null,
      code: u ? 'UNCLOSED_EXCHANGE' : null,
      reason: u
        ? `捕获结束时包标识 ${pid} 停留在 ${u.phase}：存在丢失的确认，交换未闭合`
        : `捕获结束（第 ${total} 包）时包标识 ${pid} 的交换未走完（裁决可能已被其他包提前终止）`
    };
  }

  // ---------- 链路成员：归属本首发的标识报文 + 区间内连接边界包 ----------
  const memberSeqs = [];
  for (let s = seq; s <= endSeq; s++) {
    const pk = normalized.packets[s - 1];
    if (ID_TYPES.has(pk.type)) {
      if (facts.owner.get(s) === seq) memberSeqs.push(s);
    } else if (BOUNDARY_TYPES.has(pk.type)) {
      memberSeqs.push(s);
    }
  }
  // 被归属的拒绝报文本身（可能尚未建流，owner 中无记录）
  if (rejectAttributed && !memberSeqs.includes(rj.seq)) memberSeqs.push(rj.seq);
  memberSeqs.sort((a, b) => a - b);

  // ---------- 逐项组装 ----------
  const steps = memberSeqs.map((s, idx) => {
    const pk = normalized.packets[s - 1];
    const ev = verdict.packets[s - 1];
    const isTerminalViolation = (rejectAttributed || rejectTruncates) && s === rj.seq;
    const step = {
      order: idx + 1,
      seq: s,
      connection: ev.connection,
      type: pk.type,
      direction: pk.direction,
      packetId: pk.packetId,
      dup: pk.dup,
      phase: ev.phase,
      role: null,
      ackRelation: null,
      acknowledges: null,
      deliveryEffect: null,
      note: ev.note || '',
      violation: isTerminalViolation ? (ev.violation || {
        code: verdict.reason, detail: termination.reason
      }) : null
    };

    if (BOUNDARY_TYPES.has(pk.type)) {
      step.role = 'SESSION_BOUNDARY';
      step.ackRelation = null;
      if (pk.type === 'CONNECT') {
        step.note = pk.cleanStart
          ? 'Clean Start=1：Broker 清除旧会话状态（旧链路终止边界）'
          : 'Clean Start=0：请求恢复持久会话';
      } else if (pk.type === 'CONNACK') {
        step.note = pk.sessionPresent
          ? 'Session Present=1：持久会话恢复成功，在途交换跨连接沿用同一首发交付'
          : 'Session Present=0：无既有会话状态';
      }
      return step;
    }

    step.ackRelation = TRACE_ACK_RELATION[pk.type];
    if (pk.type === 'PUBLISH') {
      if (s === seq) {
        step.role = 'FIRST_PUBLISH';
        step.deliveryEffect = 'FIRST_DELIVERY_CANDIDATE';
      } else if (ev.firstDelivery === 'RESEND') {
        // 引擎认可的合法重放（DUP=1、载荷一致、Broker 去重）
        step.role = 'RESEND';
        step.deliveryEffect = 'DEDUPED_RESEND';
      } else {
        // 闭合后重发 / 清除后重用：未被认可为重放，终止前的二次交付尝试
        step.role = 'REUSE_AFTER_TERMINATION';
        step.deliveryEffect = 'REJECTED_BEFORE_DELIVERY';
      }
    } else if (pk.type === 'PUBREC') {
      step.role = 'ACK';
    } else if (pk.type === 'PUBREL') {
      step.role = 'RELAY';
    } else if (pk.type === 'PUBCOMP') {
      step.role = 'COMPLETE';
      if (closed && s === closed.seq) step.deliveryEffect = 'UNIQUE_DELIVERY';
    }
    return step;
  });

  // 确认/重传关系：应答最近的对应前序包；PUBREL 重传指向前一 PUBREL
  const lastByType = {};
  for (const st of steps) {
    if (st.role === 'SESSION_BOUNDARY') continue;
    if (st.type === 'PUBLISH') {
      if (st.role === 'RESEND' || st.role === 'REUSE_AFTER_TERMINATION') {
        st.acknowledges = lastByType.PUBLISH ?? seq;
      }
      lastByType.PUBLISH = st.seq;
    } else if (st.type === 'PUBREC') {
      st.acknowledges = lastByType.PUBLISH ?? seq;
      lastByType.PUBREC = st.seq;
    } else if (st.type === 'PUBREL') {
      st.acknowledges = lastByType.PUBREL ?? lastByType.PUBREC ?? null;
      lastByType.PUBREL = st.seq;
    } else if (st.type === 'PUBCOMP') {
      st.acknowledges = lastByType.PUBREL ?? null;
      lastByType.PUBCOMP = st.seq;
    }
  }

  // ---------- 连接跨度与跨连接恢复说明 ----------
  const connFlags = new Map(); // connection -> { cleanStart, sessionPresent, connectSeq, connackSeq }
  let curConn = 0;
  normalized.packets.forEach((pk, i) => {
    const ev = verdict.packets[i];
    if (pk.type === 'CONNECT') {
      curConn = ev.connection;
      connFlags.set(curConn, { cleanStart: pk.cleanStart, sessionPresent: null, connectSeq: ev.seq, connackSeq: null });
    } else if (pk.type === 'CONNACK') {
      const f = connFlags.get(ev.connection);
      if (f) { f.sessionPresent = pk.sessionPresent; f.connackSeq = ev.seq; }
    }
  });

  const connSeqs = new Map();
  for (const st of steps) {
    if (st.role === 'SESSION_BOUNDARY') continue;
    if (!connSeqs.has(st.connection)) connSeqs.set(st.connection, []);
    connSeqs.get(st.connection).push(st);
  }
  const connectionSpans = [...connSeqs.entries()].map(([connection, ss]) => {
    const f = connFlags.get(connection) || {};
    return {
      connection,
      fromSeq: ss[0].seq,
      toSeq: ss[ss.length - 1].seq,
      cleanStart: f.cleanStart ?? null,
      sessionPresent: f.sessionPresent ?? null,
      connectSeq: f.connectSeq ?? null,
      connackSeq: f.connackSeq ?? null,
      resumed: f.cleanStart === false && f.sessionPresent === true
    };
  });

  const crossConnection = connectionSpans.length > 1;
  const recovery = connectionSpans.slice(1).map((span) => ({
    connection: span.connection,
    connectSeq: span.connectSeq,
    connackSeq: span.connackSeq,
    cleanStart: span.cleanStart,
    sessionPresent: span.sessionPresent,
    resumed: span.resumed,
    continuesFirstDeliverySeq: seq,
    retransmitted: steps
      .filter((s) => s.connection === span.connection &&
        (s.type === 'PUBREL' || (s.type === 'PUBLISH' && s.dup)))
      .map((s) => ({ seq: s.seq, type: s.type, role: s.role })),
    note: span.resumed
      ? `第 ${span.connection} 条连接以 Clean Start=0 恢复、CONNACK(第 ${span.connackSeq} 包) Session Present=1：包标识 ${pid} 沿用第 ${seq} 包首发的同一交付，跨连接重传 PUBREL/PUBLISH 不产生新交付`
      : `第 ${span.connection} 条连接（Clean Start=${span.cleanStart === null ? '—' : (span.cleanStart ? 1 : 0)}, Session Present=${span.sessionPresent === null ? '—' : (span.sessionPresent ? 1 : 0)}）`
  }));

  // ---------- 未并入链路的同标识报文（审查核对依据） ----------
  const included = new Set(memberSeqs);
  const excludedSameIdPackets = [];
  for (let s = 1; s <= total; s++) {
    const pk = normalized.packets[s - 1];
    if (!ID_TYPES.has(pk.type) || pk.packetId !== pid || included.has(s)) continue;
    let reason;
    if (s < seq) {
      reason = '早于本首发：属于更早的（已清除）流实例，不并入本链路';
    } else if (facts.owner.get(s) && facts.owner.get(s) !== seq) {
      reason = '属于 Clean Start 后新会话对同一包标识的另一首发链路，与本首发互不混淆';
    } else if (termination.kind === 'CLEAN_START') {
      reason = '晚于 Clean Start 清除边界：清除会话后继续旧确认/重发，只作为前一链路的终止依据，不属新首发';
    } else if (closed && s > closed.seq) {
      reason = '晚于闭合序号：闭合后重用同一包标识，作为前一链路的终止/违规依据，不构成新首发链路内容';
    } else if (s > endSeq) {
      reason = '晚于本链路终止点，不并入本首发';
    } else {
      reason = '不属于本首发流实例';
    }
    excludedSameIdPackets.push({
      seq: s, type: pk.type, connection: verdict.packets[s - 1].connection,
      dup: pk.dup, reason
    });
  }

  const deliveredOnce = !!closed;
  return {
    auditId: normalized.auditId,
    clientId: normalized.clientId,
    packetId: pid,
    origin: { seq, packetId: pid, connection: originInfo.connection },
    termination,
    deliveredOnce,
    uniqueDelivery: closed
      ? { packetId: pid, originSeq: seq, pubcompSeq: closed.seq }
      : null,
    unclosed: termination.kind === 'CAPTURE_END' && !!termination.code,
    steps,
    connectionSpans,
    crossConnection,
    recovery,
    excludedSameIdPackets,
    verdict: {
      verdict: verdict.verdict,
      reason: verdict.reason,
      reasonText: verdict.reasonText,
      reasonSeq: verdict.reasonSeq
    },
    packetCount: total
  };
}
