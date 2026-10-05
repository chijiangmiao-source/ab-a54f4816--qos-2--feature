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

export function adjudicate(rawInput) {
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
        nf.firstPublishSeq = seq;
        nf.publishSeq = seq;
        nf.topic = p.topic;
        nf.payload = p.payload;
        m.flows.set(pid, nf);
        e.phase = 'INFLIGHT';
        e.firstDelivery = 'FIRST';
        e.note = '首次发布：等待 PUBREC';
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
      e.phase = 'CLOSED';
      e.firstDelivery = 'DELIVERED_ONCE';
      e.note = '精确一次交付完成：该遥测仅此一次交付给应用方';
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
