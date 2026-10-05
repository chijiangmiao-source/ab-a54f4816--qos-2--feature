// 审计证据库：仅追加（append-only）、防篡改、可回放
//
// 规则：
//   - 审计标识为稳定主键；首次提交即固化 输入指纹 + 裁决证据；
//   - 相同审计标识 + 完全相同输入 => 回放原裁决（含逐包证据、时间戳、裁决编号）；
//   - 相同审计标识 + 改动后的输入 => 拒绝（EVIDENCE_CONFLICT），原证据原样保留；
//   - 不同标识互不影响；
//   - 存储为 JSONL（每行一条不可变记录），重启后完整恢复；
//   - 每条记录携带 prevHash 链与 sha256 完整性哈希，任何篡改都会在校验时暴露。

import { createHash } from 'node:crypto';
import { mkdir, readFile, appendFile, access } from 'node:fs/promises';
import { dirname } from 'node:path';
import { inputFingerprint, normalizeInput, adjudicate } from './engine.js';

export class StoreError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'StoreError';
    this.code = code;
    Object.assign(this, extra);
  }
}

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

export class EvidenceStore {
  constructor(file) {
    this.file = file;
    this.map = new Map(); // auditId -> record
    this.order = [];
    this.lastHash = '0'.repeat(64);
    this.loaded = false;
  }

  async load() {
    if (this.loaded) return;
    try {
      await access(this.file);
    } catch {
      await mkdir(dirname(this.file), { recursive: true });
      this.loaded = true;
      return;
    }
    const raw = await readFile(this.file, 'utf8');
    let prev = '0'.repeat(64);
    raw.split('\n').filter(Boolean).forEach((line, idx) => {
      let rec;
      try {
        rec = JSON.parse(line);
      } catch {
        throw new StoreError('STORE_CORRUPT', `证据库第 ${idx + 1} 行无法解析`);
      }
      const { hash, prevHash, ...body } = rec;
      const expect = sha256(prevHash + JSON.stringify(body));
      if (hash !== expect || prevHash !== prev) {
        throw new StoreError('STORE_CORRUPT',
          `证据库第 ${idx + 1} 行（审计标识 ${body.auditId}）哈希链校验失败：证据可能被篡改`);
      }
      if (this.map.has(rec.auditId)) {
        throw new StoreError('STORE_CORRUPT', `证据库中审计标识 ${rec.auditId} 重复出现`);
      }
      this.map.set(rec.auditId, rec);
      this.order.push(rec.auditId);
      prev = hash;
    });
    this.lastHash = prev;
    this.loaded = true;
  }

  async #append(rec) {
    await mkdir(dirname(this.file), { recursive: true });
    await appendFile(this.file, JSON.stringify(rec) + '\n', 'utf8');
  }

  // 提交裁决。mode:
  //   submit —— 新标识，正常固化
  //   reopen —— 必须命中既有标识；指纹相同回放，不同则冲突拒绝
  async submit(rawInput, { mode = 'submit' } = {}) {
    await this.load();
    const auditId = String(rawInput.auditId).trim();
    const fingerprint = inputFingerprint(rawInput);
    const existing = this.map.get(auditId);

    if (existing) {
      if (existing.evidence.fingerprint === fingerprint) {
        return {
          status: 'REPLAYED',
          record: existing,
          message: '相同审计标识与完全相同输入：回放原裁决，证据未改动'
        };
      }
      // 同标识不同输入 —— 拒绝且绝不覆盖
      const conflict = {
        status: 'CONFLICT_REJECTED',
        code: 'EVIDENCE_CONFLICT',
        message: '审计标识已被不同输入固化：改动输入复用同一标识被拒绝，原证据保留',
        auditId,
        original: {
          verdict: existing.evidence.verdict.verdict,
          reason: existing.evidence.verdict.reason,
          reasonSeq: existing.evidence.verdict.reasonSeq,
          caseId: existing.caseId,
          sealedAt: existing.sealedAt,
          packetCount: existing.evidence.verdict.packets.length,
          fingerprint: existing.evidence.fingerprint
        },
        attemptedFingerprint: fingerprint
      };
      return conflict;
    }

    if (mode === 'reopen') {
      throw new StoreError('AUDIT_ID_NOT_FOUND', `审计标识 ${auditId} 无已固化裁决，无法重新打开`);
    }

    // 先裁决再固化（裁决本身的录入错误不写库）
    const verdict = adjudicate(rawInput);
    const normalizedInput = normalizeInput(rawInput);
    const now = new Date();
    const body = {
      auditId,
      clientId: String(rawInput.clientId).trim(),
      caseId: `CASE-${now.getUTCFullYear()}${String(now.getUTCMonth() + 1).padStart(2, '0')}${String(now.getUTCDate()).padStart(2, '0')}-${String(this.order.length + 1).padStart(4, '0')}`,
      sealedAt: now.toISOString(),
      evidence: {
        fingerprint,
        normalizedInput,
        verdict
      }
    };
    const hash = sha256(this.lastHash + JSON.stringify(body));
    const rec = { ...body, prevHash: this.lastHash, hash };    await this.#append(rec);
    this.map.set(auditId, rec);
    this.order.push(auditId);
    this.lastHash = hash;
    return { status: 'SEALED', record: rec, message: '裁决已固化为不可变审计证据' };
  }

  async reopen(rawInput) {
    return this.submit(rawInput, { mode: 'reopen' });
  }

  async get(auditId) {
    await this.load();
    return this.map.get(String(auditId).trim()) ?? null;
  }

  async list() {
    await this.load();
    return this.order.map((id) => {
      const r = this.map.get(id);
      return {
        auditId: id,
        clientId: r.clientId,
        caseId: r.caseId,
        sealedAt: r.sealedAt,
        verdict: r.evidence.verdict.verdict,
        reason: r.evidence.verdict.reason,
        reasonSeq: r.evidence.verdict.reasonSeq,
        packetCount: r.evidence.verdict.packets.length
      };
    });
  }

  async verifyChain() {
    await this.load();
    let prev = '0'.repeat(64);
    for (const id of this.order) {
      const { hash, prevHash, ...body } = this.map.get(id);
      if (prevHash !== prev || hash !== sha256(prevHash + JSON.stringify(body))) {
        throw new StoreError('STORE_CORRUPT', `审计标识 ${id} 哈希链断裂`);
      }
      prev = hash;
    }
    return { records: this.order.length, ok: true };
  }
}
