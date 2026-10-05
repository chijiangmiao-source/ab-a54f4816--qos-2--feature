// 证据库测试：固化 / 同输入回放 / 改输入冲突拒绝且保留原证据 / 重启恢复 / 防篡改
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EvidenceStore } from '../server/store.js';

let passed = 0;
let failed = 0;
const failures = [];
const check = (name, cond, detail = '') => {
  if (cond) passed++;
  else { failed++; failures.push(`${name}${detail ? ` —— ${detail}` : ''}`); }
};

const baseInput = () => ({
  auditId: 'SAT-001',
  clientId: 'relay-7',
  packets: [
    { type: 'CONNECT', direction: 'C2S', cleanStart: true },
    { type: 'CONNACK', direction: 'S2C', sessionPresent: false },
    { type: 'PUBLISH', direction: 'C2S', qos: 2, packetId: 1, topic: 'sat/t', payload: 'A', dup: false },
    { type: 'PUBREC', direction: 'S2C', packetId: 1 },
    { type: 'PUBREL', direction: 'C2S', packetId: 1 },
    { type: 'PUBCOMP', direction: 'S2C', packetId: 1 },
    { type: 'DISCONNECT', direction: 'C2S' }
  ]
});

const dir = await mkdtemp(join(tmpdir(), 'evidence-'));
const file = join(dir, 'evidence.jsonl');

try {
  // 1. 首次固化
  const s1 = new EvidenceStore(file);
  const r1 = await s1.submit(baseInput());
  check('首次提交返回 SEALED', r1.status === 'SEALED', r1.status);
  check('裁决通过', r1.record.evidence.verdict.verdict === 'ACCEPTED');
  const caseId = r1.record.caseId;
  const sealedAt = r1.record.sealedAt;

  // 2. 完全相同输入（含字段顺序/等价布尔差异）=> 回放
  const again = baseInput();
  again.packets[2] = { ...again.packets[2], dup: 'false' }; // 规范化后等价
  const reordered = { packets: again.packets, clientId: again.clientId, auditId: again.auditId };
  const r2 = await s1.submit(reordered);
  check('相同输入回放返回 REPLAYED', r2.status === 'REPLAYED', r2.status);
  check('回放返回同一裁决编号', r2.record.caseId === caseId);
  check('回放返回同一固化时间', r2.record.sealedAt === sealedAt);
  check('回放证据逐包一致',
    JSON.stringify(r2.record.evidence.verdict.packets) === JSON.stringify(r1.record.evidence.verdict.packets));

  // 3. reopen 同输入
  const r2b = await s1.reopen(baseInput());
  check('reopen 相同输入回放', r2b.status === 'REPLAYED');

  // 4. 改动输入复用同标识 => 冲突拒绝
  const changed = baseInput();
  changed.packets[3] = { type: 'PUBLISH', direction: 'C2S', qos: 2, packetId: 1, topic: 'sat/t', payload: 'BB', dup: true };
  changed.packets.splice(4, 0, { type: 'PUBREC', direction: 'S2C', packetId: 1 });
  const r3 = await s1.submit(changed);
  check('改动输入返回 CONFLICT_REJECTED', r3.status === 'CONFLICT_REJECTED', r3.status);
  check('冲突码为 EVIDENCE_CONFLICT', r3.code === 'EVIDENCE_CONFLICT');
  check('冲突保留原 verdict', r3.original.verdict === 'ACCEPTED');
  check('冲突保留原 caseId', r3.original.caseId === caseId);

  // 5. 原证据仍可回放且未被覆盖
  const r4 = await s1.get('SAT-001');
  check('冲突后原证据仍为原裁决编号', r4.caseId === caseId);
  check('冲突后原载荷仍为 A',
    r4.evidence.normalizedInput.packets[2].payload === 'A');

  // 6. 冲突输入未写库（文件仍只有一行）
  const lines = (await readFile(file, 'utf8')).trim().split('\n');
  check('冲突提交不追加记录(仍 1 行)', lines.length === 1, `实际 ${lines.length} 行`);

  // 7. reopen 未知标识 => 报错
  let nf = false;
  try { await s1.reopen({ ...baseInput(), auditId: 'NOPE' }); }
  catch (e) { nf = e.code === 'AUDIT_ID_NOT_FOUND'; }
  check('reopen 未知标识报 AUDIT_ID_NOT_FOUND', nf);

  // 8. 不同标识独立固化
  const other = baseInput();
  other.auditId = 'SAT-002';
  other.packets = other.packets.slice(0, 3); // 未闭合
  const r5 = await s1.submit(other);
  check('不同标识独立 SEALED', r5.status === 'SEALED' && r5.record.evidence.verdict.verdict === 'REJECTED');
  check('列表含 2 条', (await s1.list()).length === 2);

  // 9. 重启：新 store 实例重新加载并回放
  const s2 = new EvidenceStore(file);
  const r6 = await s2.reopen(baseInput());
  check('重启后相同输入仍回放', r6.status === 'REPLAYED' && r6.record.caseId === caseId);
  const chain = await s2.verifyChain();
  check('重启后哈希链校验通过', chain.ok && chain.records === 2);

  // 10. 篡改检测：翻转一行中载荷字符后必须校验失败
  const raw = await readFile(file, 'utf8');
  const tampered = raw.replace('"payload":"A"', '"payload":"Z"');
  const file2 = join(dir, 'tampered.jsonl');
  await writeFile(file2, tampered);
  const s3 = new EvidenceStore(file2);
  let detected = false;
  try { await s3.verifyChain(); } catch (e) { detected = e.code === 'STORE_CORRUPT'; }
  check('篡改证据被哈希链检出', detected);
} finally {
  await rm(dir, { recursive: true, force: true });
}

console.log(`\n证据库测试：${passed} 通过，${failed} 失败`);
if (failures.length) {
  console.error('\n失败项：');
  failures.forEach((f) => console.error(' ✗ ' + f));
  process.exit(1);
}
console.log('全部通过 ✓');
