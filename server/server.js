// HTTP 服务：健康检查 + 审计 API + 联调页面（仅使用 Node 内置模块）
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { EvidenceStore, StoreError } from './store.js';
import { InputValidationError, REASON_CODES, listTraceOrigins, buildTraceChain, TraceQueryError } from './engine.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_FILE = process.env.EVIDENCE_FILE || join(__dirname, '..', 'data', 'evidence.jsonl');
const PAGE_FILE = join(__dirname, '..', 'public', 'index.html');

const store = new EvidenceStore(DATA_FILE);

const send = (res, status, obj) => {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body)
  });
  res.end(body);
};

const readJson = (req) => new Promise((resolve, reject) => {
  let data = '';
  let size = 0;
  req.on('data', (c) => {
    size += c.length;
    if (size > 2 * 1024 * 1024) {
      reject(new Error('请求体超过 2MB 限制'));
      req.destroy();
      return;
    }
    data += c;
  });
  req.on('end', () => {
    try {
      resolve(data ? JSON.parse(data) : {});
    } catch {
      reject(new Error('请求体不是合法 JSON'));
    }
  });
  req.on('error', reject);
});

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;

  try {
    // ---------- 健康检查 ----------
    if (req.method === 'GET' && (path === '/health' || path === '/healthz')) {
      const chain = await store.verifyChain();
      send(res, 200, { status: 'ok', service: 'mqtt-qos2-relay-audit', records: chain.records, time: new Date().toISOString() });
      return;
    }

    // ---------- API ----------
    if (req.method === 'POST' && path === '/api/audits') {
      const body = await readJson(req);
      const result = await store.submit(body, { mode: 'submit' });
      const status = result.status === 'CONFLICT_REJECTED' ? 409 : 201;
      send(res, status, result);
      return;
    }

    if (req.method === 'POST' && path === '/api/audits/reopen') {
      const body = await readJson(req);
      try {
        const result = await store.reopen(body);
        send(res, result.status === 'REPLAYED' ? 200 : 201, result);
      } catch (err) {
        if (err instanceof StoreError && err.code === 'AUDIT_ID_NOT_FOUND') {
          send(res, 404, { status: 'NOT_FOUND', code: err.code, message: err.message });
          return;
        }
        throw err;
      }
      return;
    }

    if (req.method === 'GET' && path === '/api/audits') {
      send(res, 200, { audits: await store.list() });
      return;
    }

    // ---------- 首发链路追溯（只读派生，绝不改写冻结证据） ----------
    // 可追溯首发选择清单
    const originsMatch = path.match(/^\/api\/audits\/([^/]+)\/trace-origins$/);
    if (req.method === 'GET' && originsMatch) {
      const rec = await store.get(decodeURIComponent(originsMatch[1]));
      if (!rec) {
        send(res, 404, { status: 'NOT_FOUND', code: 'AUDIT_ID_NOT_FOUND', message: '该审计标识无已固化裁决，无法列出发送链路首发' });
        return;
      }
      const verdict = rec.evidence.verdict;
      send(res, 200, {
        status: 'OK',
        auditId: rec.auditId,
        caseId: rec.caseId,
        sealedAt: rec.sealedAt,
        packetCount: verdict.packets.length,
        traceOrigins: listTraceOrigins(verdict)
      });
      return;
    }

    // 从某首发包起的完整有序链路
    const traceMatch = path.match(/^\/api\/audits\/([^/]+)\/trace\/([^/]+)$/);
    if (req.method === 'GET' && traceMatch) {
      const rec = await store.get(decodeURIComponent(traceMatch[1]));
      if (!rec) {
        send(res, 404, { status: 'NOT_FOUND', code: 'AUDIT_ID_NOT_FOUND', message: '该审计标识无已固化裁决，无法追溯交换链路' });
        return;
      }
      try {
        const chain = buildTraceChain(rec.evidence.verdict, decodeURIComponent(traceMatch[2]));
        send(res, 200, {
          status: 'OK',
          auditId: rec.auditId,
          caseId: rec.caseId,
          sealedAt: rec.sealedAt,
          chain
        });
      } catch (err) {
        if (err instanceof TraceQueryError) {
          // 查询错误只反馈，不触碰冻结证据
          send(res, 400, { status: 'INVALID_TRACE_QUERY', code: err.code, message: err.message });
          return;
        }
        throw err;
      }
      return;
    }

    const m = path.match(/^\/api\/audits\/([^/]+)$/);
    if (req.method === 'GET' && m) {
      const rec = await store.get(decodeURIComponent(m[1]));
      if (!rec) {
        send(res, 404, { status: 'NOT_FOUND', message: '该审计标识无已固化裁决' });
        return;
      }
      send(res, 200, { status: 'SEALED', record: rec });
      return;
    }

    if (req.method === 'GET' && path === '/api/reason-codes') {
      send(res, 200, { reasonCodes: REASON_CODES });
      return;
    }

    // ---------- 联调页面 ----------
    if (req.method === 'GET' && (path === '/' || path === '/index.html')) {
      const html = await readFile(PAGE_FILE, 'utf8');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    send(res, 404, { status: 'NOT_FOUND', message: '路径不存在' });
  } catch (err) {
    if (err instanceof InputValidationError) {
      send(res, 400, { status: 'INVALID', code: 'INPUT_INVALID', errors: err.errors });
      return;
    }
    if (err instanceof StoreError) {
      send(res, 500, { status: 'ERROR', code: err.code, message: err.message });
      return;
    }
    console.error(err);
    send(res, 500, { status: 'ERROR', message: err.message || '服务器内部错误' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`MQTT QoS2 遥测中继审计服务已启动: http://${HOST}:${PORT} (证据文件: ${DATA_FILE})`);
});
