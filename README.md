# 星载遥测中继 · MQTT 5 QoS 2 重发交付审计系统

审查**星载遥测中继断链重发 QoS 2 报文**后，同一遥测是否**只精确交付一次**，并识别因
丢失确认（PUBREC / PUBCOMP）造成的**未闭合会话**。

零运行时依赖（仅 Node.js 内置模块），提供：

- 联调页面：录入**稳定审计标识**、**客户端标识**与**最多 48 条**按捕获顺序排列、带方向的
  MQTT 5 控制包；逐包查看**会话阶段、包标识、首次交付状态、首个违规依据**；在逐包结果中选择
  **可追溯首发**，经真实只读接口查看该首发**从 PUBLISH 起到闭合 / 拒绝 / 捕获结束的完整有序链路**；
- 裁决引擎：仅处理 `CONNECT / CONNACK / PUBLISH(QoS 2) / PUBREC / PUBREL / PUBCOMP / DISCONNECT`，
  在同一持久会话中依据 **Clean Start、Session Present、DUP、Packet Identifier**
  校验重连恢复、合法重放与未闭合交换；并为每个带标识包登记**首发归属**，同一包标识的历次首发
  各自独立、互不混淆；
- 不可变证据库：相同审计标识 + 完全相同输入**回放原裁决**；改动输入复用该标识
  **一律拒绝（HTTP 409）并保留原证据**；证据仅追加、带 SHA-256 哈希链，重启可恢复、篡改可检出。

## 一、启动（Docker / Compose）

```bash
cp .env.example .env        # 可选：修改 HOST_PORT（宿主机端口，默认 8080）
docker compose up -d --build
# 打开 http://localhost:8080  （若改过 HOST_PORT 用对应端口）
curl -s http://localhost:8080/health
# {"status":"ok","service":"mqtt-qos2-relay-audit",...}
```

宿主机端口可配置：`.env` 中设置 `HOST_PORT=18080`，或
`HOST_PORT=18080 docker compose up -d`。证据持久化于命名卷 `evidence-data`。

## 二、一键验证（Compose verify，退出码报告结果）

```bash
docker compose --profile verify run --rm verify
echo $?        # 0 = 全部通过；非 0 = 存在失败
```

verify 服务会等待 `app` 健康检查通过，然后顺序执行：

1. **裁决引擎测试**（围绕重连闭合规则）；
2. **首发链路追溯测试**（首发选择入口、跨连接恢复、标识复用边界、非首发/未知审计/越界错误查询、只读不改证据）；
3. **证据库测试**（固化 / 同输入回放 / 改输入冲突拒绝且保留原证据 / 重启恢复 / 哈希链防篡改）；
4. **页面构建检查**（需求要素齐全、内联脚本语法通过）；
5. **API/HTTP 冒烟**：经真实 HTTP 验证
   - PUBREC 丢失后 DUP=1、载荷一致的合法重发 => `ACCEPTED` 且 `deliveredOnce=1`（仅一次交付）；
   - 闭合后重发 => `DOUBLE_DELIVERY` 拒绝并稳定定位违规包序号；
   - 重发载荷冲突 => `PAYLOAD_CONFLICT`；Clean Start 后继续旧确认 => `STALE_SESSION_USE`；
   - PUBCOMP 丢失后持久会话重连（SP=1）重传 PUBREL => 恢复闭合；
   - 不重连即结束 => `UNCLOSED_EXCHANGE`；
   - 同标识同输入回放 `REPLAYED`，改输入复用标识 `409 CONFLICT_REJECTED` 且原证据不变；
   - **首发链路追溯**：正常闭合、跨重连恢复（CS=0/SP=1 桥接 + 跨连接重传沿用首次交付）、
     标识复用边界（Clean Start 终止旧链 / 新首发独立链路互不混淆 / 闭合后重用仅作边界）、
     错误查询（未知审计 404、越界与非首发 400）且只读不改写冻结证据。

本地（无 Docker）等价命令：`sh scripts/verify.sh`。

## 三、HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康响应（含证据条数与哈希链校验结果） |
| POST | `/api/audits` | 提交裁决并固化（新标识 `201 SEALED`；同标识同输入 `200 REPLAYED`；同标识改输入 `409`） |
| POST | `/api/audits/reopen` | 按审计标识重新打开（同输入回放；未知标识 `404`） |
| GET | `/api/audits` | 已固化证据列表 |
| GET | `/api/audits/:auditId` | 取回单条完整原证据 |
| GET | `/api/audits/:auditId/trace-origins` | 列出该冻结证据中全部**可追溯首发**（选择入口；同标识多首发并列） |
| GET | `/api/audits/:auditId/trace/:originSeq` | 从指定首发包起派生**完整有序链路**（只读，不改证据） |
| GET | `/api/reason-codes` | 全部违规码及中文释义 |

请求示例：

```json
{
  "auditId": "SAT-RELAY-20261004-01",
  "clientId": "relay-sat-07",
  "packets": [
    {"type":"CONNECT","direction":"C2S","cleanStart":false},
    {"type":"CONNACK","direction":"S2C","sessionPresent":false},
    {"type":"PUBLISH","direction":"C2S","qos":2,"packetId":1001,"topic":"sat/temp","payload":"{\"t\":1}","dup":false},
    {"type":"PUBLISH","direction":"C2S","qos":2,"packetId":1001,"topic":"sat/temp","payload":"{\"t\":1}","dup":true},
    {"type":"PUBREC","direction":"S2C","packetId":1001},
    {"type":"PUBREL","direction":"C2S","packetId":1001},
    {"type":"PUBCOMP","direction":"S2C","packetId":1001},
    {"type":"DISCONNECT","direction":"C2S"}
  ]
}
```

裁决响应对每个包给出：`seq`、`connection`、`type`、`direction`、`packetId`、`dup`、
`phase`（会话阶段）、`firstDelivery`（`FIRST` 首次发布 / `RESEND` 合法重放 /
`DELIVERED_ONCE` 唯一交付）、`originSeq`（归属首发序号）、`traceableOrigin`（是否可追溯首发）、
`crossConnection`（是否跨连接重传）、`ack`（确认关系）、`note`、`violation`；整体给出
`verdict / reason / reasonSeq（首个违规包序号） / traceOrigins（可追溯首发清单） / summary`。

### 首发交换链路追溯（只读派生）

`GET /api/audits/:auditId/trace/:originSeq` 从选中的首发 PUBLISH 起，返回按原始捕获顺序排列的
完整交换，逐**步**给出：`seq`（原始序号）、`connection`（连接编号）、`phaseChange`（阶段变化）、
`ackRole / acknowledgesSeq / retransmitsSeq`（确认关系与重传指向）、`crossConnection / crossRecovery`
（跨连接及"沿用首次交付"说明）、`deliveredOnce`（是否产生唯一交付），并给出链路
`endReason`：

| endReason | 含义 |
| --- | --- |
| `CLOSED` | 由 PUBCOMP 正常闭合，产生唯一交付 |
| `REJECTED` | 链路上出现违规被拒，未交付 |
| `TERMINATED_CLEAN_START` | 在途交换被 Clean Start=1 清除而终止，未交付 |
| `CAPTURE_END_UNCLOSED` | 捕获结束仍存在丢失的确认，未闭合 |
| `CAPTURE_END` | 捕获结束且未观察到闭合事件 |

跨连接时链路会插入恢复所用的 `CONNECT(Clean Start=0)` / `CONNACK(Session Present=1)` **桥接步**，
重传的 PUBREL / PUBLISH 标记 `crossConnection` 并声明沿用第几条首发的首次交付，重传不产生第二次交付。

**边界不归入**：闭合后对同一标识的重用列为 `REUSE_AFTER_CLOSE`；Clean Start 清除后的旧确认 / 旧重发
列为 `STALE_AFTER_CLEAN_START`；标识被另一条首发重用标记 `REUSED_BY_NEW_ORIGIN` 并指向新首发序号——
这些仅作前一链路的终止依据，绝不出现在链路成员中。同一包标识出现多次首发时，选择不同首发得到
互不相交、互不混淆的两条链路。

错误查询不改写冻结证据：未知审计 `404 AUDIT_ID_NOT_FOUND`；越界 / 负数序号
`400 ORIGIN_SEQ_OUT_OF_RANGE`；非整数 `400 ORIGIN_SEQ_INVALID`；选择了非首发包（PUBREC/PUBREL/
PUBCOMP/CONNECT 或 DUP 重发包）`400 NOT_TRACEABLE_ORIGIN`，均附带中文说明。

## 四、裁决规则要点（违规码）

| 违规码 | 含义 |
| --- | --- |
| `PHASE_SKIP` | 阶段跳跃（建连前发包、PUBREL 先于 PUBREC、PUBCOMP 先于 PUBREL、已收 PUBREC 后重发整个报文等） |
| `WRONG_DIRECTION` | 方向错误（如 PUBLISH/PUBREL 为 S2C，CONNACK/PUBREC/PUBCOMP 为 C2S） |
| `SESSION_PRESENT_CONFLICT` | Clean Start=1 却收到 SP=1、首次连接即 SP=1 等矛盾 |
| `SESSION_EXPIRED` | 持久会话重连（CS=0）却收到 SP=0，旧交换无状态可依 |
| `DUP_WITHOUT_ORIGINAL` | DUP=1 找不到同标识首发 |
| `RESEND_WITHOUT_DUP` | 重复 PUBLISH 未置 DUP=1 |
| `PAYLOAD_CONFLICT` | 重发的主题/载荷与首发不一致 |
| `DOUBLE_DELIVERY` | 同一遥测二次交付（闭合后重发、新会话重用已交付标识等） |
| `STALE_SESSION_USE` | Clean Start=1 清除会话后继续旧包标识的重发/确认 |
| `UNKNOWN_PACKET_ID` | 确认报文引用当前会话从未发布的标识 |
| `DUPLICATE_ACK` / `REPEATED_PUBCOMP` | 无对应重发的重复确认 / 重复 PUBCOMP |
| `PACKET_AFTER_DISCONNECT` | DISCONNECT 后未重新 CONNECT 即继续 |
| `UNCLOSED_EXCHANGE` | 捕获结束仍停在 INFLIGHT / REC_RCVD / REL_SENT（丢失确认，未闭合会话） |

合法路径：完整四次握手；PUBREC 丢失区间内 `DUP=1` 且载荷一致的重发（Broker 按包标识去重，
不产生第二次应用交付）；PUBCOMP 丢失后**同一持久会话**（Clean Start=0、重连 CONNACK SP=1）
重传 PUBREL 并以新的 PUBCOMP 闭合——这两种情况下 `deliveredOnce` 恒为 1。

## 五、目录结构

```
server/engine.js   裁决引擎（纯函数：校验/规范化/指纹/状态机/首发归属/链路派生）
server/store.js    仅追加哈希链证据库（固化/回放/冲突拒绝）
server/server.js   零依赖 HTTP 服务（健康检查/API/链路追溯/静态页面）
public/index.html  联调页面（录入、逐包证据、首发链路追溯、按标识重开、场景模板）
test/              引擎 / 链路追溯 / 证据库测试（node 直接运行）
scripts/           verify.sh / check-page.js / smoke.js
Dockerfile  docker-compose.yml  .env.example
```
