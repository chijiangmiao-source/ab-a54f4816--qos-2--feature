# 星载遥测中继 · MQTT 5 QoS 2 重发交付审计系统

审查**星载遥测中继断链重发 QoS 2 报文**后，同一遥测是否**只精确交付一次**，并识别因
丢失确认（PUBREC / PUBCOMP）造成的**未闭合会话**。

零运行时依赖（仅 Node.js 内置模块），提供：

- 联调页面：录入**稳定审计标识**、**客户端标识**与**最多 48 条**按捕获顺序排列、带方向的
  MQTT 5 控制包；逐包查看**会话阶段、包标识、首次交付状态、首个违规依据**；
- 裁决引擎：仅处理 `CONNECT / CONNACK / PUBLISH(QoS 2) / PUBREC / PUBREL / PUBCOMP / DISCONNECT`，
  在同一持久会话中依据 **Clean Start、Session Present、DUP、Packet Identifier**
  校验重连恢复、合法重放与未闭合交换；
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

1. **裁决引擎测试**（117 项，围绕重连闭合规则）；
2. **证据库测试**（固化 / 同输入回放 / 改输入冲突拒绝且保留原证据 / 重启恢复 / 哈希链防篡改）；
3. **页面构建检查**（需求要素齐全、内联脚本语法通过）；
4. **API/HTTP 冒烟**：经真实 HTTP 验证
   - PUBREC 丢失后 DUP=1、载荷一致的合法重发 => `ACCEPTED` 且 `deliveredOnce=1`（仅一次交付）；
   - 闭合后重发 => `DOUBLE_DELIVERY` 拒绝并稳定定位违规包序号；
   - 重发载荷冲突 => `PAYLOAD_CONFLICT`；Clean Start 后继续旧确认 => `STALE_SESSION_USE`；
   - PUBCOMP 丢失后持久会话重连（SP=1）重传 PUBREL => 恢复闭合；
   - 不重连即结束 => `UNCLOSED_EXCHANGE`；
   - 同标识同输入回放 `REPLAYED`，改输入复用标识 `409 CONFLICT_REJECTED` 且原证据不变。

本地（无 Docker）等价命令：`sh scripts/verify.sh`。

## 三、HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康响应（含证据条数与哈希链校验结果） |
| POST | `/api/audits` | 提交裁决并固化（新标识 `201 SEALED`；同标识同输入 `200 REPLAYED`；同标识改输入 `409`） |
| POST | `/api/audits/reopen` | 按审计标识重新打开（同输入回放；未知标识 `404`） |
| GET | `/api/audits` | 已固化证据列表 |
| GET | `/api/audits/:auditId` | 取回单条完整原证据 |
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
`DELIVERED_ONCE` 唯一交付）、`note`、`violation`；整体给出
`verdict / reason / reasonSeq（首个违规包序号） / summary`。

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
server/engine.js   裁决引擎（纯函数：校验/规范化/指纹/状态机）
server/store.js    仅追加哈希链证据库（固化/回放/冲突拒绝）
server/server.js   零依赖 HTTP 服务（健康检查/API/静态页面）
public/index.html  联调页面（录入、逐包证据、按标识重开、场景模板）
test/              引擎与证据库测试（node 直接运行）
scripts/           verify.sh / check-page.js / smoke.js
Dockerfile  docker-compose.yml  .env.example
```
