#!/bin/sh
# Compose verify 入口：引擎规则测试 → 证据库测试 → 页面构建检查 → API/HTTP 冒烟
# 任一步失败立即以非零退出码结束。
set -eu

echo "=================== [1/5] 裁决引擎测试（重连闭合规则） ==================="
node test/engine.test.js

echo "=================== [2/5] 首发链路追溯测试（首发入口/跨连接/标识复用/错误查询） ==================="
node test/trace.test.js

echo "=================== [3/5] 证据库测试（回放/冲突拒绝/防篡改） ==================="
node test/store.test.js

echo "=================== [4/5] 页面构建检查 ==================="
node scripts/check-page.js

echo "=================== [5/5] API/HTTP 冒烟（闭合/跨重连恢复/标识复用边界/错误查询） ==================="
node scripts/smoke.js

echo ""
echo "VERIFY OK：全部检查通过"
