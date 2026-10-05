#!/bin/sh
# Compose verify 入口：引擎规则测试 → 证据库测试 → 页面构建检查 → API/HTTP 冒烟
# 任一步失败立即以非零退出码结束。
set -eu

echo "=================== [1/4] 裁决引擎测试（重连闭合规则） ==================="
node test/engine.test.js

echo "=================== [2/4] 证据库测试（回放/冲突拒绝/防篡改） ==================="
node test/store.test.js

echo "=================== [3/4] 页面构建检查 ==================="
node scripts/check-page.js

echo "=================== [4/4] API/HTTP 冒烟（合法重发仅一次 / 冲突重发拒绝） ==================="
node scripts/smoke.js

echo ""
echo "VERIFY OK：全部检查通过"
