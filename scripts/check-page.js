// 页面构建检查：本项目页面为零构建静态页，检查内容：
//   1. public/index.html 存在且包含全部需求规定的录入/证据/重开要素；
//   2. 内联 <script> 通过 Node --check 等价语法解析（用 vm.Script 解析，不执行）；
//   3. 场景模板覆盖关键裁决路径。
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const html = await readFile(join(here, '..', 'public', 'index.html'), 'utf8');

let passed = 0;
let failed = 0;
const failures = [];
const check = (name, cond) => {
  if (cond) { passed++; console.log(' ✓ ' + name); }
  else { failed++; failures.push(name); console.error(' ✗ ' + name); }
};

// 必需文案/元素
check('含页面标题', /星载遥测中继/.test(html) && /<title>/.test(html));
check('含稳定审计标识录入', /id="auditId"/.test(html));
check('含客户端标识录入', /id="clientId"/.test(html));
check('含按捕获顺序的包录入表', /id="pktBody"/.test(html));
check('含 48 包上限约束', /MAX\s*=\s*48/.test(html));
check('含 CONNECT/CONNACK/PUBLISH/PUBREC/PUBREL/PUBCOMP/DISCONNECT 类型',
  ['CONNECT', 'CONNACK', 'PUBLISH', 'PUBREC', 'PUBREL', 'PUBCOMP', 'DISCONNECT']
    .every((t) => html.includes(`'${t}'`)));
check('含方向 C2S/S2C', html.includes("'C2S'") && html.includes("'S2C'"));
check('含提交裁决入口', /id="submitBtn"/.test(html));
check('含按审计标识重新打开入口', /id="reopenBtn"/.test(html));
check('含逐包证据区(会话阶段/包标识/首次交付/违规依据)',
  /id="evBody"/.test(html) && /会话阶段/.test(html) && /首次交付/.test(html) && /首个违规依据/.test(html));
check('含已固化证据列表', /id="caseList"/.test(html));
check('展示首个违规包序号', /reasonSeq|首个违规包序号/.test(html));

// 首发链路追溯要素
check('含可追溯首发选择区', /id="originChips"/.test(html));
check('含链路追溯结果区', /id="chainBody"/.test(html) && /id="boundaryBox"/.test(html));
check('逐包首发提供追溯入口', /data-trace=/.test(html) && /可追溯首发/.test(html));
check('链路含连接编号/阶段变化/确认关系/唯一交付列',
  /连接/.test(html) && /阶段变化/.test(html) && /确认关系/.test(html) && /唯一交付/.test(html));
check('调用首发清单接口', html.includes('/trace-origins'));
check('调用链路追溯接口', html.includes('/trace/'));
check('体现跨连接恢复(Clean Start=0/Session Present=1)', /Clean Start=0/.test(html) && /Session Present=1/.test(html));
check('体现标识复用边界提示', /REUSED_BY_NEW_ORIGIN|标识被新的首发重用|标识复用边界/.test(html));

// 场景模板
['normal', 'pubrecLost', 'pubcompLost', 'double', 'cleanstart', 'payload', 'unclosed', 'reuse', 'direrr']
  .forEach((p) => check(`场景模板 ${p}`, html.includes(`data-preset="${p}"`)));

// API 调用存在
check('调用提交 API', html.includes("'/api/audits'"));
check('调用重开 API', html.includes("'/api/audits/reopen'"));

// 内联脚本语法解析
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
check('存在内联脚本', scripts.length >= 1);
scripts.forEach((s, i) => {
  try {
    new vm.Script(s, { filename: `index-inline-${i}.js` });
    check(`内联脚本 #${i} 语法通过`, true);
  } catch (e) {
    check(`内联脚本 #${i} 语法通过 (${e.message})`, false);
  }
});

console.log(`\n页面检查：${passed} 通过，${failed} 失败`);
if (failed) {
  console.error('失败项：' + failures.join('; '));
  process.exit(1);
}
console.log('页面构建检查通过 ✓');
