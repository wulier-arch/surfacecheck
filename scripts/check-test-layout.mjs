/**
 * 测试文件结构自检：防止「新增了模块但忘了写测试」这类静默退化。
 *
 *   1. test/ 下的文件必须是 *.test.mjs
 *   2. src/ 下每个模块（入口除外）都要被至少一个测试文件 import
 *   3. 测试文件不能是空壳（至少有一个 test( 调用）
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel) => readFileSync(resolve(root, rel), "utf-8");

const errors = [];

/* 1. 命名 */
const testFiles = readdirSync(resolve(root, "test"));
for (const file of testFiles) {
  if (!file.endsWith(".test.mjs")) {
    errors.push(`test/${file}：测试文件必须以 .test.mjs 结尾`);
  }
}

/* 3. 不能是空壳 */
for (const file of testFiles) {
  const count = (read(`test/${file}`).match(/^test\(/gm) ?? []).length;
  if (count === 0) errors.push(`test/${file}：没有任何 test( 调用`);
}

/* 2. 覆盖 */
const srcFiles = readdirSync(resolve(root, "src")).filter((f) => f.endsWith(".mjs"));
const entrypoints = new Set(["cli.mjs"]);
const allTests = testFiles.map((f) => read(`test/${f}`)).join("\n");

for (const file of srcFiles) {
  if (entrypoints.has(file)) continue;
  if (!allTests.includes(file)) {
    errors.push(`src/${file}：没有被任何测试文件引用，新增模块请补测试`);
  }
}

if (errors.length) {
  for (const error of errors) console.error(`❌ ${error}`);
  console.error(`\n共 ${errors.length} 个问题。`);
  process.exit(1);
}

console.log(
  `✅ 测试文件结构自检通过（${testFiles.length} 个测试文件，覆盖 ${srcFiles.length - entrypoints.size} 个模块）`
);
