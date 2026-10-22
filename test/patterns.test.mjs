/**
 * 测试里的假密钥一律用片段拼出来，不写字面量。
 *
 * 原因很实际：这个仓库自己会被 `surfacecheck .` 扫一遍。
 * 如果测试文件里躺着 `AKIA...` 这样的字面量，工具就会在自己的仓库里报一堆误报，
 * 而「工具在自己仓库上是干净的」本身就是最有说服力的一个演示。
 */

import test from "node:test";
import assert from "node:assert/strict";
import { shannonEntropy, looksLikePlaceholder, redact, RULES } from "../src/patterns.mjs";

/** 拼一个形如真实密钥、但由重复字符组成的假值 */
function fake(prefix, length, char = "Q") {
  return prefix + char.repeat(length);
}

test("shannonEntropy：单一字符熵为 0", () => {
  assert.equal(shannonEntropy("aaaaaaaa"), 0);
});

test("shannonEntropy：随机串的熵明显高于英文单词", () => {
  const randomish = "a8Fk2mQz9XpL4vBn7RcT";
  const wordish = "authentication";
  assert.ok(
    shannonEntropy(randomish) > shannonEntropy(wordish),
    `随机串熵应更高：${shannonEntropy(randomish)} vs ${shannonEntropy(wordish)}`
  );
});

test("shannonEntropy：空值返回 0", () => {
  assert.equal(shannonEntropy(""), 0);
  assert.equal(shannonEntropy(null), 0);
});

test("looksLikePlaceholder：常见占位词都算占位", () => {
  for (const value of ["your_key_here", "EXAMPLE123", "changeme", "REPLACE_ME", "dummy-token"]) {
    assert.ok(looksLikePlaceholder(value), `${value} 应被识别为占位`);
  }
});

test("looksLikePlaceholder：真随机串不算占位", () => {
  assert.equal(looksLikePlaceholder(fake("AKIA", 16)), false);
});

test("redact：短值全部打码，不泄露长度以外的信息", () => {
  assert.equal(redact("abc"), "***");
});

test("redact：长值只留前 4 位并标出长度", () => {
  const output = redact(fake("AKIA", 16));
  assert.ok(output.startsWith("AKIA"), "前 4 位应保留，方便用户定位是哪把 key");
  assert.ok(output.includes("20 字符"), "应标出原始长度");
  assert.ok(!output.includes("QQQQ"), "中间部分必须被抹掉");
});

test("redact：中间部分最多打 8 个星号，不会因为密钥很长就输出一长串", () => {
  const output = redact("X".repeat(500));
  assert.equal((output.match(/\*/g) ?? []).length, 8);
});

test("每条规则都写了 fix 和 severity", () => {
  for (const rule of RULES) {
    assert.ok(rule.fix && rule.fix.length > 10, `${rule.id} 缺 fix`);
    assert.ok(["critical", "high", "review"].includes(rule.severity), `${rule.id} 的 severity 不合法`);
    assert.ok(rule.re instanceof RegExp, `${rule.id} 的 re 不是正则`);
  }
});

test("规则 id 不重复", () => {
  const ids = RULES.map((rule) => rule.id);
  assert.equal(new Set(ids).size, ids.length);
});
