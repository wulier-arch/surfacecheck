import test from "node:test";
import assert from "node:assert/strict";
import {
  displayWidth,
  wrapText,
  summarize,
  exitCodeFor,
  renderTerminal,
  renderJson,
} from "../src/report.mjs";

test("displayWidth：ASCII 字符算一列", () => {
  assert.equal(displayWidth("abc"), 3);
});

test("displayWidth：中文算两列", () => {
  assert.equal(displayWidth("中文"), 4);
});

test("displayWidth：中英混排累加正确", () => {
  assert.equal(displayWidth("a中b"), 4);
});

test("wrapText：纯 ASCII 按宽度折行", () => {
  assert.deepEqual(wrapText("abcdefghij", 4), ["abcd", "efgh", "ij"]);
});

test("wrapText：中文按两列宽度折行，不会把一行折成两倍长", () => {
  const lines = wrapText("一二三四五", 4);
  assert.deepEqual(lines, ["一二", "三四", "五"]);
});

test("wrapText：保留原有换行", () => {
  assert.deepEqual(wrapText("a\nb", 10), ["a", "b"]);
});

test("summarize：按严重度计数", () => {
  const counts = summarize([
    { severity: "critical" },
    { severity: "critical" },
    { severity: "high" },
    { severity: "review" },
  ]);
  assert.deepEqual(counts, { critical: 2, high: 1, review: 1 });
});

test("summarize：空数组全 0", () => {
  assert.deepEqual(summarize([]), { critical: 0, high: 0, review: 0 });
});

test("exitCodeFor：有严重或高危就失败", () => {
  assert.equal(exitCodeFor([{ severity: "critical" }]), 1);
  assert.equal(exitCodeFor([{ severity: "high" }]), 1);
});

test("exitCodeFor：只有待确认时成功", () => {
  assert.equal(exitCodeFor([{ severity: "review" }]), 0);
  assert.equal(exitCodeFor([]), 0);
});

const sample = [
  {
    ruleId: "aws-access-key",
    name: "AWS Access Key ID",
    severity: "critical",
    file: "config/prod.env",
    line: 3,
    redacted: "AKIA****（20 字符）",
    fix: "在 IAM 里禁用并删除该 access key。",
  },
  {
    ruleId: "referrer-missing",
    name: "没设 Referrer-Policy",
    severity: "review",
    file: "example.com",
    line: 0,
    redacted: "响应里没有 Referrer-Policy",
    fix: "加 strict-origin-when-cross-origin。",
  },
];

test("renderTerminal：按严重度分组，严重的排在前面", () => {
  const output = renderTerminal(sample, { color: false });
  assert.ok(output.indexOf("AWS Access Key ID") < output.indexOf("没设 Referrer-Policy"));
});

test("renderTerminal：带行号的显示 file:line，不带行号的不显示冒号", () => {
  const output = renderTerminal(sample, { color: false });
  assert.ok(output.includes("config/prod.env:3"));
  assert.ok(output.includes("example.com"));
  assert.ok(!output.includes("example.com:0"), "line 为 0 时不该显示 :0");
});

test("renderTerminal：脱敏值出现在报告里，原文不出现", () => {
  const output = renderTerminal(sample, { color: false });
  assert.ok(output.includes("AKIA****"));
});

test("renderTerminal：干净的时候明确说「没扫到不等于不存在」", () => {
  const output = renderTerminal([], { color: false });
  assert.ok(output.includes("没有发现问题"));
  assert.ok(output.includes("不是「不存在」"), "不能给用户虚假的安全感");
});

test("renderTerminal：color=false 时不带 ANSI 转义", () => {
  const output = renderTerminal(sample, { color: false });
  assert.ok(!output.includes("\u001b["), "关掉颜色后不该有转义序列");
});

test("renderTerminal：color=true 时带 ANSI 转义", () => {
  const output = renderTerminal(sample, { color: true });
  assert.ok(output.includes("\u001b["));
});

test("renderTerminal：显示扫了哪些目标", () => {
  const output = renderTerminal([], {
    color: false,
    targets: { repo: "my-app", files: 42, commits: 7, hosts: ["example.com"] },
  });
  assert.ok(output.includes("my-app"));
  assert.ok(output.includes("42"));
  assert.ok(output.includes("example.com"));
});

test("renderJson：能被打回对象，且带 summary", () => {
  const parsed = JSON.parse(renderJson(sample, { repo: "x" }));
  assert.equal(parsed.tool, "surfacecheck");
  assert.equal(parsed.summary.critical, 1);
  assert.equal(parsed.summary.review, 1);
  assert.equal(parsed.findings.length, 2);
  assert.equal(parsed.targets.repo, "x");
});

test("renderJson：输出也是按严重度排好的", () => {
  const parsed = JSON.parse(renderJson(sample));
  assert.equal(parsed.findings[0].severity, "critical");
});
