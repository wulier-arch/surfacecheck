import test from "node:test";
import assert from "node:assert/strict";
import {
  cvss31BaseScore,
  parseCvss31Vector,
  severityFromScore,
  scoreFromOsvSeverity,
} from "../src/cvss.mjs";

test("parseCvss31Vector：解析出各项指标", () => {
  const m = parseCvss31Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  assert.equal(m.AV, "N");
  assert.equal(m.S, "U");
  assert.equal(m.A, "H");
});

test("parseCvss31Vector：v4 向量返回 null", () => {
  assert.equal(parseCvss31Vector("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P"), null);
});

test("parseCvss31Vector：空值不抛错", () => {
  assert.equal(parseCvss31Vector(null), null);
  assert.equal(parseCvss31Vector(""), null);
});

// 下面几条是规范文档和官方计算器里的标准用例
test("cvss31BaseScore：全满向量 = 9.8", () => {
  assert.equal(cvss31BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
});

test("cvss31BaseScore：典型反射型 XSS = 6.1", () => {
  assert.equal(cvss31BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
});

test("cvss31BaseScore：需要交互且影响有限 = 5.0", () => {
  assert.equal(cvss31BaseScore("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"), 5.0);
});

test("cvss31BaseScore：本地低权限 = 5.5", () => {
  assert.equal(cvss31BaseScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5);
});

test("cvss31BaseScore：无影响 = 0", () => {
  assert.equal(cvss31BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
});

test("cvss31BaseScore：Scope 变化会拉高 PR 权重", () => {
  const changed = cvss31BaseScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  const unchanged = cvss31BaseScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  assert.ok(changed > unchanged, `${changed} 应该大于 ${unchanged}`);
});

test("cvss31BaseScore：指标缺失返回 null 而不是猜", () => {
  assert.equal(cvss31BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H"), null);
});

test("cvss31BaseScore：非法取值返回 null", () => {
  assert.equal(cvss31BaseScore("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), null);
});

test("cvss31BaseScore：v3.0 向量同样能算", () => {
  assert.equal(cvss31BaseScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
});

test("severityFromScore：分档边界", () => {
  assert.equal(severityFromScore(9.0), "critical");
  assert.equal(severityFromScore(10), "critical");
  assert.equal(severityFromScore(8.9), "high");
  assert.equal(severityFromScore(7.0), "high");
  assert.equal(severityFromScore(6.9), "review");
  assert.equal(severityFromScore(0), "review");
});

test("severityFromScore：非数字降级为待确认", () => {
  assert.equal(severityFromScore(null), "review");
  assert.equal(severityFromScore(NaN), "review");
});

test("scoreFromOsvSeverity：优先用 v3 向量算分", () => {
  const result = scoreFromOsvSeverity([
    { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P" },
    { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
  ]);
  assert.equal(result.score, 9.8);
});

test("scoreFromOsvSeverity：只有 v4 时不给分数，但保留向量", () => {
  const result = scoreFromOsvSeverity([{ type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:P" }]);
  assert.equal(result.score, null);
  assert.equal(result.vector, "CVSS:4.0/AV:N/AC:L/AT:P");
});

test("scoreFromOsvSeverity：空数组安全返回", () => {
  assert.deepEqual(scoreFromOsvSeverity([]), { score: null, vector: null });
  assert.deepEqual(scoreFromOsvSeverity(undefined), { score: null, vector: null });
});
