import test from "node:test";
import assert from "node:assert/strict";
import { scanText, sortFindings } from "../src/scan-text.mjs";

/** 假密钥用片段拼，不写字面量——否则本仓库自己会被扫出误报 */
function fake(prefix, length, char = "Q") {
  return prefix + char.repeat(length);
}

/** 同上：敏感赋值语句也在运行时拼出来，源码里不留完整形态 */
function build(...parts) {
  return parts.join("");
}

test("能抓到 AWS access key", () => {
  const findings = scanText(`const id = "${fake("AKIA", 16)}";`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "aws-access-key");
  assert.equal(findings[0].severity, "critical");
});

test("能抓到私钥头", () => {
  const findings = scanText(["-----BEGIN", "RSA PRIVATE KEY-----", "MIIE..."].join(" "));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "private-key");
});

test("能抓到带密码的数据库连接串", () => {
  const findings = scanText(build("DATABASE_URL=postgres://admin:", "hunter2", "@db.internal:5432/app"));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "db-url-with-password");
});

test("能抓到 GCP 服务账号 JSON", () => {
  const keyBody = ["-----BEGIN", "PRIVATE KEY-----", "MIIE"].join(" ");
  const text = JSON.stringify({ type: "service_account", project_id: "x", private_key: keyBody });
  const findings = scanText(text);
  assert.ok(findings.some((f) => f.ruleId === "gcp-service-account"), "应命中 GCP 规则");
});

test("能抓到 AWS Secret Access Key（没有前缀，只能靠变量名认）", () => {
  const findings = scanText(build("AWS_SECRET_ACCESS_KEY=", "k9Xm2Qz7Lp4Vb8Nr3Tc6aB1dE4fG7hJ0kL5mN9pQ"));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "aws-secret-key");
  assert.equal(findings[0].severity, "critical");
});

test("AWS secret 变量名后面跟短值时不报", () => {
  assert.equal(scanText(build("AWS_SECRET_ACCESS_KEY=", "short")).length, 0);
});

test("行号算得对", () => {
  const text = ["line one", "line two", `key = "${fake("AKIA", 16)}"`, "line four"].join("\n");
  const findings = scanText(text);
  assert.equal(findings[0].line, 3);
});

test("同一行同一规则只报一次", () => {
  const text = `${fake("AKIA", 16)} and ${fake("ASIA", 16, "R")}`;
  const findings = scanText(text);
  assert.equal(findings.length, 1, "一行两个 AWS key 只报一条，避免刷屏");
});

test("占位值不报", () => {
  const text = `AWS_KEY=${fake("AKIA", 16, "X")}`; // 含 xxxx 占位特征
  assert.equal(scanText(text).length, 0);
});

test("普通英文句子不报", () => {
  const text = "const token = config.authentication.retrieve();\nconst secret = process.env.SECRET;";
  assert.equal(scanText(text).length, 0);
});

test("泛化规则要求熵足够高，低熵长串不报", () => {
  // api_key 赋给一串 a，长度够但熵为 0
  const lowEntropy = build("api_key", ' = "', "a".repeat(24), '"');
  const highEntropy = build("api_key", ' = "', "k9Xm2Qz7Lp4Vb8Nr3Tc6", '"');
  assert.equal(scanText(lowEntropy).length, 0, "低熵值应被熵阈值挡掉");
  assert.equal(scanText(highEntropy).length, 1, "高熵值应命中");
});

test("泛化规则脱敏的是密钥值，不是整行", () => {
  const findings = scanText(build("api_key", ' = "', "k9Xm2Qz7Lp4Vb8Nr3Tc6", '"'));
  assert.ok(!findings[0].redacted.includes("api_key"), "脱敏结果不该带变量名");
  assert.ok(findings[0].redacted.startsWith("k9Xm"), "应保留密钥前 4 位");
});

test("空文本返回空数组", () => {
  assert.deepEqual(scanText(""), []);
  assert.deepEqual(scanText(null), []);
});

test("同一个正则重复调用不会因为 lastIndex 残留而漏报", () => {
  const text = `a=${fake("AKIA", 16)}`;
  const first = scanText(text);
  const second = scanText(text);
  assert.equal(first.length, 1);
  assert.equal(second.length, 1, "第二次调用必须报出同样结果");
});

test("sortFindings：严重度优先，同级按文件名和行号", () => {
  const input = [
    { severity: "review", file: "b.js", line: 1 },
    { severity: "critical", file: "z.js", line: 9 },
    { severity: "high", file: "a.js", line: 5 },
    { severity: "critical", file: "a.js", line: 2 },
  ];
  const sorted = sortFindings(input);
  assert.deepEqual(
    sorted.map((f) => `${f.severity}:${f.file}:${f.line}`),
    ["critical:a.js:2", "critical:z.js:9", "high:a.js:5", "review:b.js:1"]
  );
});

test("sortFindings 不改原数组", () => {
  const input = [{ severity: "review", file: "a", line: 1 }];
  const copy = [...input];
  sortFindings(input);
  assert.deepEqual(input, copy);
});

test("maxPerRule 能拦住病态文件", () => {
  const text = Array.from({ length: 50 }, () => fake("AKIA", 16)).join("\n");
  const findings = scanText(text, { maxPerRule: 5 });
  assert.equal(findings.length, 5);
});
