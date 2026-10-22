import test from "node:test";
import assert from "node:assert/strict";
import { evaluateHeaders, normalizeHeaders, parseCsp } from "../src/check-headers.mjs";

/** 一套配齐的头，作为「健康」基线 */
function hardened(overrides = {}) {
  return {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    ...overrides,
  };
}

const ids = (findings) => findings.map((f) => f.ruleId).sort();

test("配齐的站点没有问题", () => {
  assert.deepEqual(evaluateHeaders(hardened(), { url: "example.com" }), []);
});

test("什么都没配时把该报的都报出来", () => {
  const found = ids(evaluateHeaders({}, { url: "example.com" }));
  assert.deepEqual(found, [
    "clickjacking",
    "csp-missing",
    "hsts-missing",
    "nosniff-missing",
    "permissions-policy-missing",
    "referrer-missing",
  ]);
});

test("没有 CSP 也没有 X-Frame-Options 时报点击劫持", () => {
  const found = ids(evaluateHeaders({}, { url: "example.com" }));
  assert.ok(found.includes("clickjacking"), "clickjacking 必须被报出");
});

test("有 CSP frame-ancestors 时不报点击劫持", () => {
  const found = ids(
    evaluateHeaders(hardened({ "content-security-policy": "default-src 'self'; frame-ancestors 'none'" }))
  );
  assert.ok(!found.includes("clickjacking"));
});

test("只有 X-Frame-Options 也能挡住点击劫持", () => {
  const found = ids(evaluateHeaders({ "x-frame-options": "DENY" }));
  assert.ok(!found.includes("clickjacking"), "有 XFO 就不该报 clickjacking");
});

test("HSTS 缺 max-age 报高危", () => {
  const found = evaluateHeaders(hardened({ "strict-transport-security": "includeSubDomains" }));
  assert.equal(found[0].ruleId, "hsts-no-maxage");
  assert.equal(found[0].severity, "high");
});

test("HSTS 有效期过短报待确认", () => {
  const found = evaluateHeaders(hardened({ "strict-transport-security": "max-age=300; includeSubDomains" }));
  assert.equal(found[0].ruleId, "hsts-short");
  assert.equal(found[0].severity, "review");
});

test("HSTS 没覆盖子域名报待确认", () => {
  const found = evaluateHeaders(hardened({ "strict-transport-security": "max-age=31536000" }));
  assert.equal(found[0].ruleId, "hsts-no-subdomains");
});

test("CSP 里有 * 报高危", () => {
  const found = evaluateHeaders(hardened({ "content-security-policy": "default-src *; frame-ancestors 'none'" }));
  assert.ok(found.some((f) => f.ruleId === "csp-wildcard" && f.severity === "high"));
});

test("CSP 里有 unsafe-inline 报待确认", () => {
  const found = evaluateHeaders(
    hardened({ "content-security-policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'" })
  );
  assert.ok(found.some((f) => f.ruleId === "csp-unsafe-inline"));
});

test("CSP 里有 unsafe-eval 报待确认", () => {
  const found = evaluateHeaders(
    hardened({ "content-security-policy": "script-src 'self' 'unsafe-eval'; frame-ancestors 'none'" })
  );
  assert.ok(found.some((f) => f.ruleId === "csp-unsafe-eval"));
});

test("X-Frame-Options 值无效报待确认", () => {
  const found = evaluateHeaders({
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "ALLOW-FROM https://a.com",
  });
  assert.ok(found.some((f) => f.ruleId === "xfo-invalid"));
});

test("nosniff 值不对报待确认", () => {
  const found = evaluateHeaders(hardened({ "x-content-type-options": "yes" }));
  assert.ok(found.some((f) => f.ruleId === "nosniff-invalid"));
});

test("Referrer-Policy 是 unsafe-url 报高危", () => {
  const found = evaluateHeaders(hardened({ "referrer-policy": "unsafe-url" }));
  assert.equal(found[0].ruleId, "referrer-unsafe");
  assert.equal(found[0].severity, "high");
});

test("响应头里带版本号报待确认", () => {
  const found = evaluateHeaders(hardened({ server: "nginx/1.18.0", "x-powered-by": "PHP/7.4.3" }));
  assert.equal(found.length, 1, "两个泄露头合并成一条，不要刷屏");
  assert.ok(found[0].redacted.includes("nginx/1.18.0"));
  assert.ok(found[0].redacted.includes("PHP/7.4.3"));
});

test("只有 Server 头但没版本号时不报", () => {
  const found = evaluateHeaders(hardened({ server: "cloudflare" }));
  assert.deepEqual(found, []);
});

test("每条问题都带 fix 和可读的定位", () => {
  const found = evaluateHeaders({}, { url: "shop.example.com" });
  for (const finding of found) {
    assert.ok(finding.fix && finding.fix.length > 10, `${finding.ruleId} 缺 fix`);
    assert.equal(finding.file, "shop.example.com");
  }
});

test("normalizeHeaders：能处理 fetch 的 Headers 对象", () => {
  const headers = new Headers({ "X-Test": "1" });
  assert.deepEqual(normalizeHeaders(headers), { "x-test": "1" });
});

test("normalizeHeaders：普通对象的 key 转小写，数组值合并", () => {
  assert.deepEqual(normalizeHeaders({ Server: "nginx", "Set-Cookie": ["a=1", "b=2"] }), {
    server: "nginx",
    "set-cookie": "a=1, b=2",
  });
});

test("normalizeHeaders：空值返回空对象", () => {
  assert.deepEqual(normalizeHeaders(null), {});
});

test("parseCsp：解析出指令和来源", () => {
  const parsed = parseCsp("default-src 'self' https://cdn.example.com; img-src *; frame-ancestors 'none'");
  assert.deepEqual(parsed["default-src"], ["'self'", "https://cdn.example.com"]);
  assert.deepEqual(parsed["img-src"], ["*"]);
  assert.deepEqual(parsed["frame-ancestors"], ["'none'"]);
});

test("parseCsp：忽略空段和多余分号", () => {
  const parsed = parseCsp("  default-src 'self' ;;  ; img-src *  ");
  assert.deepEqual(Object.keys(parsed), ["default-src", "img-src"]);
});
