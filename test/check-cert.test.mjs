import test from "node:test";
import assert from "node:assert/strict";
import { parseSAN, sanCoversHost, evaluateCertificate } from "../src/check-cert.mjs";

const DAY = 24 * 60 * 60 * 1000;
const NOW = new Date("2026-10-22T00:00:00Z").getTime();

/** 造一张证书对象，只填检查需要的字段 */
function cert({ daysLeft = 90, san = "DNS:example.com" } = {}) {
  return {
    subject: { CN: "example.com" },
    issuer: { O: "Let's Encrypt" },
    valid_to: new Date(NOW + daysLeft * DAY).toISOString(),
    subjectaltname: san,
  };
}

test("parseSAN：只取 DNS 项，转小写", () => {
  assert.deepEqual(parseSAN("DNS:Example.COM, IP Address:1.2.3.4, DNS:*.api.example.com"), [
    "example.com",
    "*.api.example.com",
  ]);
});

test("parseSAN：没有 SAN 时返回空数组", () => {
  assert.deepEqual(parseSAN(undefined), []);
  assert.deepEqual(parseSAN(""), []);
});

test("sanCoversHost：精确匹配", () => {
  assert.equal(sanCoversHost(["example.com"], "example.com"), true);
});

test("sanCoversHost：通配符覆盖一级子域", () => {
  assert.equal(sanCoversHost(["*.example.com"], "api.example.com"), true);
});

test("sanCoversHost：通配符不覆盖多级子域", () => {
  assert.equal(sanCoversHost(["*.example.com"], "a.b.example.com"), false);
});

test("sanCoversHost：通配符不覆盖裸域", () => {
  assert.equal(sanCoversHost(["*.example.com"], "example.com"), false);
});

test("sanCoversHost：不相关域名返回 false", () => {
  assert.equal(sanCoversHost(["example.com"], "evil.com"), false);
});

test("sanCoversHost：后缀相近的域名不会被误判为覆盖", () => {
  // notexample.com 结尾是 example.com，但不是子域
  assert.equal(sanCoversHost(["*.example.com"], "notexample.com"), false);
});

test("健康证书不产生任何问题", () => {
  const { findings, info } = evaluateCertificate(cert(), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.deepEqual(findings, []);
  assert.equal(info.daysLeft, 90);
  assert.equal(info.protocol, "TLSv1.3");
  assert.equal(info.authorized, true);
});

test("证书已过期报严重", () => {
  const { findings } = evaluateCertificate(cert({ daysLeft: -3 }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "cert-expired");
  assert.equal(findings[0].severity, "critical");
  assert.ok(findings[0].redacted.includes("3 天前"), findings[0].redacted);
});

test("14 天内过期报高危", () => {
  const { findings } = evaluateCertificate(cert({ daysLeft: 10 }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.equal(findings[0].ruleId, "cert-expiring");
  assert.equal(findings[0].severity, "high");
});

test("30 天内过期报待确认", () => {
  const { findings } = evaluateCertificate(cert({ daysLeft: 25 }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.equal(findings[0].ruleId, "cert-expiring-soon");
  assert.equal(findings[0].severity, "review");
});

test("刚好 31 天不报", () => {
  const { findings } = evaluateCertificate(cert({ daysLeft: 31 }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.deepEqual(findings, []);
});

test("证书链不受信报高危", () => {
  const { findings } = evaluateCertificate(cert(), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: false,
    now: NOW,
  });
  assert.equal(findings[0].ruleId, "cert-chain");
  assert.equal(findings[0].severity, "high");
});

test("证书不覆盖该域名报严重", () => {
  const { findings } = evaluateCertificate(cert({ san: "DNS:other.com" }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.equal(findings[0].ruleId, "cert-san");
  assert.equal(findings[0].severity, "critical");
});

test("TLS 1.0 / 1.1 报高危，1.2 和 1.3 不报", () => {
  for (const protocol of ["TLSv1", "TLSv1.1"]) {
    const { findings } = evaluateCertificate(cert(), {
      host: "example.com",
      protocol,
      authorized: true,
      now: NOW,
    });
    assert.equal(findings[0]?.ruleId, "cert-protocol", `${protocol} 应被报出`);
  }
  for (const protocol of ["TLSv1.2", "TLSv1.3"]) {
    const { findings } = evaluateCertificate(cert(), {
      host: "example.com",
      protocol,
      authorized: true,
      now: NOW,
    });
    assert.deepEqual(findings, [], `${protocol} 不该被报出`);
  }
});

test("多个问题能同时报出，不会只报第一个", () => {
  const { findings } = evaluateCertificate(cert({ daysLeft: 5, san: "DNS:other.com" }), {
    host: "example.com",
    protocol: "TLSv1.1",
    authorized: false,
    now: NOW,
  });
  const ids = findings.map((f) => f.ruleId).sort();
  assert.deepEqual(ids, ["cert-chain", "cert-expiring", "cert-protocol", "cert-san"]);
});

test("拿不到证书时报一条，不抛错", () => {
  const { findings, info } = evaluateCertificate(null, {
    host: "example.com",
    protocol: null,
    authorized: false,
    now: NOW,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "cert-missing");
  assert.equal(info.daysLeft, null);
});
