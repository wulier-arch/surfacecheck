import test from "node:test";
import assert from "node:assert/strict";
import {
  parseSAN,
  sanCoversHost,
  evaluateCertificate,
  evaluatePublicKey,
} from "../src/check-cert.mjs";

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

/* ------------------------------- 剩余寿命比例（64 天证书时代的主判据） */

const DAY_MS = DAY;

/** 造一张指定总寿命、剩余天数的证书 */
function certWithLifetime({ lifetimeDays, daysLeft }) {
  const validTo = new Date(NOW + daysLeft * DAY_MS);
  return {
    subject: { CN: "example.com" },
    issuer: { O: "Let's Encrypt" },
    valid_to: validTo.toISOString(),
    valid_from: new Date(validTo.getTime() - lifetimeDays * DAY_MS).toISOString(),
    subjectaltname: "DNS:example.com",
  };
}

test("90 天证书剩 25 天：剩余寿命不足三分之一", () => {
  const { findings, info } = evaluateCertificate(certWithLifetime({ lifetimeDays: 90, daysLeft: 25 }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.equal(findings[0].ruleId, "cert-expiring-soon");
  assert.equal(info.lifetimeDays, 90);
  assert.ok(Math.abs(info.remainingRatio - 25 / 90) < 0.01);
});

test("64 天证书剩 25 天：比例只剩 39%，仍不告警（还没到三分之一）", () => {
  const { findings } = evaluateCertificate(certWithLifetime({ lifetimeDays: 64, daysLeft: 25 }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.deepEqual(findings, [], "39% 还不到三分之一，不该报");
});

test("64 天证书剩 20 天：比例 31%，触发告警", () => {
  const { findings } = evaluateCertificate(certWithLifetime({ lifetimeDays: 64, daysLeft: 20 }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.equal(findings[0].ruleId, "cert-expiring-soon");
});

test("7 天短周期证书：不会因为绝对阈值 30 天而一直报警", () => {
  const { findings } = evaluateCertificate(certWithLifetime({ lifetimeDays: 7, daysLeft: 6 }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.deepEqual(findings, [], "刚签发一天的短证书不该报，否则用户会把告警关掉");
});

test("7 天短周期证书剩 1 天：按比例触发高危", () => {
  const { findings } = evaluateCertificate(certWithLifetime({ lifetimeDays: 7, daysLeft: 1 }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.equal(findings[0].ruleId, "cert-expiring");
});

test("有效期超过 398 天报待确认", () => {
  const { findings } = evaluateCertificate(certWithLifetime({ lifetimeDays: 730, daysLeft: 700 }), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
  });
  assert.equal(findings[0].ruleId, "cert-lifetime-long");
});

/* ------------------------------------------------------ 公钥强度 */

test("evaluatePublicKey：RSA 1024 位判为弱", () => {
  const result = evaluatePublicKey({ asymmetricKeyType: "rsa", asymmetricKeyDetails: { modulusLength: 1024 } });
  assert.equal(result.weak, true);
  assert.ok(result.reason.includes("1024"));
});

test("evaluatePublicKey：RSA 2048 位正常", () => {
  const result = evaluatePublicKey({ asymmetricKeyType: "rsa", asymmetricKeyDetails: { modulusLength: 2048 } });
  assert.equal(result.weak, false);
  assert.equal(result.bits, 2048);
});

test("evaluatePublicKey：prime256v1 正常", () => {
  const result = evaluatePublicKey({ asymmetricKeyType: "ec", asymmetricKeyDetails: { namedCurve: "prime256v1" } });
  assert.equal(result.weak, false);
});

test("evaluatePublicKey：已知弱曲线判为弱", () => {
  const result = evaluatePublicKey({ asymmetricKeyType: "ec", asymmetricKeyDetails: { namedCurve: "secp192r1" } });
  assert.equal(result.weak, true);
});

test("evaluatePublicKey：拿不到公钥时不猜", () => {
  const result = evaluatePublicKey(null);
  assert.equal(result.weak, false);
  assert.equal(result.type, null);
});

test("弱公钥会变成一条高危", () => {
  const { findings } = evaluateCertificate(cert(), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
    meta: { weakKeyReason: "RSA 1024 位，低于 2048 位" },
  });
  assert.equal(findings[0].ruleId, "cert-key-weak");
  assert.equal(findings[0].severity, "high");
});

test("自签证书报高危", () => {
  const { findings } = evaluateCertificate(cert(), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
    meta: { selfSigned: true },
  });
  assert.equal(findings[0].ruleId, "cert-self-signed");
});

test("info 里带上链深度和公钥信息", () => {
  const { info } = evaluateCertificate(cert(), {
    host: "example.com",
    protocol: "TLSv1.3",
    authorized: true,
    now: NOW,
    meta: { keyType: "ec", keyBits: null, chainDepth: 2 },
  });
  assert.equal(info.keyType, "ec");
  assert.equal(info.chainDepth, 2);
});
