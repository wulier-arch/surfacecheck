/**
 * TLS 证书检查。
 *
 * 只报能拿到的事实：有效期、链是否可信、SAN 是否覆盖域名、协议版本、公钥强度。
 * **不判断签名算法强度**——Node 的 TLS 接口不暴露这个字段，硬猜就是编数据。
 *
 * 2026 年 10 月这一周把证书问题的三个面全暴露了：
 *   - UiPath 停机（10-13）：出事的是 AI/ML 依赖链上的**次级端点**，不是主站，
 *     而且事发前根本没有到期监控
 *   - eMudhra 的 8 张中间 CA 私钥弱到能被算出来（P-384 私钥的整数是 4、56、66 这种）
 *   - Let's Encrypt 宣布 2027-02-10 起有效期从 90 天缩到 64 天
 *
 * 所以这里不再只数「还剩几天」：
 *   1. 用**剩余寿命比例**做主判据。64 天证书上写死「30 天内告警」等于只剩一半寿命才提醒；
 *      而 7 天的证书会让绝对阈值永远在响，用户第一件事就是把告警关掉。
 *   2. 检查公钥强度。弱密钥不是理论问题，是已经发生过的事故。
 *   3. 给出链深度和是否自签，让「次级端点用了自签证书」这类事能被看见。
 */

import tls from "node:tls";
import { X509Certificate } from "node:crypto";

const DAY = 24 * 60 * 60 * 1000;

/** CA/B Forum 对公网证书有效期的上限（398 天） */
const MAX_LIFETIME_DAYS = 398;

/** RSA 密钥低于这个位数，2026 年已经不该出现在公网证书上 */
const MIN_RSA_BITS = 2048;

/** 这些曲线已经不安全 */
const WEAK_CURVES = new Set(["secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "prime192v1"]);

/** "DNS:a.com, DNS:*.b.com" → ["a.com", "*.b.com"] */
export function parseSAN(subjectaltname) {
  if (!subjectaltname) return [];
  return subjectaltname
    .split(/,\s*/)
    .map((part) => part.trim())
    .filter((part) => part.startsWith("DNS:"))
    .map((part) => part.slice(4).toLowerCase());
}

/** 证书上的域名能否覆盖待检查的 host（支持一级通配） */
export function sanCoversHost(san, host) {
  const target = host.toLowerCase();
  return san.some((entry) => {
    if (entry === target) return true;
    if (!entry.startsWith("*.")) return false;
    const suffix = entry.slice(1); // ".example.com"
    if (!target.endsWith(suffix)) return false;
    // 通配只覆盖一级：*.example.com 不覆盖 a.b.example.com
    return target.slice(0, -suffix.length).indexOf(".") === -1;
  });
}

/** 公钥强度：返回 {type, bits, weak, reason} */
export function evaluatePublicKey(publicKey) {
  if (!publicKey) return { type: null, bits: null, weak: false, reason: null };
  const type = publicKey.asymmetricKeyType ?? null;
  const details = publicKey.asymmetricKeyDetails ?? {};

  if (type === "rsa" || type === "rsa-pss") {
    const bits = details.modulusLength ?? null;
    if (bits !== null && bits < MIN_RSA_BITS) {
      return { type, bits, weak: true, reason: `RSA ${bits} 位，低于 ${MIN_RSA_BITS} 位` };
    }
    return { type, bits, weak: false, reason: null };
  }

  if (type === "ec") {
    const curve = details.namedCurve ?? null;
    if (curve && WEAK_CURVES.has(curve)) {
      return { type, bits: null, weak: true, reason: `椭圆曲线 ${curve} 已不安全` };
    }
    return { type, bits: null, curve, weak: false, reason: null };
  }

  return { type, bits: null, weak: false, reason: null };
}

/**
 * 把一个已建立的 TLS 连接上的证书转成体检结论（纯函数，方便测试）。
 *
 * @param {object} cert getPeerCertificate(true) 的返回值
 * @param {{host, protocol, authorized, now?, meta?}} options
 *        meta 可带 {validFrom, validTo, keyType, keyBits, weakKeyReason, chainDepth, selfSigned}
 */
export function evaluateCertificate(cert, { host, protocol, authorized, now = Date.now(), meta = {} }) {
  const findings = [];

  if (!cert || !cert.valid_to) {
    return {
      info: { host, subject: null, issuer: null, validTo: null, daysLeft: null, protocol, authorized },
      findings: [
        {
          ruleId: "cert-missing",
          name: "拿不到证书",
          severity: "high",
          file: host,
          line: 0,
          redacted: "握手成功但没有返回证书",
          fix: "确认该端口是不是真的在提供 TLS 服务。",
        },
      ],
    };
  }

  const validTo = new Date(cert.valid_to);
  const daysLeft = Math.floor((validTo.getTime() - now) / DAY);

  const validFromRaw = meta.validFrom ?? cert.valid_from ?? null;
  const validFrom = validFromRaw ? new Date(validFromRaw) : null;
  const lifetimeDays =
    validFrom && Number.isFinite(validFrom.getTime())
      ? Math.round((validTo.getTime() - validFrom.getTime()) / DAY)
      : null;
  const remainingRatio =
    lifetimeDays && lifetimeDays > 0 ? Math.max(0, daysLeft / lifetimeDays) : null;

  const san = parseSAN(cert.subjectaltname);

  // ---- 过期 ----
  // 判据分两层：
  //   有 valid_from → 按**剩余寿命比例**判。写死天数在 64 天证书上等于「剩一半才提醒」，
  //                  在 7 天证书上则永远在响，用户第一件事就是把告警关掉。
  //   没有 valid_from（旧接口 / 异常证书）→ 退回固定天数，但不能因此漏报。
  if (daysLeft < 0) {
    findings.push({
      ruleId: "cert-expired",
      name: "证书已过期",
      severity: "critical",
      file: host,
      line: 0,
      redacted: `已于 ${validTo.toISOString().slice(0, 10)} 过期（${Math.abs(daysLeft)} 天前）`,
      fix: "立刻续期。过期证书会让所有客户端直接报错，且部分 SDK 会缓存失败结果。",
    });
  } else if (daysLeft <= 3) {
    findings.push({
      ruleId: "cert-expiring",
      name: "证书即将过期",
      severity: "high",
      file: host,
      line: 0,
      redacted: `${daysLeft} 天后过期（${validTo.toISOString().slice(0, 10)}）`,
      fix: "现在就续，不要等到最后一天；确认自动续期的定时任务还在跑。",
    });
  } else if (lifetimeDays === null) {
    // 拿不到签发日期，只能用固定天数兜底
    if (daysLeft <= 14) {
      findings.push({
        ruleId: "cert-expiring",
        name: "证书即将过期",
        severity: "high",
        file: host,
        line: 0,
        redacted: `${daysLeft} 天后过期（${validTo.toISOString().slice(0, 10)}）`,
        fix: "现在就续，不要等到最后一天；确认自动续期的定时任务还在跑。",
      });
    } else if (daysLeft <= 30) {
      findings.push({
        ruleId: "cert-expiring-soon",
        name: "证书 30 天内过期",
        severity: "review",
        file: host,
        line: 0,
        redacted: `${daysLeft} 天后过期（${validTo.toISOString().slice(0, 10)}）`,
        fix: "排进本周的待办，确认自动续期可用。",
      });
    }
  } else if (remainingRatio <= 1 / 6) {
    findings.push({
      ruleId: "cert-expiring",
      name: "证书剩余寿命不足六分之一",
      severity: "high",
      file: host,
      line: 0,
      redacted: `剩 ${daysLeft}/${lifetimeDays} 天（${Math.round(remainingRatio * 100)}%）`,
      fix: "现在就续。按「到期前固定天数」写的定时任务在 64 天证书上会失效——Let's Encrypt 2027-02-10 起有效期缩到 64 天，续期要改成按寿命比例。",
    });
  } else if (remainingRatio <= 1 / 3) {
    findings.push({
      ruleId: "cert-expiring-soon",
      name: "证书剩余寿命不足三分之一",
      severity: "review",
      file: host,
      line: 0,
      redacted: `剩 ${daysLeft}/${lifetimeDays} 天（${Math.round(remainingRatio * 100)}%）`,
      fix: "把续期排在到期前三分之二处，而不是写死「提前 30 天」。",
    });
  }

  // ---- 有效期异常长 ----
  if (lifetimeDays !== null && lifetimeDays > MAX_LIFETIME_DAYS) {
    findings.push({
      ruleId: "cert-lifetime-long",
      name: "证书有效期超过上限",
      severity: "review",
      file: host,
      line: 0,
      redacted: `${lifetimeDays} 天，超过 CA/B Forum 的 ${MAX_LIFETIME_DAYS} 天上限`,
      fix: "多数浏览器会拒绝这类证书。确认是不是自建 CA 签的，以及客户端是否真的信任它。",
    });
  }

  // ---- 链 ----
  if (authorized === false) {
    findings.push({
      ruleId: "cert-chain",
      name: "证书链不完整或不受信",
      severity: "high",
      file: host,
      line: 0,
      redacted: "用系统根证书校验失败",
      fix: "补全中间证书（常见于只配了叶子证书的 Nginx），或确认是否自签。",
    });
  }

  if (meta.selfSigned) {
    findings.push({
      ruleId: "cert-self-signed",
      name: "自签证书",
      severity: "high",
      file: host,
      line: 0,
      redacted: "签发者与主体相同",
      fix: "自签只适合内网。公网端点用自签，等于让所有客户端关掉校验——UiPath 那次停机就是次级端点上的证书没人管。",
    });
  }

  // ---- 公钥强度 ----
  if (meta.weakKeyReason) {
    findings.push({
      ruleId: "cert-key-weak",
      name: "公钥强度不足",
      severity: "high",
      file: host,
      line: 0,
      redacted: meta.weakKeyReason,
      fix: "换一张密钥强度达标的证书。eMudhra 那 8 张中间 CA 就是因为私钥随机性不足，能从公开证书里直接算出私钥。",
    });
  }

  // ---- SAN ----
  if (san.length && !sanCoversHost(san, host)) {
    findings.push({
      ruleId: "cert-san",
      name: "证书不覆盖该域名",
      severity: "critical",
      file: host,
      line: 0,
      redacted: `证书覆盖 ${san.slice(0, 3).join(", ")}${san.length > 3 ? " 等" : ""}`,
      fix: "把该域名加进证书的 SAN，或确认这个域名是不是配错了。",
    });
  }

  // ---- 协议版本 ----
  if (protocol === "TLSv1" || protocol === "TLSv1.1") {
    findings.push({
      ruleId: "cert-protocol",
      name: "使用了已废弃的 TLS 版本",
      severity: "high",
      file: host,
      line: 0,
      redacted: protocol,
      fix: "在服务端禁用 TLS 1.0/1.1，只保留 1.2 以上。",
    });
  }

  return {
    info: {
      host,
      subject: cert.subject?.CN ?? null,
      issuer: cert.issuer?.O ?? cert.issuer?.CN ?? null,
      validTo: validTo.toISOString().slice(0, 10),
      daysLeft,
      lifetimeDays,
      remainingRatio,
      keyType: meta.keyType ?? null,
      keyBits: meta.keyBits ?? null,
      chainDepth: meta.chainDepth ?? null,
      selfSigned: Boolean(meta.selfSigned),
      protocol,
      authorized: Boolean(authorized),
    },
    findings,
  };
}

/** 从 X509Certificate 里抽出评估需要的元信息 */
export function extractMeta(x509, peerChain) {
  const key = evaluatePublicKey(x509.publicKey);
  let chainDepth = 0;
  let selfSigned = x509.subject === x509.issuer;

  // peerChain 是 getPeerCertificate(true) 的链，逐层往上数
  let cursor = peerChain;
  while (cursor?.issuerCertificate && chainDepth < 8) {
    chainDepth += 1;
    if (cursor.issuerCertificate === cursor) break;
    cursor = cursor.issuerCertificate;
    if (cursor.subject === cursor.issuer) {
      selfSigned = false; // 根自签是正常的，不算站点自签
      break;
    }
  }

  return {
    validFrom: x509.validFrom,
    validTo: x509.validTo,
    keyType: key.type,
    keyBits: key.bits,
    weakKeyReason: key.reason,
    chainDepth,
    selfSigned,
  };
}

/** 真正去连一次，拿证书 */
export function checkCert(host, { port = 443, timeout = 8000 } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* 已经关了 */
      }
      resolve(value);
    };

    const fail = (ruleId, name, severity, detail, fix) => ({
      info: { host, subject: null, issuer: null, validTo: null, daysLeft: null, protocol: null, authorized: null },
      findings: [{ ruleId, name, severity, file: host, line: 0, redacted: detail, fix }],
    });

    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, timeout },
      () => {
        const peer = socket.getPeerCertificate(true);
        let meta = {};
        try {
          if (peer?.raw) meta = extractMeta(new X509Certificate(peer.raw), peer);
        } catch {
          // 拿不到 X509 就退回只用 peer 上的字段，不因此判定失败
        }
        done(
          evaluateCertificate(peer, {
            host,
            protocol: socket.getProtocol(),
            authorized: socket.authorized,
            meta,
          })
        );
      }
    );

    socket.on("error", (error) => {
      done(fail("cert-unreachable", "连不上", "review", error.code || error.message, "确认域名解析、端口和防火墙。"));
    });

    socket.setTimeout(timeout, () => {
      done(fail("cert-timeout", "握手超时", "review", `${timeout}ms 内没完成握手`, "确认网络可达；某些网络环境会拦截 443。"));
    });
  });
}
