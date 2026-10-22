/**
 * TLS 证书检查。
 *
 * 只报 Node 能拿到的事实：有效期、链是否可信、SAN 是否覆盖域名、协议版本。
 * **不判断签名算法强度**——Node 的 TLS 接口不暴露这个字段，硬猜就是编数据。
 */

import tls from "node:tls";

const DAY = 24 * 60 * 60 * 1000;

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

/** 把一个已建立的 TLS 连接上的证书转成体检结论（纯函数，方便测试） */
export function evaluateCertificate(cert, { host, protocol, authorized, now = Date.now() }) {
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
  const san = parseSAN(cert.subjectaltname);

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
  } else if (daysLeft <= 14) {
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
      protocol,
      authorized: Boolean(authorized),
    },
    findings,
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

    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, timeout },
      () => {
        const cert = socket.getPeerCertificate(true);
        done(
          evaluateCertificate(cert, {
            host,
            protocol: socket.getProtocol(),
            authorized: socket.authorized,
          })
        );
      }
    );

    socket.on("error", (error) => {
      done({
        info: { host, subject: null, issuer: null, validTo: null, daysLeft: null, protocol: null, authorized: null },
        findings: [
          {
            ruleId: "cert-unreachable",
            name: "连不上",
            severity: "review",
            file: host,
            line: 0,
            redacted: error.code || error.message,
            fix: "确认域名解析、端口和防火墙。",
          },
        ],
      });
    });

    socket.setTimeout(timeout, () => {
      done({
        info: { host, subject: null, issuer: null, validTo: null, daysLeft: null, protocol: null, authorized: null },
        findings: [
          {
            ruleId: "cert-timeout",
            name: "握手超时",
            severity: "review",
            file: host,
            line: 0,
            redacted: `${timeout}ms 内没完成握手`,
            fix: "确认网络可达；某些网络环境会拦截 443。",
          },
        ],
      });
    });
  });
}
