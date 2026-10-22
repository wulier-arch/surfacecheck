/**
 * 报告渲染。终端和浏览器共用同一份数据，但排版不同。
 *
 * 排序原则：**能直接登进系统的排最前面**，合规类的排最后。
 * 一份把所有问题平铺的报告没人看，用户只会关掉它。
 */

import { SEVERITY_ORDER } from "./scan-text.mjs";

const SEVERITY_LABEL = {
  critical: "严重",
  high: "高",
  review: "待确认",
};

const SEVERITY_COLOR = {
  critical: "\u001b[41;97m",
  high: "\u001b[33m",
  review: "\u001b[90m",
};

const RESET = "\u001b[0m";
const DIM = "\u001b[90m";
const BOLD = "\u001b[1m";

/** 中日韩字符占两列 */
export function displayWidth(text) {
  let width = 0;
  for (const ch of String(text)) {
    const code = ch.codePointAt(0);
    if (
      (code >= 0x1100 && code <= 0x115f) ||
      (code >= 0x2e80 && code <= 0xa4cf) ||
      (code >= 0xac00 && code <= 0xd7a3) ||
      (code >= 0xf900 && code <= 0xfaff) ||
      (code >= 0xfe30 && code <= 0xfe6f) ||
      (code >= 0xff00 && code <= 0xff60) ||
      (code >= 0xffe0 && code <= 0xffe6) ||
      (code >= 0x1f300 && code <= 0x1faff)
    ) {
      width += 2;
    } else {
      width += 1;
    }
  }
  return width;
}

function padEnd(text, width) {
  const gap = width - displayWidth(text);
  return gap > 0 ? text + " ".repeat(gap) : text;
}

/** 按显示宽度折行，保留已有的换行 */
export function wrapText(text, width) {
  const lines = [];
  for (const paragraph of String(text).split("\n")) {
    let current = "";
    let currentWidth = 0;
    for (const ch of paragraph) {
      const w = displayWidth(ch);
      if (currentWidth + w > width && current) {
        lines.push(current);
        current = ch;
        currentWidth = w;
      } else {
        current += ch;
        currentWidth += w;
      }
    }
    lines.push(current);
  }
  return lines;
}

/** 统计各严重度数量 */
export function summarize(findings) {
  const counts = { critical: 0, high: 0, review: 0 };
  for (const finding of findings) {
    if (counts[finding.severity] !== undefined) counts[finding.severity]++;
  }
  return counts;
}

/** 有严重或高危就该让 CI 失败 */
export function exitCodeFor(findings) {
  return findings.some((f) => f.severity === "critical" || f.severity === "high") ? 1 : 0;
}

function sortForReport(findings) {
  return [...findings].sort((a, b) => {
    const bySeverity = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    if (bySeverity !== 0) return bySeverity;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.line - b.line;
  });
}

/**
 * 终端报告。
 * @param {Array} findings
 * @param {{color?: boolean, width?: number, targets?: object}} options
 */
export function renderTerminal(findings, { color = true, width = 88, targets = {} } = {}) {
  const paint = (code, text) => (color ? `${code}${text}${RESET}` : text);
  const sorted = sortForReport(findings);
  const counts = summarize(sorted);
  const out = [];

  out.push("");
  out.push(paint(BOLD, "  surfacecheck — 攻击面体检"));
  out.push("");

  // 扫了什么东西，先说清楚，否则用户不知道这份报告覆盖了什么
  if (targets.repo) out.push(`  ${paint(DIM, "仓库")}  ${targets.repo}`);
  if (targets.files !== undefined) out.push(`  ${paint(DIM, "文件")}  ${targets.files} 个`);
  if (targets.commits === null) {
    out.push(`  ${paint(DIM, "历史")}  不是 git 仓库，跳过`);
  } else if (targets.commits !== undefined) {
    out.push(`  ${paint(DIM, "历史")}  ${targets.commits} 个 commit`);
  }
  if (targets.hosts?.length) out.push(`  ${paint(DIM, "站点")}  ${targets.hosts.join(", ")}`);
  for (const manifest of targets.manifests ?? []) {
    const lock = manifest.lock ? "" : "（没有锁文件，只查了写死版本的依赖）";
    out.push(`  ${paint(DIM, "依赖")}  ${manifest.file}  ${manifest.ecosystem} ${manifest.packages} 个包${lock}`);
  }
  if (targets.manifests && targets.manifests.length === 0) {
    out.push(`  ${paint(DIM, "依赖")}  没找到锁文件，跳过`);
  }
  if (targets.depsUnavailable) {
    out.push(`  ${paint(DIM, "依赖")}  ${paint("\u001b[33m", "没查成")}（${targets.depsUnavailable}）`);
  }
  if (targets.depsTruncated) {
    out.push(`  ${paint(DIM, "依赖")}  漏洞条目太多，只取了一部分详情`);
  }
  for (const cert of targets.certs ?? []) {
    if (!cert.validTo) continue;
    const left = cert.daysLeft === null ? "" : `，剩 ${cert.daysLeft} 天`;
    const key = cert.keyType ? `，${cert.keyType.toUpperCase()}${cert.keyBits ? " " + cert.keyBits : ""}` : "";
    out.push(`  ${paint(DIM, "证书")}  ${cert.host}  到期 ${cert.validTo}${left}${key}${cert.issuer ? `（${cert.issuer}）` : ""}`);
  }
  out.push("");

  if (!sorted.length) {
    out.push(paint("\u001b[32m", "  ✓ 没有发现问题。"));
    if (targets.depsUnavailable) {
      out.push(paint("\u001b[33m", "    但依赖漏洞这一项没查成——上面的「没有」不包括它。"));
    }
    out.push(paint(DIM, "    注意：这是「没扫到」，不是「不存在」。"));
    out.push("");
    return out.join("\n");
  }

  const summaryParts = [];
  if (counts.critical) summaryParts.push(paint(SEVERITY_COLOR.critical, ` ${counts.critical} 严重 `));
  if (counts.high) summaryParts.push(paint(SEVERITY_COLOR.high, ` ${counts.high} 高 `));
  if (counts.review) summaryParts.push(paint(SEVERITY_COLOR.review, ` ${counts.review} 待确认 `));
  out.push(`  ${summaryParts.join("  ")}`);
  out.push("");

  let lastSeverity = null;
  const indent = 4;

  for (const finding of sorted) {
    if (finding.severity !== lastSeverity) {
      if (lastSeverity !== null) out.push("");
      const title =
        finding.severity === "critical"
          ? "必须马上处理"
          : finding.severity === "high"
            ? "尽快处理"
            : "需要人看一眼";
      out.push(`  ${paint(DIM, "── " + title + " " + "─".repeat(Math.max(0, width - 8 - displayWidth(title))))}`);
      lastSeverity = finding.severity;
    }

    const tag = paint(SEVERITY_COLOR[finding.severity] ?? DIM, ` ${SEVERITY_LABEL[finding.severity] ?? finding.severity} `);
    const where = finding.line ? `${finding.file}:${finding.line}` : finding.file;
    out.push("");
    out.push(`  ${tag} ${paint(BOLD, finding.name)}`);
    out.push(`  ${" ".repeat(indent)}${paint(DIM, where)}`);
    out.push(`  ${" ".repeat(indent)}${finding.redacted}`);
    if (finding.commit) out.push(`  ${" ".repeat(indent)}${paint(DIM, "出现在 commit " + finding.commit)}`);
    const fixLines = wrapText(finding.fix, width - indent - 2);
    fixLines.forEach((line, index) => {
      out.push(`  ${" ".repeat(indent)}${paint(DIM, (index === 0 ? "→ " : "  ") + line)}`);
    });
  }

  out.push("");
  out.push(paint(DIM, "  " + "─".repeat(width - 4)));
  out.push(`  ${paint(DIM, "下一步：先处理「严重」，再处理「高」。「待确认」自己判断。")}`);
  out.push("");
  return out.join("\n");
}

/** 给 CI / 机器读的输出 */
export function renderJson(findings, targets = {}) {
  return JSON.stringify(
    {
      tool: "surfacecheck",
      version: "0.2.0",
      targets,
      summary: summarize(findings),
      findings: sortForReport(findings),
    },
    null,
    2
  );
}
