/**
 * 文本扫描：给一段文本，找出里面的凭据。
 * 不碰文件系统、不联网，浏览器和 Node 共用。
 */

import { RULES, redact, looksLikePlaceholder, shannonEntropy } from "./patterns.mjs";

/** 把字符下标换算成行号（1 起） */
function lineNumberAt(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

/** 同一行里同一规则只报一次，避免一行多个命中刷屏 */
function dedupe(findings) {
  const seen = new Set();
  const out = [];
  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.file}:${finding.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  return out;
}

/**
 * @param {string} text 要扫描的文本
 * @param {{file?: string, rules?: Array, maxPerRule?: number}} options
 * @returns {Array<{ruleId,name,severity,file,line,redacted,fix}>}
 */
export function scanText(text, options = {}) {
  const { file = "<text>", rules = RULES, maxPerRule = 200 } = options;
  if (typeof text !== "string" || !text) return [];

  const findings = [];

  for (const rule of rules) {
    // 全局正则会带状态，每次重新构造一份，避免 lastIndex 污染
    const re = new RegExp(rule.re.source, rule.re.flags.includes("g") ? rule.re.flags : `${rule.re.flags}g`);
    let match;
    let hits = 0;

    while ((match = re.exec(text)) !== null) {
      if (++hits > maxPerRule) break;

      // 泛化规则取第一个捕获组（真正的密钥值），其余规则取整段命中
      const raw = rule.minEntropy && match[1] ? match[1] : match[0];

      if (looksLikePlaceholder(raw)) continue;
      if (rule.minEntropy && shannonEntropy(raw) < rule.minEntropy) continue;

      findings.push({
        ruleId: rule.id,
        name: rule.name,
        severity: rule.severity,
        file,
        line: lineNumberAt(text, match.index),
        redacted: redact(raw),
        fix: rule.fix,
      });

      // 零宽匹配保护
      if (match.index === re.lastIndex) re.lastIndex++;
    }
  }

  return dedupe(findings);
}

/** 严重度排序：critical → high → review，同级按文件行号 */
export const SEVERITY_ORDER = { critical: 0, high: 1, review: 2 };

export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const bySeverity = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    if (bySeverity !== 0) return bySeverity;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.line - b.line;
  });
}
