/**
 * CVSS v3.1 基础评分。
 *
 * 为什么要自己算：漏洞库返回的 `severity` 字段经常缺（非 GHSA 来源就没有），
 * 只给一串向量字符串。让用户自己心算 9.8 还是 5.0 不现实，而「按感觉标个高危」
 * 就是编数据。所以按规范算。
 *
 * 只实现 v3.1。v4.0 的评分规则复杂到需要一整套查表，算错比不算更糟——
 * 遇到只有 v4 向量的条目，直接降级成「待确认」并把向量原样展示给用户。
 *
 * 规范：https://www.first.org/cvss/v3.1/specification-document
 */

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const UI = { N: 0.85, R: 0.62 };
// PR 的取值取决于 Scope，所以单独处理
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };
const CIA = { H: 0.56, L: 0.22, N: 0 };

/** 规范里的 Roundup：向上取到一位小数 */
function roundup(value) {
  const scaled = Math.round(value * 100000);
  if (scaled % 10000 === 0) return scaled / 100000;
  return (Math.floor(scaled / 10000) + 1) / 10;
}

/** "CVSS:3.1/AV:N/AC:L/..." → {AV:'N', ...}；不是 v3.x 就返回 null */
export function parseCvss31Vector(vector) {
  if (typeof vector !== "string") return null;
  const parts = vector.trim().split("/");
  if (!/^CVSS:3\.[01]$/i.test(parts[0] ?? "")) return null;
  const metrics = {};
  for (const part of parts.slice(1)) {
    const [key, value] = part.split(":");
    if (key && value) metrics[key.toUpperCase()] = value.toUpperCase();
  }
  return metrics;
}

/**
 * 算 CVSS v3.1 基础分。向量不完整或取值非法时返回 null——宁可不算，不要算错。
 * @returns {number|null} 0.0 ~ 10.0
 */
export function cvss31BaseScore(vector) {
  const m = parseCvss31Vector(vector);
  if (!m) return null;

  const scopeChanged = m.S === "C";
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[m.PR];

  if (
    AV[m.AV] === undefined ||
    AC[m.AC] === undefined ||
    pr === undefined ||
    UI[m.UI] === undefined ||
    CIA[m.C] === undefined ||
    CIA[m.I] === undefined ||
    CIA[m.A] === undefined ||
    (m.S !== "U" && m.S !== "C")
  ) {
    return null;
  }

  const iss = 1 - (1 - CIA[m.C]) * (1 - CIA[m.I]) * (1 - CIA[m.A]);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;

  if (impact <= 0) return 0;

  const exploitability = 8.22 * AV[m.AV] * AC[m.AC] * pr * UI[m.UI];
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);

  return roundup(raw);
}

/** 分数 → 严重度。分档按规范附录的定性评级 */
export function severityFromScore(score) {
  if (typeof score !== "number" || !Number.isFinite(score)) return "review";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  return "review";
}

/** 从 OSV 条目的 severity 数组里挑能算的那个，返回 {score, vector} */
export function scoreFromOsvSeverity(severityList) {
  if (!Array.isArray(severityList)) return { score: null, vector: null };

  // 优先 v3.1，其次 v3.0（两者基础分算法一致）
  for (const type of ["CVSS_V3", "CVSS_V31"]) {
    const entry = severityList.find((item) => item?.type === type && item?.score);
    if (entry) {
      const score = cvss31BaseScore(entry.score);
      if (score !== null) return { score, vector: entry.score };
    }
  }

  // 只有 v4 的时候保留向量给用户看，但分数留空
  const v4 = severityList.find((item) => item?.type === "CVSS_V4" && item?.score);
  return { score: null, vector: v4?.score ?? null };
}
