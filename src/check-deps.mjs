/**
 * 依赖漏洞检查：读锁文件，查 OSV 数据库。
 *
 * 为什么需要这一层：凭据泄露是「你写错了」，依赖漏洞是「你没写错，但上游坏了」。
 * PHP 那组 php2shell（CVE-2026-109618 / 109619）就是典型——业务代码一行没改，
 * 只要跑在受影响版本上就是未认证 RCE。
 *
 * 数据源用 OSV（https://osv.dev）：Google 维护，覆盖 Packagist / npm / PyPI / RubyGems，
 * 免密钥，有批量接口。零依赖直接 fetch，不引任何 SDK。
 *
 * 一条重要取舍：**只查锁文件里的精确版本**。composer.json 写的是 `^8.0`，
 * 那不是一个版本，拿它去查漏洞库只能编结果。没有锁文件就明确告诉用户查不了。
 */

import { readFileSync, existsSync } from "node:fs";
import { join, relative } from "node:path";
import { scoreFromOsvSeverity, severityFromScore } from "./cvss.mjs";

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns/";

/** 详情最多拉这么多条，避免一个巨型锁文件把请求数打爆 */
const MAX_DETAIL_LOOKUPS = 80;
const DETAIL_CONCURRENCY = 8;

/* ------------------------------------------------------------ 清单解析 */

/** composer.lock → packages[] + packages-dev[] */
export function parseComposerLock(text) {
  const data = JSON.parse(text);
  const out = [];
  for (const key of ["packages", "packages-dev"]) {
    for (const pkg of data[key] ?? []) {
      if (!pkg?.name || !pkg?.version) continue;
      out.push({ name: pkg.name, version: String(pkg.version).replace(/^v/, "") });
    }
  }
  return out;
}

/** composer.json → 只取写死版本号的（"1.2.3"），范围约束跳过 */
export function parseComposerJson(text) {
  const data = JSON.parse(text);
  const out = [];
  for (const key of ["require", "require-dev"]) {
    for (const [name, version] of Object.entries(data[key] ?? {})) {
      const exact = exactVersion(version);
      if (exact) out.push({ name, version: exact });
    }
  }
  return out;
}

/** package-lock.json：v1 的 dependencies 是嵌套树，v2/v3 的 packages 是扁平表 */
export function parsePackageLock(text) {
  const data = JSON.parse(text);
  const out = [];

  if (data.packages && typeof data.packages === "object") {
    for (const [path, info] of Object.entries(data.packages)) {
      if (!path || !info?.version) continue; // 空 key 是根项目自己
      const name = info.name ?? path.replace(/^.*node_modules\//, "");
      out.push({ name, version: info.version });
    }
    return dedupePackages(out);
  }

  const walk = (deps) => {
    for (const [name, info] of Object.entries(deps ?? {})) {
      if (info?.version) out.push({ name, version: info.version });
      if (info?.dependencies) walk(info.dependencies);
    }
  };
  walk(data.dependencies);
  return dedupePackages(out);
}

/** package.json → 只取写死版本号的 */
export function parsePackageJson(text) {
  const data = JSON.parse(text);
  const out = [];
  for (const key of ["dependencies", "devDependencies"]) {
    for (const [name, version] of Object.entries(data[key] ?? {})) {
      const exact = exactVersion(version);
      if (exact) out.push({ name, version: exact });
    }
  }
  return out;
}

/** requirements.txt → 只取 `==` 钉死版本的 */
export function parseRequirementsTxt(text) {
  const out = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.split("#")[0].trim();
    if (!line) continue;
    const match = line.match(/^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;]*)/);
    if (match) out.push({ name: match[1], version: match[2] });
  }
  return dedupePackages(out);
}

/** Gemfile.lock → specs 段里的 `name (version)` */
export function parseGemfileLock(text) {
  const out = [];
  let inSpecs = false;
  for (const line of text.split("\n")) {
    if (/^ {2}specs:$/.test(line)) {
      inSpecs = true;
      continue;
    }
    if (inSpecs && /^\S/.test(line) && !/^ {2}specs:/.test(line)) {
      // 回到顶格说明 specs 段结束了
      inSpecs = false;
    }
    if (!inSpecs) continue;
    const match = line.match(/^ {4}([A-Za-z0-9._-]+) \(([0-9][^)]*)\)$/);
    if (match) out.push({ name: match[1], version: match[2] });
  }
  return dedupePackages(out);
}

function exactVersion(value) {
  const text = String(value ?? "").trim();
  if (/^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$/.test(text)) return text;
  return null;
}

function dedupePackages(packages) {
  const seen = new Set();
  const out = [];
  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(pkg);
  }
  return out;
}

/** 一个目录里能认出来的清单文件（锁文件优先，有锁就不再看 manifest） */
const MANIFESTS = [
  { file: "composer.lock", ecosystem: "Packagist", parse: parseComposerLock, lock: true },
  { file: "composer.json", ecosystem: "Packagist", parse: parseComposerJson, lock: false },
  { file: "package-lock.json", ecosystem: "npm", parse: parsePackageLock, lock: true },
  { file: "package.json", ecosystem: "npm", parse: parsePackageJson, lock: false },
  { file: "requirements.txt", ecosystem: "PyPI", parse: parseRequirementsTxt, lock: false },
  { file: "Gemfile.lock", ecosystem: "RubyGems", parse: parseGemfileLock, lock: true },
];

/**
 * 找出目录里的清单文件。
 * 同一生态有锁文件时只用锁文件——manifest 里是范围约束，查了也是猜。
 */
export function collectManifests(root) {
  const found = [];
  const coveredEcosystems = new Set();

  for (const spec of MANIFESTS) {
    const full = join(root, spec.file);
    if (!existsSync(full)) continue;
    if (coveredEcosystems.has(spec.ecosystem)) continue;

    let packages = [];
    let error = null;
    try {
      packages = spec.parse(readFileSync(full, "utf-8"));
    } catch (e) {
      error = e.message;
    }

    found.push({
      file: relative(root, full) || spec.file,
      ecosystem: spec.ecosystem,
      lock: spec.lock,
      packages,
      error,
    });
    if (spec.lock) coveredEcosystems.add(spec.ecosystem);
  }

  return found;
}

/* -------------------------------------------------------------- 查 OSV */

/** 分批把包版本交给 OSV，返回与输入等长的 [{ids:[]}] */
async function queryBatch(packages, { timeout }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(OSV_BATCH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: packages.map((pkg) => ({
          package: { name: pkg.name, ecosystem: pkg.ecosystem },
          version: pkg.version,
        })),
      }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`OSV 返回 ${response.status}`);
    const data = await response.json();
    return (data.results ?? []).map((item) => ({
      ids: (item?.vulns ?? []).map((v) => v.id),
    }));
  } finally {
    clearTimeout(timer);
  }
}

async function fetchVulnDetail(id, { timeout }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(OSV_VULN + encodeURIComponent(id), { signal: controller.signal });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** 限并发地拉详情 */
async function fetchDetails(ids, { timeout }) {
  const details = new Map();
  let cursor = 0;

  const worker = async () => {
    while (cursor < ids.length) {
      const id = ids[cursor++];
      const detail = await fetchVulnDetail(id, { timeout });
      if (detail) details.set(id, detail);
    }
  };

  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, ids.length) }, worker));
  return details;
}

/** 从 OSV 条目里抽出报告要用的字段 */
export function summarizeVuln(detail) {
  const { score, vector } = scoreFromOsvSeverity(detail.severity);

  // GHSA 自带一个定性等级，没有 CVSS 向量时用它兜底
  const dbSeverity = String(detail.database_specific?.severity ?? "").toUpperCase();
  const fromDb =
    dbSeverity === "CRITICAL" ? "critical" : dbSeverity === "HIGH" ? "high" : dbSeverity ? "review" : null;

  const fixed = [];
  for (const affected of detail.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed && !fixed.includes(event.fixed)) fixed.push(event.fixed);
      }
    }
  }

  const cve = (detail.aliases ?? []).find((alias) => String(alias).startsWith("CVE-")) ?? null;

  return {
    id: detail.id,
    cve,
    summary: String(detail.summary ?? detail.details?.split("\n")[0] ?? "").trim(),
    score,
    vector,
    severity: score !== null ? severityFromScore(score) : (fromDb ?? "review"),
    fixed: fixed.sort()[0] ?? null,
  };
}

/**
 * 主入口：查一批包，返回漏洞结论。
 * 网络失败不抛错，而是返回 {unavailable:true}——「查不了」和「没问题」必须分开说。
 */
export async function queryVulnerabilities(packages, { timeout = 20000 } = {}) {
  if (!packages.length) return { results: [], details: new Map(), unavailable: false, truncated: false };

  let batch;
  try {
    batch = await queryBatch(packages, { timeout });
  } catch (error) {
    return { results: [], details: new Map(), unavailable: true, reason: error.message, truncated: false };
  }

  const uniqueIds = [...new Set(batch.flatMap((item) => item.ids))];
  const truncated = uniqueIds.length > MAX_DETAIL_LOOKUPS;
  const details = await fetchDetails(uniqueIds.slice(0, MAX_DETAIL_LOOKUPS), { timeout });

  return { results: batch, details, unavailable: false, truncated };
}

/* ---------------------------------------------------------- 变成 findings */

/**
 * 把 OSV 结果变成统一的 findings。
 *
 * 同一个包命中几十条漏洞是常态（老版本 Guzzle 就是这样）。全列出来会把报告冲垮，
 * 所以每个包只留最严重的几条，剩下的折成一条「还有 N 条」——数量本身是信息，
 * 但不需要占二十行。
 *
 * @param {Array<{name,version,ecosystem,file}>} packages
 * @param {Array<{ids:string[]}>} results 与 packages 等长
 * @param {Map<string, object>} details
 * @param {{maxPerPackage?: number}} options
 */
export function evaluateDependencies(packages, results, details, { maxPerPackage = 5 } = {}) {
  const findings = [];
  // 同一条 CVE 在 OSV 里可能有多条记录（GHSA 镜像 + 上游），按 CVE 去重，
  // 否则一个包会把同一条漏洞报三遍。
  const seen = new Set();
  const perPackage = new Map();

  packages.forEach((pkg, index) => {
    const ids = results[index]?.ids ?? [];
    for (const id of ids) {
      const detail = details.get(id);
      if (!detail) {
        const key = `${pkg.name}@${pkg.version}:${id}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          ruleId: "dep-vuln-unknown",
          name: `${pkg.name} ${pkg.version} 命中 ${id}`,
          severity: "review",
          file: pkg.file,
          line: 0,
          redacted: `${id} · 详情没取到，需人工确认`,
          fix: `到 osv.dev/vulnerability/${id} 看影响范围，确认是否真的用到了受影响代码路径。`,
        });
        continue;
      }

      const info = summarizeVuln(detail);
      const key = `${pkg.name}@${pkg.version}:${info.cve ?? info.id}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const ids_ = [info.cve, info.id].filter(Boolean).join(" / ");
      const scoreText = info.score === null ? "无 CVSS v3 分数" : `CVSS ${info.score.toFixed(1)}`;
      const fixedText = info.fixed ? `修复于 ${info.fixed}` : "上游未给出修复版本";

      findings.push({
        ruleId: "dep-vuln",
        name: `${pkg.name} ${pkg.version} 有已知漏洞`,
        severity: info.severity,
        file: pkg.file,
        line: 0,
        redacted: `${ids_} · ${scoreText} · ${fixedText}`,
        fix: info.fixed
          ? `${info.summary}。升级到 ${info.fixed} 或更高。`
          : `${info.summary}。上游还没有修复版本，先确认这条代码路径是否真的可达。`,
        packageKey: `${pkg.name}@${pkg.version}`,
      });
      perPackage.set(`${pkg.name}@${pkg.version}`, (perPackage.get(`${pkg.name}@${pkg.version}`) ?? 0) + 1);
    }
  });

  // 按严重度排好后再截断，保证留下的是最要紧的那几条
  const sorted = [...findings].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
  );
  const kept = [];
  const keptCount = new Map();

  for (const finding of sorted) {
    if (!finding.packageKey) {
      kept.push(finding);
      continue;
    }
    const used = keptCount.get(finding.packageKey) ?? 0;
    if (used >= maxPerPackage) continue;
    keptCount.set(finding.packageKey, used + 1);
    kept.push(finding);
  }

  // 被折掉的部分补一条汇总，避免「看着只有 5 条」
  for (const [packageKey, total] of perPackage) {
    const shown = keptCount.get(packageKey) ?? 0;
    if (total <= shown) continue;
    const file = packages.find((p) => `${p.name}@${p.version}` === packageKey)?.file;
    kept.push({
      ruleId: "dep-vuln-more",
      name: `${packageKey} 还有 ${total - shown} 条漏洞没列出`,
      severity: "review",
      file,
      line: 0,
      redacted: `共 ${total} 条，只显示最严重的 ${shown} 条`,
      fix: `升级这个包是唯一的批量解法。完整清单：osv.dev/list?q=${encodeURIComponent(packageKey)}`,
    });
  }

  return kept.map(({ packageKey, ...rest }) => rest);
}

const SEVERITY_RANK = { critical: 0, high: 1, review: 2 };
