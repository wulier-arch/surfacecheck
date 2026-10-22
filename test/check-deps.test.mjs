import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseComposerLock,
  parseComposerJson,
  parsePackageLock,
  parsePackageJson,
  parseRequirementsTxt,
  parseGemfileLock,
  collectManifests,
  summarizeVuln,
  evaluateDependencies,
} from "../src/check-deps.mjs";

function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "surfacecheck-deps-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/* ------------------------------------------------------------ 清单解析 */

test("parseComposerLock：packages 和 packages-dev 都收，去掉版本前的 v", () => {
  const packages = parseComposerLock(
    JSON.stringify({
      packages: [{ name: "laravel/framework", version: "v8.83.0" }],
      "packages-dev": [{ name: "phpunit/phpunit", version: "9.5.0" }],
    })
  );
  assert.deepEqual(packages, [
    { name: "laravel/framework", version: "8.83.0" },
    { name: "phpunit/phpunit", version: "9.5.0" },
  ]);
});

test("parseComposerLock：缺字段的条目跳过，不抛错", () => {
  const packages = parseComposerLock(JSON.stringify({ packages: [{ name: "a/b" }, {}, null] }));
  assert.deepEqual(packages, []);
});

test("parseComposerJson：只取写死版本号，范围约束跳过", () => {
  const packages = parseComposerJson(
    JSON.stringify({
      require: { "php": "^8.1", "laravel/framework": "8.83.0", "monolog/monolog": "~2.0" },
      "require-dev": { "phpunit/phpunit": "9.5.0" },
    })
  );
  assert.deepEqual(packages, [
    { name: "laravel/framework", version: "8.83.0" },
    { name: "phpunit/phpunit", version: "9.5.0" },
  ]);
});

test("parsePackageLock：v3 的扁平 packages 表", () => {
  const packages = parsePackageLock(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "root", version: "1.0.0" },
        "node_modules/express": { version: "4.18.2" },
        "node_modules/@scope/pkg": { version: "2.0.0" },
      },
    })
  );
  assert.deepEqual(packages, [
    { name: "express", version: "4.18.2" },
    { name: "@scope/pkg", version: "2.0.0" },
  ]);
});

test("parsePackageLock：v1 的嵌套 dependencies 树", () => {
  const packages = parsePackageLock(
    JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        express: { version: "4.18.2", dependencies: { accepts: { version: "1.3.8" } } },
      },
    })
  );
  assert.deepEqual(packages, [
    { name: "express", version: "4.18.2" },
    { name: "accepts", version: "1.3.8" },
  ]);
});

test("parsePackageLock：同一个包不同版本都保留（不同依赖树可能各带一份）", () => {
  const packages = parsePackageLock(
    JSON.stringify({
      packages: {
        "node_modules/a/node_modules/lodash": { version: "4.17.15" },
        "node_modules/lodash": { version: "4.17.21" },
      },
    })
  );
  assert.equal(packages.length, 2);
});

test("parsePackageJson：只取写死版本号", () => {
  const packages = parsePackageJson(
    JSON.stringify({ dependencies: { lodash: "4.17.15", express: "^4.18.0" } })
  );
  assert.deepEqual(packages, [{ name: "lodash", version: "4.17.15" }]);
});

test("parseRequirementsTxt：只取 == 钉死的，注释和选项跳过", () => {
  const packages = parseRequirementsTxt(
    ["# 注释", "flask==2.0.1", "django>=4.0", "requests[socks]==2.31.0", "-r other.txt", ""].join("\n")
  );
  assert.deepEqual(packages, [
    { name: "flask", version: "2.0.1" },
    { name: "requests", version: "2.31.0" },
  ]);
});

test("parseGemfileLock：只取 specs 段", () => {
  const packages = parseGemfileLock(
    [
      "GEM",
      "  remote: https://rubygems.org/",
      "  specs:",
      "    rack (2.2.3)",
      "    rails (7.0.4)",
      "      rack (~> 2.0)",
      "",
      "PLATFORMS",
      "  ruby",
    ].join("\n")
  );
  assert.deepEqual(packages, [
    { name: "rack", version: "2.2.3" },
    { name: "rails", version: "7.0.4" },
  ]);
});

/* --------------------------------------------------------- 目录扫描 */

test("collectManifests：有锁文件时不再看 manifest", () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, "composer.json"), JSON.stringify({ require: { "a/b": "1.0.0" } }));
    writeFileSync(join(dir, "composer.lock"), JSON.stringify({ packages: [{ name: "a/b", version: "0.9.0" }] }));
    const manifests = collectManifests(dir);
    assert.equal(manifests.length, 1, "同一生态只认锁文件");
    assert.equal(manifests[0].file, "composer.lock");
    assert.equal(manifests[0].ecosystem, "Packagist");
    assert.deepEqual(manifests[0].packages, [{ name: "a/b", version: "0.9.0" }]);
  });
});

test("collectManifests：没有锁文件时退回 manifest 并标 lock=false", () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { lodash: "4.17.15" } }));
    const manifests = collectManifests(dir);
    assert.equal(manifests.length, 1);
    assert.equal(manifests[0].lock, false);
  });
});

test("collectManifests：JSON 坏了不抛错，把错误记下来", () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, "package-lock.json"), "{ not json");
    const manifests = collectManifests(dir);
    assert.ok(manifests[0].error, "应该记下解析错误");
    assert.deepEqual(manifests[0].packages, []);
  });
});

test("collectManifests：空目录返回空数组", () => {
  withTempDir((dir) => {
    assert.deepEqual(collectManifests(dir), []);
  });
});

/* ---------------------------------------------------------- 结论生成 */

test("summarizeVuln：抽出 CVE、CVSS 分数、修复版本", () => {
  const info = summarizeVuln({
    id: "GHSA-test-0000-0000",
    aliases: ["CVE-2026-109618"],
    summary: "PHP 里的未认证远程代码执行",
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
    affected: [{ ranges: [{ events: [{ introduced: "0" }, { fixed: "8.5.12" }] }] }],
  });
  assert.equal(info.cve, "CVE-2026-109618");
  assert.equal(info.score, 9.8);
  assert.equal(info.severity, "critical");
  assert.equal(info.fixed, "8.5.12");
});

test("summarizeVuln：没有 CVSS 向量时用 GHSA 的定性等级兜底", () => {
  const info = summarizeVuln({
    id: "GHSA-x",
    summary: "x",
    severity: [],
    database_specific: { severity: "HIGH" },
    affected: [],
  });
  assert.equal(info.score, null);
  assert.equal(info.severity, "high");
});

test("summarizeVuln：什么都没有就落到待确认，不猜成高危", () => {
  const info = summarizeVuln({ id: "GHSA-x", summary: "x", affected: [] });
  assert.equal(info.severity, "review");
  assert.equal(info.fixed, null);
});

test("evaluateDependencies：一个包命中多条漏洞就出多条", () => {
  const packages = [{ name: "laravel/framework", version: "8.83.0", ecosystem: "Packagist", file: "composer.lock" }];
  const results = [{ ids: ["GHSA-a", "GHSA-b"] }];
  const details = new Map([
    ["GHSA-a", { id: "GHSA-a", aliases: ["CVE-1"], summary: "A", affected: [], severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] }],
    ["GHSA-b", { id: "GHSA-b", aliases: ["CVE-2"], summary: "B", affected: [], severity: [] }],
  ]);
  const findings = evaluateDependencies(packages, results, details);
  assert.equal(findings.length, 2);
  assert.equal(findings[0].severity, "critical");
  assert.equal(findings[1].severity, "review");
});

test("evaluateDependencies：详情没取到时明确说「需人工确认」", () => {
  const packages = [{ name: "x", version: "1.0.0", ecosystem: "npm", file: "package-lock.json" }];
  const findings = evaluateDependencies(packages, [{ ids: ["GHSA-missing"] }], new Map());
  assert.equal(findings[0].ruleId, "dep-vuln-unknown");
  assert.ok(findings[0].redacted.includes("人工确认"));
});

test("evaluateDependencies：没有漏洞就不出 finding", () => {
  const packages = [{ name: "safe", version: "1.0.0", ecosystem: "npm", file: "package-lock.json" }];
  assert.deepEqual(evaluateDependencies(packages, [{ ids: [] }], new Map()), []);
});

test("evaluateDependencies：finding 里带上锁文件名，方便定位", () => {
  const packages = [{ name: "x", version: "1.0.0", ecosystem: "npm", file: "app/package-lock.json" }];
  const details = new Map([["GHSA-a", { id: "GHSA-a", summary: "s", affected: [], severity: [] }]]);
  const findings = evaluateDependencies(packages, [{ ids: ["GHSA-a"] }], details);
  assert.equal(findings[0].file, "app/package-lock.json");
});

test("evaluateDependencies：同一条 CVE 的多条记录只报一次", () => {
  const packages = [{ name: "guzzlehttp/guzzle", version: "6.5.0", ecosystem: "Packagist", file: "composer.lock" }];
  const results = [{ ids: ["GHSA-f2wf-25xc-69c9", "GHSA-w248-ffj2-4v5q"] }];
  const details = new Map([
    ["GHSA-f2wf-25xc-69c9", { id: "GHSA-f2wf-25xc-69c9", aliases: ["CVE-2022-31042"], summary: "A", affected: [], severity: [] }],
    ["GHSA-w248-ffj2-4v5q", { id: "GHSA-w248-ffj2-4v5q", aliases: ["CVE-2022-31042"], summary: "A", affected: [], severity: [] }],
  ]);
  const findings = evaluateDependencies(packages, results, details);
  assert.equal(findings.length, 1, "同一个 CVE 不该报两遍");
});
