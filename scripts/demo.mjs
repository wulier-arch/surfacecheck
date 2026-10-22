/**
 * 现场造一个「泄露过又被修好」的仓库，然后扫它。
 *
 * 为什么不用静态的 examples/ 目录：示例里必须真的躺着假密钥才有意义，
 * 但那样这个仓库自己就会被扫出一堆误报，CI 里那条「自扫必须干净」就永远过不了。
 * 所以示例在运行时生成——顺便也让演示变成可复现的：任何人跑一遍看到的都一样。
 *
 * 运行：node scripts/demo.mjs
 */

import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { scanFiles, scanGitHistory } from "../src/scan-fs.mjs";
import { collectManifests, queryVulnerabilities, evaluateDependencies } from "../src/check-deps.mjs";
import { renderTerminal } from "../src/report.mjs";

const DAY = 24 * 60 * 60 * 1000;

/** 假密钥在运行时拼出来，源码里不留字面量 */
const fake = (prefix, length, seed = 7) => {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[(i * seed + 5) % alphabet.length];
  return prefix + out;
};

const dir = mkdtempSync(join(tmpdir(), "surfacecheck-demo-"));

/**
 * 所有 git 调用都走这里。
 * 关键点：`-c user.email/-c user.name` 必须每一次都带上，不能只在 init 时带。
 * 本机有全局 git 配置所以看不出来，CI 里没有——第一次跑就挂在 `git commit`
 * 那句「Please tell me who you are」，而且因为 stdio 是 ignore，报错还是空的。
 */
const git = (args, env) => {
  const result = execFileSync(
    "git",
    ["-c", "user.email=demo@example.com", "-c", "user.name=demo", ...args],
    { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } }
  );
  return result;
};

const commitAt = (message, isoDate) => {
  // 用固定时间戳而不是「几天前」，这样每次跑出来的 commit SHA 都一样，
  // 文档里引用的输出才不会隔天就对不上。
  git(["add", "-A"]);
  git(["commit", "-q", "-m", message], { GIT_AUTHOR_DATE: isoDate, GIT_COMMITTER_DATE: isoDate });
};

try {
  git(["init", "-q"]);
  mkdirSync(join(dir, "config"));
  mkdirSync(join(dir, "src"));

  // ---- 第 1 天：把生产密钥写进配置，一起提交了 ----
  writeFileSync(
    join(dir, "config", "production.env"),
    [
      "# 生产环境配置",
      `AWS_ACCESS_KEY_ID=${fake("AKIA", 16, 3)}`,
      `AWS_SECRET_ACCESS_KEY=${fake("", 40, 11)}`,
      `DATABASE_URL=postgres://app:${fake("", 12, 5)}@db.internal:5432/prod`,
      `STRIPE_SECRET_KEY=sk_live_${fake("", 24, 13)}`,
      "",
    ].join("\n")
  );
  writeFileSync(
    join(dir, "src", "deploy.js"),
    [
      "// 部署脚本",
      "const client = new Client({ connectionString: process.env.DATABASE_URL });",
      "module.exports = { client };",
      "",
    ].join("\n")
  );
  // 顺带放一份 composer.lock：这是「你一行没写错，但上游坏了」那一类问题
  writeFileSync(
    join(dir, "composer.json"),
    `${JSON.stringify({ require: { "laravel/framework": "8.83.0" } }, null, 2)}\n`
  );
  writeFileSync(
    join(dir, "composer.lock"),
    `${JSON.stringify(
      {
        packages: [
          { name: "laravel/framework", version: "v8.83.0" },
          { name: "guzzlehttp/guzzle", version: "6.5.0" },
        ],
        "packages-dev": [],
      },
      null,
      2
    )}\n`
  );
  commitAt("feat: 加上部署脚本", "2025-09-17T08:00:00Z");

  // ---- 第 90 天：有人发现不对，把密钥挪进环境变量 ----
  writeFileSync(
    join(dir, "config", "production.env"),
    ["# 生产环境配置（密钥已挪到密钥管理服务）", "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}", ""].join("\n")
  );
  commitAt("fix: 配置里的密钥改成环境变量", "2026-07-24T08:00:00Z");

  // ---- 今天：工作区看起来是干净的 ----
  const workingTree = scanFiles(dir);
  const history = scanGitHistory(dir);

  console.log("\n这个仓库现在的样子：");
  console.log("  config/production.env 里已经没有任何密钥了。\n");

  console.log("只扫工作区（大多数工具的做法）：");
  console.log(`  发现 ${workingTree.length} 条\n`);

  const report = renderTerminal(history.findings, {
    color: process.stdout.isTTY,
    targets: { repo: "demo-repo", files: 2, commits: history.commits },
  });
  console.log("连 git 历史一起扫：");
  console.log(report);

  const unique = new Set(history.findings.map((f) => `${f.ruleId}:${f.commit}`));
  console.log(`  历史里仍然躺着 ${unique.size} 条不同位置的凭据。`);
  console.log("  轮换密钥是必须的——清理历史不能让它变回安全。\n");

  // ---- 第三段：依赖漏洞 ----
  const manifests = collectManifests(dir);
  const packages = manifests.flatMap((m) =>
    m.packages.map((pkg) => ({ ...pkg, ecosystem: m.ecosystem, file: m.file }))
  );

  console.log("依赖漏洞（查 osv.dev）：");
  if (!packages.length) {
    console.log("  没有可查的锁文件。\n");
  } else {
    const { results, details, unavailable, reason } = await queryVulnerabilities(packages, { timeout: 15000 });
    if (unavailable) {
      console.log(`  没查成（${reason}）。这一项不算「干净」。\n`);
    } else {
      const depFindings = evaluateDependencies(packages, results, details);
      console.log(
        renderTerminal(depFindings, {
          color: process.stdout.isTTY,
          targets: {
            repo: "demo-repo",
            manifests: manifests.map((m) => ({
              file: m.file,
              ecosystem: m.ecosystem,
              lock: m.lock,
              packages: m.packages.length,
            })),
          },
        })
      );
      console.log(`  ${packages.length} 个包里有 ${new Set(depFindings.map((f) => f.name)).size} 个命中已知漏洞。`);
      console.log("  这一层跟你有没有写错代码无关：版本在锁文件里，漏洞在上游。\n");
    }
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
