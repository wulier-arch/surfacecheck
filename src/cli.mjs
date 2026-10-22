#!/usr/bin/env node
/**
 * 命令行入口。
 *
 * 一条命令同时看三件事：仓库里的明文凭据（含历史）、线上证书、线上安全头。
 * 这三件事在真实泄露事件里是同一个攻击面的三个面——
 * 只扫代码会漏掉「证书过期导致客户端回落到 http」，
 * 只扫线上会漏掉「三年前那个 commit 里的 key」。
 */

import { existsSync, statSync } from "node:fs";
import { resolve, basename } from "node:path";
import { scanFiles, collectFiles, scanGitHistory, isGitRepo } from "./scan-fs.mjs";
import { checkCert } from "./check-cert.mjs";
import { checkHeaders } from "./check-headers.mjs";
import { renderTerminal, renderJson, summarize } from "./report.mjs";

const VERSION = "0.1.0";

const HELP = `
surfacecheck ${VERSION} — 攻击面体检：明文凭据 / 证书 / 安全响应头

用法
  surfacecheck [目录] [选项]
  surfacecheck --url <地址> [选项]

选项
  --url <地址>        检查线上站点，可重复；自动做证书 + 安全头
  --no-history        跳过 git 历史（默认会扫，历史里的泄露更常见）
  --no-files          只扫线上，不扫本地文件
  --json              输出 JSON，给 CI 用
  --fail-on <级别>    达到该级别就以退出码 1 结束：critical | high | review | none
                      默认 high
  --no-color          关掉颜色
  -h, --help          显示这份帮助
  -v, --version       显示版本

例子
  surfacecheck .                              # 扫当前仓库，含 git 历史
  surfacecheck --url https://example.com      # 只看线上
  surfacecheck . --url https://example.com    # 一起看
  surfacecheck . --json --fail-on critical    # CI 里只拦「严重」

退出码
  0  没有达到阈值的问题
  1  有达到阈值的问题
  2  用法错误
`;

function parseArgs(argv) {
  const options = {
    dir: null,
    urls: [],
    history: true,
    files: true,
    json: false,
    failOn: "high",
    color: true,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "-h":
      case "--help":
        options.help = true;
        break;
      case "-v":
      case "--version":
        options.version = true;
        break;
      case "--url": {
        const value = argv[++i];
        if (!value) throw new UsageError("--url 后面要跟一个地址");
        options.urls.push(value);
        break;
      }
      case "--no-history":
        options.history = false;
        break;
      case "--no-files":
        options.files = false;
        break;
      case "--json":
        options.json = true;
        options.color = false;
        break;
      case "--no-color":
        options.color = false;
        break;
      case "--fail-on": {
        const value = argv[++i];
        if (!["critical", "high", "review", "none"].includes(value)) {
          throw new UsageError("--fail-on 只接受 critical / high / review / none");
        }
        options.failOn = value;
        break;
      }
      default:
        if (arg.startsWith("-")) throw new UsageError(`不认识的选项：${arg}`);
        if (options.dir) throw new UsageError(`只能指定一个目录，已经指定了 ${options.dir}`);
        options.dir = arg;
    }
  }

  return options;
}

class UsageError extends Error {}

function normalizeUrl(input) {
  if (/^https?:\/\//i.test(input)) return input;
  return `https://${input}`;
}

/** 按 --fail-on 过滤后再算退出码 */
function exitCodeWithThreshold(findings, failOn) {
  if (failOn === "none") return 0;
  const order = { critical: 0, high: 1, review: 2 };
  const threshold = order[failOn] ?? 1;
  return findings.some((f) => (order[f.severity] ?? 9) <= threshold) ? 1 : 0;
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`surfacecheck: ${error.message}\n\n${HELP}`);
      return 2;
    }
    throw error;
  }

  if (options.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (options.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  const targets = {};
  const findings = [];

  // ---- 本地 ----
  const dir = resolve(options.dir ?? process.cwd());
  // 只给 --url 时不顺带扫当前目录：用户说「看线上」，就别擅自翻他本地代码
  const wantsLocal = (options.files || options.history) && (options.dir !== null || options.urls.length === 0);

  if (wantsLocal) {
    if (!existsSync(dir) || !statSync(dir).isDirectory()) {
      process.stderr.write(`surfacecheck: 目录不存在：${dir}\n`);
      return 2;
    }

    if (options.files) {
      findings.push(...scanFiles(dir));
      targets.files = collectFiles(dir).length;
    }

    if (options.history) {
      if (isGitRepo(dir)) {
        const history = scanGitHistory(dir);
        findings.push(...history.findings);
        targets.commits = history.commits;
        if (history.truncated) targets.historyTruncated = true;
      } else {
        targets.commits = null; // 不是 git 仓库，明确标出来
      }
    }

    targets.repo = basename(dir) || dir;
  }

  // ---- 线上 ----
  if (options.urls.length) {
    targets.hosts = [];
    targets.certs = [];
    for (const raw of options.urls) {
      const url = normalizeUrl(raw);
      let host;
      try {
        host = new URL(url).hostname;
      } catch {
        process.stderr.write(`surfacecheck: 地址不合法：${raw}\n`);
        return 2;
      }
      targets.hosts.push(host);

      // 证书和响应头互不依赖，并发跑
      const [cert, headers] = await Promise.all([checkCert(host), checkHeaders(url)]);
      targets.certs.push(cert.info);
      findings.push(...cert.findings, ...headers.findings);
    }
  }

  if (!wantsLocal && !options.urls.length) {
    process.stderr.write(`surfacecheck: 没有指定要检查的东西\n\n${HELP}`);
    return 2;
  }

  // ---- 输出 ----
  if (options.json) {
    process.stdout.write(renderJson(findings, targets) + "\n");
  } else {
    const color = options.color && process.stdout.isTTY;
    process.stdout.write(renderTerminal(findings, { color, targets }));

    const counts = summarize(findings);
    if (targets.historyTruncated) {
      process.stderr.write("注意：git 历史太大，只扫了一部分。可以用 git filter-repo 拆出大文件后再扫。\n");
    }
    if (counts.critical > 0) {
      process.stderr.write("有「严重」问题：这些凭据现在就能被用来登录你的系统，先轮换再清理仓库。\n");
    }
  }

  return exitCodeWithThreshold(findings, options.failOn);
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(`surfacecheck 出错：${error.stack ?? error.message}\n`);
    process.exitCode = 2;
  });
