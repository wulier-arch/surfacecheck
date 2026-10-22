/**
 * 文件系统与 git 历史扫描。只在 Node 里跑。
 *
 * 关于 git 历史：泄露最常见的位置不是当前代码，而是**三年前删掉的那个 commit**。
 * 所以默认连历史一起扫。历史扫描用 `git log -p` 流式解析，只看新增行。
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, extname, basename } from "node:path";
import { execFileSync } from "node:child_process";
import { scanText, sortFindings } from "./scan-text.mjs";

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  "coverage",
  "vendor",
  ".next",
  ".cache",
  "__pycache__",
  ".venv",
  "venv",
]);

const SKIP_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar",
  ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".eot", ".so", ".dylib", ".dll",
  ".exe", ".bin", ".wasm", ".class", ".jar", ".lock",
]);

const MAX_FILE_BYTES = 512 * 1024;

/** 递归收集要扫的文件 */
export function collectFiles(root, { maxFileBytes = MAX_FILE_BYTES } = {}) {
  const files = [];

  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (SKIP_EXT.has(extname(entry.name).toLowerCase())) continue;
      // 锁文件动辄几万行，且全是哈希，扫它没有意义
      if (basename(entry.name) === "package-lock.json") continue;
      try {
        if (statSync(full).size > maxFileBytes) continue;
      } catch {
        continue;
      }
      files.push(full);
    }
  };

  walk(root);
  return files;
}

/** 扫工作区里的文件 */
export function scanFiles(root, options = {}) {
  const files = collectFiles(root, options);
  const findings = [];

  for (const file of files) {
    let text;
    try {
      text = readFileSync(file, "utf-8");
    } catch {
      continue;
    }
    // 含 NUL 基本就是二进制，跳过
    if (text.includes("\u0000")) continue;
    findings.push(...scanText(text, { file: relative(root, file) || file }));
  }

  return sortFindings(findings);
}

/** 这个目录是不是一个 git 仓库 */
export function isGitRepo(root) {
  try {
    execFileSync("git", ["rev-parse", "--git-dir"], { cwd: root, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/**
 * 扫 git 历史里被删掉的密钥。
 * 只看新增行（`+` 开头），因为泄露发生在「被加进去」的那一刻。
 */
export function scanGitHistory(root, { maxBytes = 200 * 1024 * 1024 } = {}) {
  if (!isGitRepo(root)) return { findings: [], truncated: false, commits: 0 };

  let output;
  try {
    output = execFileSync(
      "git",
      ["log", "-p", "--all", "--no-color", "--unified=0", "--format=commit:%H"],
      { cwd: root, encoding: "utf-8", maxBuffer: maxBytes, stdio: ["ignore", "pipe", "ignore"] }
    );
  } catch (error) {
    // 历史太大时 maxBuffer 会超，这时只报能扫到的部分，并明确告诉用户
    if (error.code === "ENOBUFS") {
      output = String(error.stdout ?? "");
      return finishHistory(output, root, true);
    }
    return { findings: [], truncated: false, commits: 0 };
  }

  return finishHistory(output, root, false);
}

function finishHistory(output, root, truncated) {
  const findings = [];
  let commit = null;
  let file = null;
  // 当前 hunk 在「新文件」里的起始行号。有了它，报告才能给出真实行号，
  // 否则每条历史发现都显示 :1，用户得自己去翻。
  let nextLine = 0;
  const commits = new Set();

  for (const line of output.split("\n")) {
    if (line.startsWith("commit:")) {
      commit = line.slice(7).trim();
      commits.add(commit);
      file = null;
      nextLine = 0;
      continue;
    }
    if (line.startsWith("+++ ")) {
      file = line.slice(4).replace(/^b\//, "").trim();
      continue;
    }
    if (line.startsWith("@@")) {
      const match = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      nextLine = match ? Number(match[1]) : 0;
      continue;
    }
    if (line.startsWith("+")) {
      if (line.startsWith("+++")) continue;
      const lineNo = nextLine;
      nextLine += 1;
      if (!commit || !file || file === "/dev/null") continue;

      const hits = scanText(line.slice(1), { file });
      for (const hit of hits) {
        findings.push({ ...hit, line: lineNo, commit: commit.slice(0, 7) });
      }
      continue;
    }
    // 上下文行 / 删除行也会推进新文件的行号
    if (line.startsWith(" ")) nextLine += 1;
  }

  return { findings: sortFindings(findings), truncated, commits: commits.size };
}
