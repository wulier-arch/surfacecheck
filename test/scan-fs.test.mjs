import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { collectFiles, scanFiles, isGitRepo, scanGitHistory } from "../src/scan-fs.mjs";

function fake(prefix, length, char = "Q") {
  return prefix + char.repeat(length);
}

/** 建一个临时目录，用完删掉 */
function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "surfacecheck-test-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function git(dir, ...args) {
  return execFileSync("git", ["-c", "user.email=t@example.com", "-c", "user.name=t", ...args], {
    cwd: dir,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "ignore"],
  });
}

test("collectFiles：跳过 node_modules 和二进制文件", () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, "a.js"), "console.log(1)");
    writeFileSync(join(dir, "logo.png"), "not really a png");
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules", "b.js"), "console.log(2)");

    const files = collectFiles(dir).map((f) => f.replace(dir + "/", ""));
    assert.deepEqual(files.sort(), ["a.js"]);
  });
});

test("collectFiles：跳过超大文件", () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, "big.txt"), "a".repeat(2000));
    writeFileSync(join(dir, "small.txt"), "a");
    const files = collectFiles(dir, { maxFileBytes: 1000 }).map((f) => f.replace(dir + "/", ""));
    assert.deepEqual(files, ["small.txt"]);
  });
});

test("scanFiles：在真实文件里找到密钥并给出相对路径", () => {
  withTempDir((dir) => {
    mkdirSync(join(dir, "config"));
    writeFileSync(join(dir, "config", "prod.env"), `AWS=${fake("AKIA", 16)}\n`);
    const findings = scanFiles(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, "config/prod.env");
  });
});

test("scanFiles：含 NUL 的文件按二进制跳过", () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, "weird.dat"), `\u0000${fake("AKIA", 16)}`);
    assert.equal(scanFiles(dir).length, 0);
  });
});

test("isGitRepo：普通目录返回 false", () => {
  withTempDir((dir) => {
    assert.equal(isGitRepo(dir), false);
  });
});

test("isGitRepo：git 仓库返回 true", () => {
  withTempDir((dir) => {
    git(dir, "init", "-q");
    assert.equal(isGitRepo(dir), true);
  });
});

test("scanGitHistory：抓到已经被删掉的密钥", () => {
  withTempDir((dir) => {
    git(dir, "init", "-q");
    writeFileSync(join(dir, "app.js"), `const key = "${fake("AKIA", 16)}";\n`);
    git(dir, "add", ".");
    git(dir, "commit", "-q", "-m", "feat: 加入配置");

    // 第二天「发现并修复」，但 key 还在历史里
    writeFileSync(join(dir, "app.js"), "const key = process.env.AWS_KEY;\n");
    git(dir, "add", ".");
    git(dir, "commit", "-q", "-m", "fix: 改成环境变量");

    // 当前工作区是干净的
    assert.equal(scanFiles(dir).length, 0, "工作区里已经没有密钥");

    // 但历史里有
    const history = scanGitHistory(dir);
    assert.equal(history.commits, 2);
    assert.ok(history.findings.length >= 1, "历史里应该还能找到");
    assert.ok(history.findings[0].commit, "要标出是哪个 commit");
    assert.equal(history.findings[0].commit.length, 7);
  });
});

test("scanGitHistory：报的是历史文件里的真实行号，不是永远 :1", () => {
  withTempDir((dir) => {
    git(dir, "init", "-q");
    writeFileSync(
      join(dir, "config.env"),
      ["# 配置", "", "# 下面这行有问题", `AWS=${fake("AKIA", 16)}`, ""].join("\n")
    );
    git(dir, "add", ".");
    git(dir, "commit", "-q", "-m", "feat: 配置");

    const history = scanGitHistory(dir);
    assert.equal(history.findings.length, 1);
    assert.equal(history.findings[0].line, 4, "应该是文件里的第 4 行");
  });
});

test("scanGitHistory：非 git 目录返回空结果而不是抛错", () => {
  withTempDir((dir) => {
    const result = scanGitHistory(dir);
    assert.deepEqual(result.findings, []);
    assert.equal(result.commits, 0);
  });
});

test("scanGitHistory：只扫新增行，不把删除行算成泄露", () => {
  withTempDir((dir) => {
    git(dir, "init", "-q");
    // 第一个 commit 里根本没有密钥
    writeFileSync(join(dir, "a.txt"), "clean\n");
    git(dir, "add", ".");
    git(dir, "commit", "-q", "-m", "init");

    // 第二个 commit 只删了一行无害内容
    writeFileSync(join(dir, "a.txt"), "cleaner\n");
    git(dir, "add", ".");
    git(dir, "commit", "-q", "-m", "chore: 改文案");

    const history = scanGitHistory(dir);
    assert.equal(history.findings.length, 0);
  });
});
