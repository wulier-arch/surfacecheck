/**
 * 浏览器端：纯本地扫描，任何内容都不出这个标签页。
 *
 * 这里只做「文本 → 结论」这一段。文件系统遍历、git 历史、TLS 握手、响应头
 * 都需要 Node 权限，浏览器拿不到，也不该假装能拿到。
 */

/**
 * 页面在两种路径下都要能加载到 src/：
 *   本地直接开 web/index.html      → ../src/
 *   GitHub Pages 项目页 /repo/      → ./src/
 * 所以按顺序试。这是之前踩过的坑：只在本地能跑，上线后点一下什么都不发生。
 */
async function loadModule(name) {
  let lastError;
  for (const base of ["./src/", "../src/"]) {
    try {
      return await import(base + name);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

const input = document.getElementById("input");
const result = document.getElementById("result");
const editor = document.getElementById("editor");

let scanText = null;
let sortFindings = null;

const LABEL = { critical: "严重", high: "高", review: "待确认" };
const GROUP = {
  critical: "必须马上处理",
  high: "尽快处理",
  review: "需要人看一眼",
};

/** 转义后再塞进 innerHTML */
function esc(text) {
  return String(text).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[ch]);
}

/** 示例文本在运行时拼出来，源码里不留完整形态——不然这个仓库自己会被扫出误报 */
function sampleText() {
  const join = (...parts) => parts.join("");
  const rand = (n, chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789") =>
    Array.from({ length: n }, (_, i) => chars[(i * 7 + 3) % chars.length]).join("");

  return [
    "# .env.production（这个文件曾经被提交过）",
    join("AWS_ACCESS_KEY_ID=AKIA", rand(16)),
    join("AWS_SECRET_ACCESS_KEY=", rand(40, "abcdefghijklmnopqrstuvwxyz0123456789")),
    "",
    "# 数据库",
    join("DATABASE_URL=postgres://app:", "S3cretPw", "@db.internal:5432/prod"),
    "",
    "# 第三方",
    join("STRIPE_SECRET=", "sk_live_", rand(24)),
    "",
    "# 一段被贴进 issue 的日志",
    "curl -H 'Authorization: Bearer " + join("eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U") + "' https://api.example.com/v1/me",
    "",
    "# 顺手带上的私钥（真的有人这么干）",
    ["-----BEGIN", "RSA PRIVATE KEY-----"].join(" "),
    "MIIEpAIBAAKCAQEA7...",
    ["-----END", "RSA PRIVATE KEY-----"].join(" "),
  ].join("\n");
}

function render(findings, sourceLabel) {
  if (!findings.length) {
    result.innerHTML =
      '<div class="tally"><div class="ok">✓ 没有发现问题</div></div>' +
      '<div class="empty">注意：这是「没扫到」，不是「不存在」。规则覆盖的是常见凭据形态，不是全部。</div>';
    return;
  }

  const counts = { critical: 0, high: 0, review: 0 };
  for (const f of findings) counts[f.severity]++;

  const tally = [];
  if (counts.critical) tally.push(`<div class="c">${counts.critical} 严重</div>`);
  if (counts.high) tally.push(`<div class="h">${counts.high} 高</div>`);
  if (counts.review) tally.push(`<div class="r">${counts.review} 待确认</div>`);
  tally.push(`<div>来源 ${esc(sourceLabel)}</div>`);

  const parts = [`<div class="tally">${tally.join("")}</div>`];

  let last = null;
  for (const f of findings) {
    if (f.severity !== last) {
      if (last !== null) parts.push("</div>");
      parts.push(`<div class="group-title">${GROUP[f.severity]}</div><div>`);
      last = f.severity;
    }
    const where = f.line ? `${f.file}:${f.line}` : f.file;
    parts.push(
      `<div class="finding ${f.severity}">` +
        `<div class="finding-top">` +
        `<span class="badge ${f.severity}">${LABEL[f.severity]}</span>` +
        `<span class="finding-name">${esc(f.name)}</span>` +
        `</div>` +
        `<div class="finding-where">${esc(where)}</div>` +
        `<div class="finding-redacted">${esc(f.redacted)}</div>` +
        `<div class="finding-fix">${esc(f.fix)}</div>` +
        `</div>`
    );
  }
  parts.push("</div>");

  result.innerHTML = parts.join("");
}

async function run(text, sourceLabel) {
  if (!scanText) {
    result.innerHTML = '<div class="empty">模块没加载起来。刷新一次试试；如果还是不行，说明部署缺了 src/ 目录。</div>';
    return;
  }
  const findings = sortFindings(scanText(text, { file: sourceLabel }));
  render(findings, sourceLabel);
}

async function init() {
  try {
    const scanModule = await loadModule("scan-text.mjs");
    scanText = scanModule.scanText;
    sortFindings = scanModule.sortFindings;
  } catch (error) {
    console.error("加载扫描模块失败", error);
    result.innerHTML =
      '<div class="empty">扫描模块加载失败，浏览器版暂时不可用。命令行版不受影响。</div>';
    return;
  }

  document.getElementById("scan").addEventListener("click", () => {
    const text = input.value;
    if (!text.trim()) {
      result.innerHTML = '<div class="empty">先粘贴点东西。</div>';
      return;
    }
    run(text, "粘贴的文本");
  });

  document.getElementById("sample").addEventListener("click", () => {
    input.value = sampleText();
    run(input.value, "示例 .env");
  });

  document.getElementById("clear").addEventListener("click", () => {
    input.value = "";
    result.innerHTML = '<div class="empty">还没有内容。粘贴一段，或点「放一段示例」。</div>';
    input.focus();
  });

  // 拖文件进来：File API 读的是本地内容，不发请求
  for (const event of ["dragenter", "dragover"]) {
    editor.addEventListener(event, (e) => {
      e.preventDefault();
      editor.classList.add("drag");
    });
  }
  for (const event of ["dragleave", "drop"]) {
    editor.addEventListener(event, (e) => {
      e.preventDefault();
      editor.classList.remove("drag");
    });
  }
  editor.addEventListener("drop", async (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    const text = await file.text();
    input.value = text.length > 200000 ? text.slice(0, 200000) : text;
    run(input.value, file.name);
  });

  // Cmd/Ctrl + Enter 直接扫
  input.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      document.getElementById("scan").click();
    }
  });

  // 带 #demo 打开时直接跑一遍示例，方便分享和截图
  if (location.hash === "#demo") {
    input.value = sampleText();
    run(input.value, "示例 .env");
  }
}

init();
