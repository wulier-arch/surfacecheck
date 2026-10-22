/**
 * HTTP 安全响应头检查。
 *
 * 这一块经常被当成「合规装饰」——加几个头，扫描器给个 A，就完事了。
 * 实际上它挡的是很具体的攻击：
 *   - CSP            → XSS 拿到 cookie 之后能不能把数据送出去
 *   - HSTS           → 第一次请求被中间人降级成 http 之后还能不能救回来
 *   - frame-ancestors→ 点击劫持（把后台页面嵌进攻击者的 iframe）
 *   - nosniff        → 上传一个 .jpg 里其实是 JS，浏览器会不会执行它
 *
 * 所以这里不追求「评分」，只报**能被利用的配置**，并且每条都写清楚缺了会怎样。
 */

/** HSTS 半年。低于这个值等于没配——浏览器记不住那么久 */
const HSTS_MIN_MAX_AGE = 15552000;

/** 把 Headers / 普通对象统一成小写 key 的普通对象 */
export function normalizeHeaders(headers) {
  const out = {};
  if (!headers) return out;
  if (typeof headers.forEach === "function" && typeof headers.get === "function") {
    headers.forEach((value, key) => {
      out[key.toLowerCase()] = value;
    });
    return out;
  }
  for (const [key, value] of Object.entries(headers)) {
    out[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
  }
  return out;
}

/** 解析 CSP 里的指令，返回 { directive: [sources] } */
export function parseCsp(value) {
  const directives = {};
  for (const part of String(value).split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    directives[tokens[0].toLowerCase()] = tokens.slice(1);
  }
  return directives;
}

/**
 * 纯函数：给响应头，出结论。不联网，方便测试。
 * @param {Headers|object} headers
 * @param {{url?: string, now?: number}} options
 */
export function evaluateHeaders(headers, { url = "<url>" } = {}) {
  const h = normalizeHeaders(headers);
  const findings = [];
  const seen = new Set();

  const add = (ruleId, name, severity, detail, fix) => {
    if (seen.has(ruleId)) return;
    seen.add(ruleId);
    findings.push({ ruleId, name, severity, file: url, line: 0, redacted: detail, fix });
  };

  // ---- HSTS ----
  const hsts = h["strict-transport-security"];
  if (!hsts) {
    add(
      "hsts-missing",
      "没开 HSTS",
      "high",
      "响应里没有 Strict-Transport-Security",
      "加 `Strict-Transport-Security: max-age=31536000; includeSubDomains`。缺了它，用户第一次访问 http:// 的那一跳可以被中间人劫持。"
    );
  } else {
    const maxAge = Number((hsts.match(/max-age\s*=\s*(\d+)/i) ?? [])[1] ?? 0);
    if (!maxAge) {
      add("hsts-no-maxage", "HSTS 没写 max-age", "high", `值是 "${hsts}"`, "`max-age` 是必填项，缺了浏览器直接忽略整个头。");
    } else if (maxAge < HSTS_MIN_MAX_AGE) {
      add(
        "hsts-short",
        "HSTS 有效期过短",
        "review",
        `max-age=${maxAge}（不到 180 天）`,
        `改成 max-age=31536000（一年）。现在这个值只能覆盖很短的时间窗口。`
      );
    }
    if (maxAge && !/includeSubDomains/i.test(hsts)) {
      add("hsts-no-subdomains", "HSTS 没覆盖子域名", "review", "缺 includeSubDomains", "加上 includeSubDomains；注意这会影响所有子域，先确认没有还在跑 http 的子域。");
    }
  }

  // ---- CSP ----
  const csp = h["content-security-policy"];
  const directives = csp ? parseCsp(csp) : {};
  const hasFrameAncestors = Boolean(directives["frame-ancestors"]);

  if (!csp) {
    add(
      "csp-missing",
      "没开 CSP",
      "high",
      "响应里没有 Content-Security-Policy",
      "至少先上 `default-src 'self'` 并配 report-uri 观察一周，再逐步收紧。没有 CSP，一处 XSS 就等于全站失守。"
    );
  } else {
    const effective = directives["default-src"] ?? directives["script-src"] ?? null;
    if (effective && effective.includes("*")) {
      add("csp-wildcard", "CSP 允许任意来源", "high", `script 源里含 *`, "把 * 换成明确的域名白名单。写 * 等于没有 CSP。");
    }
    if (effective && effective.includes("'unsafe-inline'")) {
      add(
        "csp-unsafe-inline",
        "CSP 允许内联脚本",
        "review",
        "'unsafe-inline' 在 script 源里",
        "换成 nonce 或 hash。保留 unsafe-inline 时，注入一段 <script> 依然能执行。"
      );
    }
    if (effective && effective.includes("'unsafe-eval'")) {
      add("csp-unsafe-eval", "CSP 允许 eval", "review", "'unsafe-eval' 在 script 源里", "去掉 unsafe-eval；它让字符串能被当代码执行。");
    }
  }

  // ---- 点击劫持 ----
  // 注意：完全没有 CSP 时也在这里报。之前把这段写在 `else` 分支里，
  // 结果「什么头都没配」的站点反而不报点击劫持——最该报的漏了。
  if (!hasFrameAncestors && !h["x-frame-options"]) {
    add(
      "clickjacking",
      "没防点击劫持",
      "high",
      "既没有 CSP frame-ancestors 也没有 X-Frame-Options",
      "加 `frame-ancestors 'none'`（或 'self'）。否则任何站点都能把你的页面套进 iframe 骗点击。"
    );
  }

  // ---- X-Frame-Options 的取值 ----
  if (!hasFrameAncestors) {
    const xfo = h["x-frame-options"];
    if (xfo) {
      const normalized = xfo.trim().toLowerCase();
      if (normalized !== "deny" && normalized !== "sameorigin") {
        add("xfo-invalid", "X-Frame-Options 值无效", "review", `值是 "${xfo}"`, "只认 DENY 或 SAMEORIGIN；ALLOW-FROM 现代浏览器已不支持。");
      }
    }
  }

  // ---- nosniff ----
  const nosniff = h["x-content-type-options"];
  if (!nosniff) {
    add(
      "nosniff-missing",
      "没开 nosniff",
      "review",
      "响应里没有 X-Content-Type-Options",
      "加 `X-Content-Type-Options: nosniff`。缺了它，浏览器可能把上传的图片按 HTML/JS 解析。"
    );
  } else if (nosniff.trim().toLowerCase() !== "nosniff") {
    add("nosniff-invalid", "X-Content-Type-Options 值不对", "review", `值是 "${nosniff}"`, "唯一有效值是 `nosniff`。");
  }

  // ---- Referrer-Policy ----
  const referrer = h["referrer-policy"];
  if (!referrer) {
    add(
      "referrer-missing",
      "没设 Referrer-Policy",
      "review",
      "响应里没有 Referrer-Policy",
      "加 `strict-origin-when-cross-origin`。默认策略会把完整 URL（含 query 里的 token）带给第三方。"
    );
  } else if (/unsafe-url/i.test(referrer)) {
    add("referrer-unsafe", "Referrer-Policy 会泄露完整 URL", "high", referrer, "改成 `strict-origin-when-cross-origin` 或更严格。");
  }

  // ---- 版本泄露 ----
  const leaking = ["server", "x-powered-by", "x-aspnet-version"].filter((key) => /\d+\.\d+/.test(h[key] ?? ""));
  if (leaking.length) {
    add(
      "version-leak",
      "响应头泄露了软件版本",
      "review",
      leaking.map((key) => `${key}: ${h[key]}`).join("； "),
      "把版本号去掉（Nginx: `server_tokens off`）。攻击者会拿版本号去对已知 CVE。"
    );
  }

  // ---- Permissions-Policy ----
  if (!h["permissions-policy"] && !h["feature-policy"]) {
    add(
      "permissions-policy-missing",
      "没设 Permissions-Policy",
      "review",
      "响应里没有 Permissions-Policy",
      "关掉用不到的浏览器能力，例如 `Permissions-Policy: camera=(), microphone=(), geolocation=()`。"
    );
  }

  return findings;
}

/** 真正发一次请求拿响应头 */
export async function checkHeaders(url, { timeout = 8000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    // 用 GET 而不是 HEAD：不少 CDN/WAF 对 HEAD 的响应头处理和 GET 不一样，
    // 用 HEAD 扫出来的结果可能和真实用户看到的不同。
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "user-agent": "surfacecheck/0.1 (+https://github.com/wulier-arch/surfacecheck)" },
    });
    return {
      info: { url, status: response.status, finalUrl: response.url },
      findings: evaluateHeaders(response.headers, { url: new URL(response.url).host }),
    };
  } catch (error) {
    return {
      info: { url, status: null, finalUrl: null },
      findings: [
        {
          ruleId: "headers-unreachable",
          name: "请求失败",
          severity: "review",
          file: url,
          line: 0,
          redacted: error.name === "AbortError" ? `${timeout}ms 超时` : error.message,
          fix: "确认站点可达、证书有效；证书错误时 fetch 会直接拒绝。",
        },
      ],
    };
  } finally {
    clearTimeout(timer);
  }
}
