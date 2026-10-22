/**
 * 密钥识别规则。
 *
 * 设计取舍：
 *   1. 只写**高信号**的规则——精确前缀 + 固定长度。宁可漏一些泛化的密钥，
 *      也不要让用户被一堆误报淹没（误报多的扫描器最后没人用）。
 *   2. 泛化规则（"key = 长随机串"）单独放，严重度标成 review，并且必须过熵阈值，
 *      由人来判断。
 *   3. 所有规则都是纯正则，浏览器和 Node 共用同一份，不依赖任何库。
 */

/** 常见占位值，出现这些就不算泄露 */
const PLACEHOLDERS = [
  "example",
  "your_",
  "your-",
  "xxxx",
  "aaaa",
  "test",
  "dummy",
  "placeholder",
  "changeme",
  "replace",
  "redacted",
  "fake",
  "<",
  "***",
];

export function looksLikePlaceholder(value) {
  const lower = value.toLowerCase();
  return PLACEHOLDERS.some((token) => lower.includes(token));
}

/** 香农熵，按字符算。用来区分「真随机串」和「有意义的英文/路径」 */
export function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * severity:
 *   critical —— 拿到就能直接登进别人系统（云密钥、私钥、生产支付密钥）
 *   high     —— 通常也能造成实质损失，或需要立刻轮换
 *   review   —— 需要人看一眼，可能是误报
 */
export const RULES = [
  {
    id: "private-key",
    name: "私钥文件内容",
    severity: "critical",
    // 只认头，不认整个 key 体
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    fix: "从仓库删除并作废该密钥对，重新生成；用 git filter-repo 清理历史后再强推。",
  },
  {
    id: "aws-access-key",
    name: "AWS Access Key ID",
    severity: "critical",
    re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    fix: "在 IAM 里禁用并删除该 access key，改用 OIDC / 实例角色。",
  },
  {
    id: "gcp-service-account",
    name: "GCP 服务账号私钥",
    severity: "critical",
    re: /"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key"\s*:\s*"-----BEGIN/g,
    fix: "在 GCP IAM 里删除该服务账号密钥，改用 Workload Identity；同时排查该账号的近期活动日志。",
  },
  {
    id: "aws-secret-key",
    name: "AWS Secret Access Key",
    severity: "critical",
    // AWS 的 secret key 没有前缀，只能靠「变量名 + 40 位 base64 字符」认
    re: /\b(?:aws_)?secret[_-]?access[_-]?key\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    minEntropy: 3,
    fix: "在 IAM 里轮换该用户的 secret key。它比 Access Key ID 更要紧——ID 只是用户名，这个才是密码。",
  },
  {
    id: "github-token",
    name: "GitHub Token",
    severity: "critical",
    re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    fix: "到 GitHub Settings → Developer settings 里 revoke 该 token。",
  },
  {
    id: "openai-key",
    name: "OpenAI API Key",
    severity: "critical",
    re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g,
    fix: "在 OpenAI 后台 revoke 该 key，并检查用量是否有异常峰值。",
  },
  {
    id: "anthropic-key",
    name: "Anthropic API Key",
    severity: "critical",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    fix: "在 Anthropic Console 里 revoke 该 key。",
  },
  {
    id: "stripe-live-key",
    name: "Stripe 生产密钥",
    severity: "critical",
    re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g,
    fix: "在 Stripe Dashboard 里 roll 该密钥；生产密钥泄露通常伴随资金风险。",
  },
  {
    id: "slack-token",
    name: "Slack Token",
    severity: "high",
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    fix: "在 Slack App 管理页 revoke 该 token。",
  },
  {
    id: "google-api-key",
    name: "Google API Key",
    severity: "high",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    fix: "在 GCP Console 里删除该 key，并给新 key 加上 API 与来源限制。",
  },
  {
    id: "azure-storage-key",
    name: "Azure 存储账户密钥",
    severity: "high",
    re: /AccountKey\s*=\s*[A-Za-z0-9+/=]{40,}/g,
    fix: "在 Azure Portal 里轮换该存储账户的两个 key，改用托管身份。",
  },
  {
    id: "db-url-with-password",
    name: "带密码的数据库连接串",
    severity: "high",
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s@/]+@/g,
    fix: "改密码，连接串改从环境变量/密钥管理服务读取。",
  },
  {
    id: "jwt",
    name: "JWT",
    severity: "review",
    // 只报 header.payload 都像 base64url 的，减少误报
    re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    fix: "确认这个 JWT 是否长期有效；如果是测试 token 请从仓库删除。",
  },
  {
    id: "generic-secret",
    name: "疑似硬编码密钥（需人工确认）",
    severity: "review",
    // key/secret/token/password 赋值给一个长随机串
    re: /\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*["']([A-Za-z0-9_\-+/=]{20,})["']/gi,
    minEntropy: 3.5,
    fix: "人工确认：如果确实是凭据，改成环境变量并轮换。",
  },
];

/** 对命中的文本做脱敏：只留前 4 位和长度，报告本身不能成为新的泄露源 */
export function redact(value) {
  const text = String(value);
  if (text.length <= 8) return "*".repeat(text.length);
  return `${text.slice(0, 4)}${"*".repeat(Math.min(8, text.length - 4))}（${text.length} 字符）`;
}
