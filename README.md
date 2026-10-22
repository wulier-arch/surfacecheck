# surfacecheck

一条命令看四处攻击面：**仓库里的明文凭据**（含 git 历史）、**线上 TLS 证书**、**HTTP 安全响应头**、
**依赖漏洞**。结果按「能不能立刻被利用」排序，不是按字母排序。

零依赖，148 个测试，Node ≥ 20。

```bash
npx surfacecheck . --url https://example.com
```

> 浏览器版：[wulier-arch.github.io/surfacecheck](https://wulier-arch.github.io/surfacecheck/) —— 粘贴一段配置就能扫，内容不出标签页。

---

## 为什么是现在

2026 年 10 月 21 日晚到 22 日，不到 24 小时里四个不同层面同时出事：

| 层 | 发生了什么 |
| --- | --- |
| **PHP** | 「php2shell」，CVE-2026-109618 / 109619，CVSS v4.0 都是 9.2，未认证远程代码执行。影响 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11 及更早，根因可追到 2012 年的 PHP 5.4.0。修复版本 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 |
| **Node.js** | CVE-2026-111497，Brotli 解码器越界写，影响 26.x / 24.x / 22.x；另有 `decompress` 包的路径遍历 CVE-2026-101894（9.1），`@xhmikosr/decompress` 已修，停止维护的 `decompress` 到 4.2.1 仍未修 |
| **证书信任链** | eMudhra 的 8 张中间 CA 私钥随机性严重不足——P-384 私钥对应的整数是 4、56、66、115 这种。私钥能从公开证书里直接算出来。Chrome / Firefox 10 月 17 日起封锁，Apple 19 日、微软 20 日跟进 |
| **密钥存储** | Railway 的环境变量系统被入侵，部分变量明文被读取；平台暂停构建，导致「换钥匙但没法重新部署」 |

证书那一侧还有两件事值得单独说：

- **UiPath 停机（10 月 13 日，约 1 小时）**：原因是一张过期证书。出事的不是有人盯守的主站，
  而是 AI/ML 依赖链上的**次级端点**，而且事发前这套系统根本没有到期监控。
- **Let's Encrypt 2027 年 2 月 10 日起把有效期从 90 天缩到 64 天**。
  续期脚本里写死「提前 83 / 80 / 60 天」的，到时候会失效。

这些事的共同点：**没有一件是因为业务代码写错了。**

- PHP 和 Node.js 那两条，你的代码一行没改，只要跑在受影响版本上就中招
- 证书那条，配置完全正确也可能出事，因为问题在签发链路和资产清单之外
- 而凭据泄露那条，起点始终是「仓库里躺着的那把 key」

所以 `surfacecheck` 查的是四个地方，因为它们本来就是同一个攻击面。

---

## 它查什么

### 1. 明文凭据：14 条规则，含 git 历史

| 类别 | 例子 | 严重度 |
| --- | --- | --- |
| 云厂商密钥 | AWS Access Key ID / Secret Access Key、GCP 服务账号 JSON、Azure 存储账户密钥 | 严重 |
| 私钥文件 | `-----BEGIN … PRIVATE KEY-----` 开头的文件 | 严重 |
| 平台 token | GitHub、OpenAI、Anthropic、Stripe 生产密钥 | 严重 |
| 其他凭据 | Slack token、Google API Key、带密码的数据库连接串 | 高 |
| 需人工确认 | JWT、`api_key = "长随机串"`（过熵阈值才报） | 待确认 |

默认连 `git log -p --all` 一起扫，并且给出行号——历史里那一条会显示成
`config/production.env:2` 加上 `出现在 commit 92a4931`，不用自己去翻。

### 2. 依赖漏洞：查 OSV，只认锁文件

读 `composer.lock` / `package-lock.json` / `requirements.txt` / `Gemfile.lock`，
交给 [OSV](https://osv.dev)（Google 维护，覆盖 Packagist / npm / PyPI / RubyGems，免密钥）。

报出来的是这样的：

```
高  laravel/framework 8.83.0 有已知漏洞
  composer.lock
  CVE-2026-48019 / GHSA-5vg9-5847-vvmq · CVSS 8.9 · 修复于 12.60.0
  → Laravel Framework: CRLF injection in default email rule。升级到 12.60.0 或更高。
```

三个刻意的选择：

- **只查锁文件里的精确版本。** `composer.json` 写的是 `^8.0`，那不是一个版本，
  拿它去查漏洞库只能编结果。没有锁文件就明确告诉你查不了。
- **CVSS 分数自己算。** 漏洞库经常只给向量不给分数（非 GHSA 来源就没有）。
  按 FIRST 规范实现 v3.1 基础分；只有 v4 向量的条目降级成「待确认」并原样展示向量——
  算错比不算更糟。
- **同一个包最多列 5 条。** 老版本 Guzzle 能命中二十几条，全列出来会把报告冲垮。
  剩下的折成一条「还有 N 条」——数量本身是信息，但不需要占二十行。

### 3. TLS 证书：按剩余寿命比例，不写死天数

- 过期、剩余寿命不足 **1/6**（高危）/ 不足 **1/3**（待确认）
- 公钥强度：RSA 低于 2048 位、已知弱椭圆曲线
- 自签证书、有效期超过 CA/B Forum 的 398 天上限
- 证书链是否受信、SAN 是否覆盖该域名（支持一级通配）、TLS 版本
- 信息行给出链深度、公钥算法与位数

**为什么不写死「30 天内过期」**：64 天证书上那等于剩一半才提醒；7 天的证书则会让告警永远在响，
用户第一件事就是把告警关掉。有签发日期就按比例判，没有才退回固定天数。

**不判断签名算法强度**——Node 的 TLS 接口不暴露这个字段，硬猜就是编数据。

### 4. HTTP 安全响应头

不追求「评分」，只报**能被利用的配置**：

- 没开 CSP / CSP 里有 `*` → 一处 XSS 就是全站失守
- 没开 HSTS 或 `max-age` 太短 → 第一次 http 请求可以被中间人劫持
- 既没有 `frame-ancestors` 也没有 `X-Frame-Options` → 任何站点都能把你的页面套进 iframe 骗点击
- 没开 `nosniff` → 上传的「图片」可以被当 JS 执行
- `Referrer-Policy: unsafe-url` → query 里的 token 会被带给第三方
- 响应头带软件版本号 → 攻击者拿版本号去对已知 CVE

---

## 输出长什么样

真实输出，来自 `node scripts/demo.mjs`（脚本会现场造一个「泄露过又被修好」的仓库再扫它）：

```
这个仓库现在的样子：
  config/production.env 里已经没有任何密钥了。

只扫工作区（大多数工具的做法）：
  发现 0 条

连 git 历史一起扫：

  surfacecheck — 攻击面体检

  仓库  demo-repo
  文件  4 个
  历史  2 个 commit

   3 严重    1 高

  ── 必须马上处理 ────────────────────────────────────────────────

   严重  AWS Access Key ID
      config/production.env:2
      AKIA********（20 字符）
      出现在 commit 92a4931
      → 在 IAM 里禁用并删除该 access key，改用 OIDC / 实例角色。

   严重  AWS Secret Access Key
      config/production.env:3
      FS5G********（40 字符）
      出现在 commit 92a4931
      → 在 IAM 里轮换该用户的 secret key。它比 Access Key ID 更要紧——
        ID 只是用户名，这个才是密码。

  ...

依赖漏洞（查 osv.dev）：

  ── 尽快处理 ────────────────────────────────────────────────

   高  laravel/framework 8.83.0 有已知漏洞
      composer.lock
      CVE-2026-48019 / GHSA-5vg9-5847-vvmq · CVSS 8.9 · 修复于 12.60.0
      → Laravel Framework: CRLF injection in default email rule。升级到 12.60.0 或更高。

  ...
```

注意三点：工作区是干净的，问题全在历史里；报告里的密钥是打码的；
依赖那一层跟你有没有写错代码无关。

`scripts/demo.mjs` 用固定时间戳建 commit，所以任何人跑一遍看到的 SHA 和行号都一样，
不会隔天就对不上。

---

## 用法

```
surfacecheck [目录] [选项]
surfacecheck --url <地址> [选项]

  --url <地址>        检查线上站点，可重复；自动做证书 + 安全头
  --no-history        跳过 git 历史
  --no-files          只扫线上，不扫本地文件
  --no-deps           不查依赖漏洞（默认会查，需要联网访问 osv.dev）
  --json              输出 JSON，给 CI 用
  --fail-on <级别>    达到该级别就以退出码 1 结束：critical | high | review | none（默认 high）
  --no-color          关掉颜色
```

只给 `--url` 时不顺带扫当前目录——用户说「看线上」，就别擅自翻他本地代码。

### 在 CI 里

```yaml
- name: 攻击面体检
  run: npx surfacecheck . --fail-on critical
```

`--json` 的输出带 `summary` 和按严重度排好序的 `findings`，方便接进自己的告警。
依赖没查成时 `targets.depsUnavailable` 会写明原因——**「没查成」和「没问题」不会混为一谈**。

---

## 设计取舍

**为什么默认扫 git 历史。** 泄露最常发生的位置不是当前代码，而是三年前那个已经删掉的 commit。
只扫工作区等于给自己发一张假的安全证明。代价是慢一些，所以给了 `--no-history` 和 512 MB 的缓冲上限；
超限时会明确告诉你「只扫了一部分」，而不是假装扫完了。

**为什么报告里是打码的。** 报告本身不能变成新的泄露源——它会被贴进 issue、贴进群、存进工单系统。
输出只保留前 4 位和长度：够你定位是哪把 key，不够别人拿去用。

**为什么不分级给「评分」。** 评分会让用户去优化评分，而不是去修问题。这里只有三档，
而且每一档都写清楚「不修会怎样」。

**为什么不做「自动修复」。** 自动删文件、自动改历史、自动升级依赖在真实仓库里都太容易出事。
工具只给结论和动作，动手这一步留给人。

---

## 局限（这些是真的）

- **规则是有限的。** 覆盖的是常见凭据形态，扫不到说明「没扫到」，不说明「不存在」。
- **依赖检查依赖 OSV 的覆盖度。** OSV 收录很快但不是全知；没查到不等于没漏洞。
  另外它需要联网，离线时会明确标注「没查成」。
- **浏览器版只能扫文本。** 文件系统遍历、git 历史、TLS 握手、响应头、依赖查询都需要 Node 权限，
  浏览器拿不到，也不假装拿得到。
- **GitHub Pages 设不了响应头。** 本项目的在线演示页自己也会被扫出「没开 CSP」——
  这是平台限制，不是配置疏忽。真站点请在自己的 Nginx / CDN 上配。
- **「待确认」这一档需要人看。** 尤其是 JWT、泛化的 `api_key = "..."`、以及只有 CVSS v4 向量的漏洞。

---

## 开发

```bash
npm test                # 148 个测试，零依赖，只用 node:test
npm run check           # 文档事实核查 + 测试结构自检
node scripts/demo.mjs   # 现场造一个泄露过的仓库再扫它
```

`npm run check` 里有一条是这个项目特有的：**仓库自己扫一遍必须干净**。
测试里的假密钥一律在运行时用片段拼出来，不写字面量——否则工具会在自己的仓库里报误报，
而「对自己也是干净的」正是它最有力的一个演示。

版本变更见 [CHANGELOG.md](CHANGELOG.md)，示例说明见 [examples/README.md](examples/README.md)。

MIT
