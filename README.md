# surfacecheck

一条命令看三处攻击面：**仓库里的明文凭据**（含 git 历史）、**线上 TLS 证书**、**HTTP 安全响应头**。
结果按「能不能立刻被利用」排序，不是按字母排序。

零依赖，96 个测试，Node ≥ 20。

```bash
npx surfacecheck . --url https://example.com
```

> 浏览器版：[wulier-arch.github.io/surfacecheck](https://wulier-arch.github.io/surfacecheck/) —— 粘贴一段配置就能扫，内容不出标签页。

---

## 为什么做这个

2026 年 10 月，PingCAP 披露了一起入侵事件。攻击方（自称 FulcrumSec）的说法是：入口不是 0day，
而是 PingCAP 自己代码仓库里躺着的 **GCP 服务账号密钥和 Azure 凭据**——用这些凭据搭了一条复制通道，
定时把控制平面数据库导出去。

这些细节目前只有攻击方单方面披露，未经独立验证；PingCAP 的公告口径是「部分内部经营数据，不影响客户数据库系统」。
两边在数据量上差得很远，真实范围要等取证结论。

但有一点两边没有分歧：**泄露的起点是仓库里的凭据，不是某个还没被发现的漏洞。**

这类事情反复发生的真正原因不是「没人扫」，而是扫的东西不对：

- 只扫当前工作区 → 三年前那个已经删掉的 commit 依然在，`git clone` 一次就全拿到了
- 只扫代码 → 证书过期导致客户端回落到 http，这条链路没有任何代码层面的痕迹
- 只扫线上 → 服务器配得再干净，也挡不住仓库里那把能直接登进控制台的 key

`surfacecheck` 把这三件事放在一条命令里，因为它们本来就是同一个攻击面。

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
`config/production.env:2` 加上 `出现在 commit d7df11e`，不用自己去翻。

### 2. TLS 证书

过期（分 14 天 / 30 天两档）、证书链是否受信、SAN 是否覆盖该域名、协议版本是否已废弃。
支持一级通配：`*.example.com` 覆盖 `api.example.com`，不覆盖 `a.b.example.com`。

**不判断签名算法强度**——Node 的 TLS 接口不暴露这个字段，硬猜就是编数据。

### 3. HTTP 安全响应头

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
  文件  2 个
  历史  2 个 commit

   3 严重    1 高

  ── 必须马上处理 ────────────────────────────────────────────────

   严重  AWS Access Key ID
      config/production.env:2
      AKIA********（20 字符）
      出现在 commit d7df11e
      → 在 IAM 里禁用并删除该 access key，改用 OIDC / 实例角色。

   严重  AWS Secret Access Key
      config/production.env:3
      FS5G********（40 字符）
      出现在 commit 259120a
      → 在 IAM 里轮换该用户的 secret key。它比 Access Key ID 更要紧——
        ID 只是用户名，这个才是密码。

  ...
```

注意两点：工作区是干净的，问题全在历史里；报告里的密钥是打码的。

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

---

## 设计取舍

**为什么默认扫 git 历史。** 泄露最常发生的位置不是当前代码，而是三年前那个已经删掉的 commit。
只扫工作区等于给自己发一张假的安全证明。代价是慢一些，所以给了 `--no-history` 和 512 MB 的缓冲上限；
超限时会明确告诉你「只扫了一部分」，而不是假装扫完了。

**为什么报告里是打码的。** 报告本身不能变成新的泄露源——它会被贴进 issue、贴进群、存进工单系统。
输出只保留前 4 位和长度：够你定位是哪把 key，不够别人拿去用。

**为什么不分级给「评分」。** 评分会让用户去优化评分，而不是去修问题。这里只有三档，
而且每一档都写清楚「不修会怎样」。

**为什么不做「自动修复」。** 自动删文件、自动改历史在真实仓库里太容易出事。
工具只给结论和动作，动手这一步留给人。

---

## 局限（这些是真的）

- **规则是有限的。** 覆盖的是常见凭据形态，扫不到说明「没扫到」，不说明「不存在」。
- **浏览器版只能扫文本。** 文件系统遍历、git 历史、TLS 握手、响应头都需要 Node 权限，浏览器拿不到，也不假装拿得到。
- **GitHub Pages 设不了响应头。** 本项目的在线演示页自己也会被扫出「没开 CSP」——这是平台限制，不是配置疏忽。真站点请在自己的 Nginx / CDN 上配。
- **「待确认」这一档需要人看。** 尤其是 JWT 和泛化的 `api_key = "..."`，误报率不低。

---

## 开发

```bash
npm test        # 96 个测试，零依赖，只用 node:test
npm run check   # 文档事实核查 + 测试结构自检
node scripts/demo.mjs   # 现场造一个泄露过的仓库再扫它
```

`npm run check` 里有一条是这个项目特有的：**仓库自己扫一遍必须干净**。
测试里的假密钥一律在运行时用片段拼出来，不写字面量——否则工具会在自己的仓库里报误报，
而「对自己也是干净的」正是它最有力的一个演示。

版本变更见 [CHANGELOG.md](CHANGELOG.md)，示例说明见 [examples/README.md](examples/README.md)。

MIT
