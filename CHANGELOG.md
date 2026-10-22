# 变更记录

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-10-22

首个版本。三条检查线放在一条命令里，因为它们本来就是同一个攻击面。

### 新增

- 明文凭据扫描：14 条规则，覆盖 AWS / GCP / Azure / GitHub / OpenAI / Anthropic / Stripe /
  Slack / Google API Key / 私钥 / 带密码的数据库连接串 / JWT / 泛化硬编码密钥。
  含香农熵阈值与占位值过滤，报告输出对密钥打码。
- git 历史扫描：`git log -p --all` 流式解析，只认新增行，并解析 hunk 头给出历史文件里的真实行号。
- TLS 证书检查：过期（14 / 30 天两档）、证书链受信、SAN 覆盖（支持一级通配）、TLS 版本。
- HTTP 安全响应头检查：CSP、HSTS、点击劫持、nosniff、Referrer-Policy、Permissions-Policy、版本泄露。
- 终端报告按「能不能立刻被利用」排序；`--json` 供 CI 使用；`--fail-on` 控制退出码。
- 浏览器版：粘贴或拖入文本即可扫描，内容不出标签页。
- `scripts/demo.mjs`：现场造一个「泄露过又被修好」的仓库再扫它，用于演示和自测。

### 说明

- 零依赖，96 个测试，Node ≥ 20。
- 不判断 TLS 签名算法强度——Node 的接口不暴露该字段，硬猜就是编数据。
