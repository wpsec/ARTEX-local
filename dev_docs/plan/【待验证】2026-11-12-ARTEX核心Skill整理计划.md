# 【待验证】ARTEX Skill 核心集整理与拓展计划

状态：实现与定向验收完成；待用 `0.3.17` 本地镜像完成 Agent 运行时验收；不对真实目标发起扫描。

## 审查结论

当前仓库原有 23 个 Skill。恶意样本分析、逆向工程、社工、深度红队、云和移动端能力不属于本轮自主渗透测试核心；其中部分还依赖默认镜像未提供的专用工具。总路由对 Web/API 工作流有重复推荐，多个通用 Skill 也声明了不必要的 ScopeSentry 与浏览器 MCP。

本轮聚焦 Web、API、代码审查和内网测试，不新增 Skill。根据真实测试暴露的缺口再提出下一批扩展。

## 核心 Skill

保留 10 个默认 Skill：

- 路由与整体评估：`authorized-pentest-router`、`application-security-testing`
- Web 与 API：`web-app-penetration-testing`、`api-recon`、`api-security-testing`、`owasp-top-10-testing`
- 代码与内网：`find-security-vulnerabilities-in-code`、`conducting-internal-network-penetration-test`
- 浏览器自动化与外部资产：`playwright-cli`、`scopesentry`

默认继续授权给 `auto`、`pentest`、`worker`；不新增数据库结构或清理用户自行上传的 Skill。

## 仓库移除项

- 恶意样本与 DFIR 8 个：Android、Golang、Linux ELF、Cuckoo、恶意流量、UPX、UEFI、JavaScript 混淆分析。
- 逆向路由：`reverse-engineering-router`。
- 社工与深度红队：`conducting-social-engineering-penetration-test`、`authorized-red-team-operations`。
- 云与移动端：`conducting-cloud-penetration-testing`、`conducting-mobile-app-penetration-test`。

删除这些内置目录，不打包为可选扩展；保留仍被核心 Skill 使用的许可证文件和来源记录。

## 路由与工具行为

- 总路由为每个请求选择一个主流程。整体产品评估、Web 测试、API 盘点、API 安全验证和 OWASP 分类评估分别限定触发条件。
- Web 与 API 安全测试在 ARTEX 中调用 OWASP ZAP；仅盘点 API 时不启动扫描。主动扫描必须受任务授权范围约束。
- 内网/AD 流程仅在用户通过通用 MCP 接入 BloodHound 且图数据与授权目标匹配时调用只读图查询。默认不内置 BloodHound；不调用其上传或写入工具。
- 启用 Browser MCP 后用于交互式浏览；`playwright-cli` 用于可复现脚本或测试产物，同一操作默认只选一个入口。Browser MCP 不可用时，仅对适合脚本化的流程改用 CLI。测试 runner 仅在目标项目已安装时使用，不临时下载依赖。
- ScopeSentry 专项 Skill 仅用于 ARTEX 中已连接的服务；通用代码、OWASP 与应用路由 Skill 不解锁它。
- `api-recon` 可选脚本始终验证 TLS 证书，并说明 `puppeteer-core` 与 Chromium 的运行前提。

## 验收

- 默认 Skill 目录、DB 可见性清单和打包加载结果均为上述 10 个；不留下已移除 Skill 的路由或许可条目。
- Skill frontmatter 可解析，MCP 名称与 ARTEX 中的预设一致。
- 授权 Web/API 测试调用 ZAP；API 盘点不误触发扫描；AD 查询不把合成数据当作目标证据。
- 代码审查不解锁 ScopeSentry 或浏览器；ScopeSentry 未配置时能说明限制。
- Browser MCP 与 CLI 的触发规则、运行前提和 TLS 行为符合本计划。
- 用现有定向检查验证默认清单与 Skill 加载；手工审阅上述调用路径。不对真实外部目标发起验收扫描。

## 实施结果

- Skill 目录与 DB 默认授权均为 10 项；定向测试 `TestBuiltinSkillVisibilityDefaults`、`TestBundledCoreSkillsLoad` 通过。
- frontmatter YAML、目录/授权集合一致性、MCP 名称、Go 格式、API 侦察脚本语法和 `git diff --check` 检查通过；已移除 Skill 的代码与许可清单引用已清理。
- 手工核对路由与 MCP 解锁规则：Web/API 工作流声明 ZAP；API 盘点无 ZAP；OWASP 评估仅调用适用的专用流程；AD 工作流不要求 BloodHound，只有用户配置且目标数据匹配时才使用其只读查询；代码审查不解锁 ScopeSentry 或浏览器；ScopeSentry 未配置时明确降级；Browser MCP 与 CLI 分工清楚。
- 未在当前运行容器中验证新 Skill 提示词，也未对真实目标发起扫描；需要重建镜像后才能进行 ARTEX Agent 运行时验收。
