# Web/API 工具拓展实现说明

## 默认镜像内容

- `Dockerfile` 从固定版本的 ZAP 构建阶段提取 Web 工具：ffuf 2.3.0 与固定 commit 的 sqlmap；ffuf 发布压缩包按目标架构校验 SHA-256。
- `tools/ffuf/web-common.txt` 提供小型内置路径字典。
- 镜像安装固定版本 Puppeteer Core，并将 Playwright 管理的 Chromium 映射到 `/usr/bin/chromium`，供 `skills/api-recon/scripts/runtime_harvest.js` 复用。
- `THIRD_PARTY_NOTICES.md` 记录工具版本、上游许可及镜像内文件位置。
- 镜像保留 SQLMap 完整上游源码，其中包括 `tamper/`。ARTEX 没有新增自定义绕过脚本；Skills 限定脚本只可在授权包含过滤器验证且观察到具体过滤行为后按需使用。

## Agent 使用方式

未新增 MCP 或调用入口。Web/API Agent 在现有 Skill 被加载后，通过 Bash 按需调用命令行工具；具体限制见 `skills/web-app-penetration-testing/SKILL.md` 和 `skills/api-security-testing/SKILL.md`。工具结果是候选证据，确认 finding 前仍需检查原始请求、响应和目标影响。

ZAP Skill 的数据库装配与调用链由 `server.TestWireAgentAugmentUnlocksSeededZAPAfterSkillLoad` 覆盖：测试在隔离 PostgreSQL 中使用默认 ZAP seed 和 loopback MCP fixture，验证 Skill 加载前工具受 deferred/locked 控制，加载后可调用。`agent.TestSkillGatedMCPCallThroughSession` 以 fake provider 验证 ARTEX Agent Session 的工具 schema 隐藏、搜索、解锁和执行路径；不调用真实模型。

SQLMap 首轮参数限制为单参数、`risk=1`、`level=1`、单线程和 30 秒时限，并通过 `--answers='extending provided level=N'` 明确拒绝自动扩大测试级别。`--skip-waf` 只关闭 WAF/IPS 启发式识别；WAF 过滤验证属于单独授权场景，不由 Agent 自动启用 tamper 脚本。

资产闸门对资产绑定意图执行全局拦截规则与任务级允许白名单；当任务配置了允许白名单时，超出白名单的资产绑定会被拒绝。Bash/CLI 任意 URL 不受网络层范围硬限制，按用户决定作为单用户本地部署的已知限制记录。

本地标签 `artex:2.3.0` 已重建并已切换到当前 `artex-local-artex-1` 容器。最后一次构建镜像 ID 为 `sha256:c947f79a73d68e22653dba2d26bf9cead74da13fb94a38c3b5b4b720736fc8a8`，Docker 报告大小为 `1,240,919,299` bytes。切换后 HTTP 根路径返回 200；容器内确认 ffuf 2.3.0、sqlmap `1.10.11.9#dev`、Chromium 与 Puppeteer Core 可用。`artex-local-postgres-1` 保持原容器且健康，未重建数据库服务或卷。新镜像另以断网临时容器启动 Puppeteer/Chromium 打开 data 页面，检查通过。

默认运行仍只需要 ARTEX 与 PostgreSQL 两个容器。新增 CLI、字典和浏览器脚本依赖不作为守护进程启动。
