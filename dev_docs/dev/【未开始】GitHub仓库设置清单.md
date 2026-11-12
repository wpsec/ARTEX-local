# 【未开始】GitHub 仓库设置清单

以下设置需在 GitHub 仓库设置中启用；本地文件无法替代远端分支规则。

## `main`：安全维护备份

- 只接受漏洞修复，不接收 `artex-iteration` 或 `artex-iteration-dev` 的整合、优化和功能合并。
- 要求 Pull Request 才能合并，禁止强制推送和删除分支。
- 要求以下状态检查通过：`Go tests`、`Web checks`、`Browser regression`、`Go vulnerability scan`。
- 要求解决所有 Pull Request 对话线程。
- 有其他维护者参与时要求至少一人批准；单人维护阶段不要设置会阻止本人合并的审查门槛。
- 分支保护不能自动判断变更是否属于漏洞修复；PR 说明应列出漏洞影响和修复范围，并由维护者检查没有夹带功能或优化。

## `artex-iteration`：活跃整合分支

- 将此分支设为整合目标；`artex-iteration-dev` 的开发通过检查后以 Pull Request 合入。
- 要求 Pull Request、CI 状态检查和对话线程解决；禁止强制推送和删除分支。
- 安全修复若需进入整合版，应单独 cherry-pick 到开发线并审查，不将 `main` 整体合并到此分支。

## `artex-iteration-dev`：日常开发分支

- CI 应在 push 和 Pull Request 时运行。
- 开发完成后以 Pull Request 合入 `artex-iteration`；不要直接合入 `main`。

## 安全与 Actions

- 默认 `GITHUB_TOKEN` 权限设为只读；发布工作流按 job 单独授予写权限。
- 启用 Dependabot security updates、依赖图和私密漏洞报告。
- 首次通过 Release workflow 发布 GHCR 镜像后，如需匿名拉取，将 `wpsec/artex-local` 包可见性设为 Public，并确认 Actions 可发布该包。
- 对 `v*` 发布 tag 配置规则，限制创建和更新权限。
- 检查 GitHub Actions 允许列表与第三方 Action 使用策略；工作流中的 Action 应固定到完整 commit SHA，并通过 Dependabot 定期更新。

## 启用后复核

分别确认 `main` 的安全修复 Pull Request、`artex-iteration-dev` 到 `artex-iteration` 的整合 Pull Request 都会触发必需状态检查。不要以跳过规则的方式测试保护设置。
