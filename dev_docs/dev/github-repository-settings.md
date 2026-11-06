# GitHub 仓库设置清单

以下设置需在 GitHub 仓库设置中启用；本地文件无法替代远端分支规则。

## `main` 分支规则

- 要求 Pull Request 才能合并，禁止直接推送、强制推送和删除分支。
- 要求分支与目标分支保持最新。
- 要求以下状态检查通过：`Go tests`、`Web checks`、`Browser regression`、`Go vulnerability scan`。
- 要求解决所有 Pull Request 对话线程。
- 有其他维护者参与时要求至少一人批准；单人维护阶段不要设置会阻止本人合并的审查门槛。

## 安全与 Actions

- 默认 `GITHUB_TOKEN` 权限设为只读；发布工作流按 job 单独授予写权限。
- 启用 Dependabot security updates、依赖图和私密漏洞报告。
- 首次通过 Release workflow 发布 GHCR 镜像后，如需匿名拉取，将 `wpsec/artex-local` 包可见性设为 Public，并确认 Actions 可发布该包。
- 对 `v*` 发布 tag 配置规则，限制创建和更新权限。
- 检查 GitHub Actions 允许列表与第三方 Action 使用策略；工作流中的 Action 应固定到完整 commit SHA，并通过 Dependabot 定期更新。

## 启用后复核

创建一个不含业务改动的临时 Pull Request，确认四个状态检查均能触发并成为必需检查，再移除临时 Pull Request。不要以跳过规则的方式测试保护设置。
