# 【未开始】GitHub 仓库设置清单

以下设置需在 GitHub 仓库设置中启用；本地文件无法替代远端分支规则。

## `main`：ARTEX-Pro 正式主分支

- 将 `main` 设为仓库默认分支。
- `artex-dev` 的开发通过审查和 CI 后以 Pull Request 合入 `main`。
- 要求以下状态检查通过：`Go tests`、`Web checks`、`Browser regression`、`Go vulnerability scan`。
- 要求解决所有 Pull Request 对话线程；禁止强制推送和删除分支。
- 有其他维护者参与时要求至少一人批准；单人维护阶段不要设置会阻止本人合并的审查门槛。

## `artex-dev`：日常开发分支

- CI 应在 push 和目标为 `main` 的 Pull Request 时运行。
- 开发完成后通过 Pull Request 合入 `main`；不要绕过审查直接更新正式分支。

## `artex-native-backup`：原生源码备份

- 保留原生 ARTEX 源码基线，不承接 ARTEX-Pro 的功能开发。
- 禁止强制推送和删除，避免丢失原始基线。

## 安全与 Actions

- 默认 `GITHUB_TOKEN` 权限设为只读；发布工作流按 job 单独授予写权限。
- 启用 Dependabot security updates、依赖图和私密漏洞报告。
- 首次通过 Release workflow 发布 GHCR 镜像后，如需匿名拉取，将 `wpsec/artex-pro` 包可见性设为 Public，并确认 Actions 可发布该包。
- 对 `v*` 发布 tag 配置规则，限制创建和更新权限。
- 检查 GitHub Actions 允许列表与第三方 Action 使用策略；工作流中的 Action 应固定到完整 commit SHA，并通过 Dependabot 定期更新。

## 启用后复核

分别确认 `artex-dev` 到 `main` 的 Pull Request 会触发必需状态检查。不要以跳过规则的方式测试保护设置。
