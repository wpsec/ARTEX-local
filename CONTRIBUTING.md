# 参与开发

## 分支与提交

- 日常开发基于 `artex-iteration`；面向稳定版本的改动通过 Pull Request 合入 `main`。
- 提交信息使用 `<type>(<scope>): <简体中文主题>`，类型和范围遵循仓库 `CLAUDE.md`。
- 不提交本地配置、凭据、运行数据或构建产物。

## 本地检查

提交 Pull Request 前，按改动范围运行：

```bash
go test ./...
go vet ./...
cd web
npm ci
npm run build:static
npx tsc --noEmit --pretty false
npx playwright install chromium
npm run test:e2e
```

Go 测试可通过 `ARTEX_PG_DSN` 连接 PostgreSQL；未配置数据库时，需要数据库的测试会按测试代码规则跳过。浏览器回归以 mock API 数据运行，不会连接真实目标。

## Pull Request

- 说明问题背景、实现方式和用户可见影响。
- 列出已运行的检查及结果；未运行的检查要明确标注。
- UI 改动附桌面与窄屏截图，或说明为什么不适用。
- 涉及授权、扫描边界、凭据或外部通信的改动，单独说明安全影响与测试范围。
- 保持改动聚焦，不在同一 Pull Request 中混入无关重构。
