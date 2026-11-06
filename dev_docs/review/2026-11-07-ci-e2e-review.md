# CI 与浏览器回归复审

## 范围

- `.github/workflows/ci.yml` 中的 Web 检查步骤顺序。
- `web/e2e/ui-layout.spec.ts` 中任务操作列的浏览器回归覆盖。
- 贡献指南和工程准备记录中的检查顺序与验证状态。

## 发现与处理

- **P1：** CI 在 Next.js 生成 `next-env.d.ts` 和 `.next/types` 前执行 `tsc`，干净环境会因缺少生成文件失败。已调整为先运行静态构建，再运行独立 TypeScript 检查。
- **P3：** 任务操作列用例只检查初始视口边界，没有验证横向滚动后的固定效果。已将视口设为 1024px，滚动表格容器到最右侧，并比较滚动前后的操作列位置及控件边界。

## 验证与未解决事项

- Biome、工作流 YAML 解析和 `git diff --check` 通过。
- 本次未重跑 Playwright；合并前需由 CI 执行浏览器回归。
- npm audit 报告的依赖树漏洞仍待单独复核，未纳入本次修复范围。
