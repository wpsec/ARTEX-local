# UI 布局修复记录

日期：2026-11-07  
分支：`artex-iteration`  
状态：代码已修改，待浏览器视觉复核

## 问题

根据本轮提供的截图，Skill 总览中的长 Skill 名称被截断并挤入相邻区域；任务列表右侧固定的操作列空间不足，行内操作按钮出现重叠。

## 实现

- Skill 总览和两列内容增加 `min-width: 0` 约束，避免长内容撑开网格列。
- 未使用 Skill 的标签允许换行，最长宽度限制为 `12rem`，完整名称保留在标签内。
- 任务列表的表头和行内 sticky 操作列统一设置 `13rem` 最小宽度，操作按钮禁止收缩。
- 修改范围仅限 Skill 总览与任务列表两个前端页面，没有调整 API 或后端逻辑。

## 验证

- `cd web && ./node_modules/.bin/tsc --noEmit --pretty false`：通过。
- `git diff --check`：通过。
- `npm run build`：启动后在 Next.js `compile` 阶段超过 3 分钟无新进展，已停止；不能视为构建通过。
- 对两个页面运行 Biome 检查时报告了多处文件级诊断，包含未涉及本次修改的既有代码；没有自动格式化文件。
- 尚未完成浏览器截图复核，后续应在窄屏和宽屏下检查标签换行、表格横向滚动及 sticky 操作列。

## 变更文件

- `web/src/app/(main)/system/skills/page.tsx`
- `web/src/app/(main)/function/tasks/page.tsx`
