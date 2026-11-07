# 单漏洞交付报告

## 目标

在任务详情的现有详细报告下方提供“交付报告”。详细报告生成和展示路径保持不变。交付报告面向开发修复，每次为一个漏洞生成独立 Markdown 草稿，用户可以编辑、保存和复制。

## 已实现行为

- 漏洞选择范围限于当前任务和该任务直接继承的漏洞；继承漏洞在当前任务单独保存。
- 生成由用户显式触发，使用当前任务的 `reporter` LLM 路由。
- 草稿说明实际入口和触发过程，给出短攻击链与发现路径说明；修复建议用一个简短段落说明必要改动、解决的问题和证据支持的最小范围，不重复内容，也不给无依据的工期或成本估算。
- CVSS 使用 CVSS 4.0 Base 指标。向量可编辑，评分与等级由本地实现重算，标签标为 CVSS-B。
- AI 生成不直接覆盖数据库中的已保存报告。只有用户点击“保存”才写入；模型失败时保留当前编辑器和数据库内容。
- 报告按 `(task_id, finding_id)` 保存，并记录生成时的漏洞证据版本。证据版本更新后提示报告过期；旧版本报告不能覆盖新证据状态。
- Burp 请求与响应仅从漏洞已绑定的真实 HTTP 流量生成，选择 proof 流量优先。报文头和正文中的认证信息、Cookie、Token 等值按原始证据保留并传入模型。没有绑定流量时显示缺失说明，不生成伪造报文。
- 任务归档包包含交付报告，恢复任务时一并恢复；旧归档包没有该表时按空报告恢复。

## API 与存储

- `GET /api/tasks/{id}/findings/{finding_id}/delivery-report` 读取任务上下文下的报告和当前证据版本。
- `PUT /api/tasks/{id}/findings/{finding_id}/delivery-report` 保存 Markdown、CVSS 向量和证据版本；归档状态或版本冲突返回冲突。
- `POST /api/tasks/{id}/findings/{finding_id}/delivery-report/generate` 读取已登记漏洞、详细报告和已绑定 HTTP 证据，返回未保存草稿。
- 数据单独保存在 `finding_delivery_reports`，不写入 `findings.report`，因此不会改动现有详细报告。

## CVSS 与复核

`web/src/lib/cvss-v4.ts` 使用 FIRST / Red Hat 参考计算器的 CVSS v4.0 Base 宏向量表和评分方法；BSD-2-Clause 版权与许可文本随前端静态资源发布，见 `web/public/third-party-notices.txt`。交付报告只使用 Base 指标，评分结果明确标为 CVSS-B。AI 向量是建议值，最终漏洞等级由开发或安全复核人员确认。

评分回归记录了一个上游资料差异：FIRST 示例页将 `AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` 的 Base 分标为 8.2；FIRST 公开参考源码中的宏向量查表和插值算法得出 9.2。当前实现与测试遵循参考源码，遇到该向量时应核对 FIRST 计算器的当前行为后再发布评分。

## 边界

- 仅能从已绑定流量生成 HTTP 报文；未留存的浏览器操作、原始请求或响应需要人工补充。
- 报文正文最多带入 8 KiB，超出部分截断并标明；二进制正文会替换为省略说明。
