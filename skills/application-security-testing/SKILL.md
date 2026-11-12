---
name: application-security-testing
description: 为整套产品规划授权安全评估，按代码、Web 应用、API 和 OWASP 覆盖范围拆分 ARTEX 任务，并汇总有证据支持的结果。用户提出整体安全审查、发布前评估或尚未确定测试类型时使用。
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
  source: https://github.com/usestrix/strix/tree/main/skills/application-security-testing
---

# 应用安全评估

> 改编说明：基于 usestrix/strix 的 `application-security-testing`（Apache-2.0），已翻译并改写为 ARTEX 工作流。

## 目标与边界

将宽泛的安全评估请求拆成有明确范围的检查，复用 ARTEX 现有资产图、任务规划和 worker 执行流程。不要假设存在 Strix CLI、Strix 云服务、CI 扫描集成或其他未配置的能力。

只有在用户授权且范围清楚时才安排主动测试。授权不明确、目标归属不明或约束缺失时，先整理已知信息并询问；不要扩大目标、推测授权或自行选择生产环境。

## 1. 收敛范围

开始前确认或从当前 ARTEX 任务中读取：

- 目标公司、项目、任务和确切资产；不得从一个域名自行扩展到其子域、相邻 IP 或第三方服务。
- 授权来源、测试环境、允许的主机、路径、协议和时间窗口；优先使用 staging。
- 允许的测试类型、明确排除的资产或操作，以及速率、预算和并发限制。
- 可用的源代码、接口描述和测试账号；需要跨用户或跨租户验证时，使用用户提供的专用测试账号及测试数据。

缺少 staging 或必要测试账号时，说明会导致的覆盖缺口。不要因覆盖不足而转向未授权的生产目标。

## 2. 选择工作流

| 目标 | 使用方式 |
| --- | --- |
| 仓库或指定源码目录 | `find-security-vulnerabilities-in-code` |
| 已授权的在线 Web 应用 | `web-app-penetration-testing` |
| REST、GraphQL 或其他已确认可达的 API | `api-security-testing` |
| 用户要求按 OWASP 类别评估或映射 | `owasp-top-10-testing` |
| 只要求盘点前端接口、参数和页面触发点 | `api-recon`；不得把侦察请求当成漏洞测试授权 |

同一产品有多种资产时，按资产拆分目标和意图；不要把所有目标塞进一条无限扩张的工作。通过 ARTEX 已有规划流程登记目标和约束，再让 worker 各自完成被分配的意图。若当前角色没有对应管理工具，只整理计划并交由有权限的角色处理。

本 Skill 负责选择并组织子流程，不直接调用浏览器或 ScopeSentry。Web 测试由 `web-app-penetration-testing` 调用 OWASP ZAP；API 安全测试由 `api-security-testing` 执行；接口盘点由 `api-recon` 执行。不要为未选择的流程解锁或调用工具。

对每种纳入范围的资产，调用对应的专用 Skill 后再执行或汇总，不要只列出 Skill 名称。仅要求整理已有发现时，不启动新测试；整体评估则只运行授权范围内的流程。

## 3. 汇总结果

- 去重时按共同根因合并，不因多个入口而重复计数。
- 按可复现影响排序，并区分已确认漏洞、待验证线索和未评估范围。
- 每个类别或资产分别记录：测试尝试、实际证据、结论、限制和未覆盖原因。
- 预算、步数、登录权限或工具能力导致提前停止时，明确标注未完成；不得把无结果写成“安全”或“已通过”。

遵循 ARTEX worker 的写回约定：新资产用 `insert_assets`，观察和待验证线索用 `record_fact`，只有本次真实触发且有可复现证据的漏洞才用 `report_finding`。不要在事实或发现中复制凭据、令牌或敏感响应数据。
