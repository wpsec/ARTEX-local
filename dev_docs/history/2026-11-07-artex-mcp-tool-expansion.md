# ARTEX MCP 工具拓展调研计划

## 摘要

状态：调研与评分已完成（2026-11-08）；ZAP 与 BloodHound 条件性试点另见[集成实施历史](2026-11-08-artex-zap-bloodhound-mcp-integration.md)。

调研适用于 Web/API 渗透测试和授权内网红队测试的 MCP，产出评分短名单及 1–3 个试点建议。本轮只做调研和评估，不安装或接入新 MCP。

## 调研与评估

- 按 Web/API 测试、网络与服务发现、内网/AD 测试三类搜集候选，优先检查项目官方仓库、文档和发布记录。开源、自托管项目优先；只有在能力缺口明显时，才把商业托管服务列为备选。
- 以现有 ARTEX 能力为基线，排除与 Browser MCP、内置工具和现有 Skill 重复的候选。
- 候选按 0–5 分评估：测试覆盖与实用价值 30%、ARTEX 接入匹配度 25%、成熟度与可靠性 20%、安全和凭据管理 15%、许可与运行成本 10%。总分 = 各项分数 × 权重之和 ÷ 5。
- 进入试点建议需达到 75/100，且支持 ARTEX 已有的 stdio、HTTP 或 SSE 传输；部署和凭据配置有文档；没有未解决的严重安全问题。未达门槛的候选保留评分及淘汰原因。

## 试点验证与接口

在隔离的授权测试环境验证入选候选：完成一个 Web/API 用例和一个内网用例，检查输出是否能支撑 ARTEX 资产、事实或漏洞记录；确认 MCP 能按 Agent 授权、调用可观测、超时和重连行为可接受。

本轮不改 API、数据库或 Agent 接口。若候选需要 ARTEX 当前 MCP 接入方式无法支持的能力，记录为后续开发缺口，不在调研中临时扩展接口。

## 交付与默认项

将调研记录写入本文件，包括候选来源、能力与重复项、评分依据、运行成本和凭据要求、淘汰理由、试点建议。默认以 Web/API＋授权内网为范围；本轮不安装、不启用、不分配任何新 MCP。

---

## 调研执行记录（2026-11-08）

### ARTEX 能力基线

本次按当前代码核对了接入和权限边界：

- 通用 MCP 连接支持 stdio、Streamable HTTP 和 legacy SSE；HTTP 连接可配置请求头和 TLS 校验选项。见 server/mcpdiscover.go。
- MCP 工具可以按 Agent 可见性分配；新增工具需要实际验证调用记录、超时和重连体验。见 server/platform_tools.go、agent/assembly.go。
- Browser MCP、内置工具和已有 Skill 已能覆盖浏览器操作、HTTP 流量查看以及常见 Web/API 和网络测试流程，因此新接入工具需要带来额外扫描覆盖或图谱分析能力，才有引入价值。
- 原计划中“ScopeSentry 条目尚未发现工具”的描述需要更正：项目已有 ScopeSentry 专用同步流程，通过 MCP 客户端调用 list_projects_data、list_tasks、get_project、list_assets，并将项目范围和资产同步到 ARTEX。该流程属于资产/范围同步，不等同于面向 Agent 的通用 MCP 工具集，也不能据此认为 ScopeSentry 的其他测试能力已接入。见 server/sync_scopesentry.go。

### 候选评分短名单

评分基于 2026-11-08 可查到的仓库、官方文档和发布记录；社区热度只作为成熟度的弱参考，不能替代安全审查。

| 候选 | 类别与来源 | 价值 | 接入匹配 | 成熟度 | 安全/凭据 | 许可/成本 | 总分 | 结论 |
|---|---|---:|---:|---:|---:|---:|---:|---|
| OWASP ZAP MCP Integration | Web/API；[官方集成说明](https://github.com/zaproxy/zaproxy-website/blob/main/site/content/blog/2026-04-02-zap-mcp-server/index.md) | 5 | 4 | 2 | 4 | 5 | 80 | 条件性试点；先验证 HTTP transport，再限隔离靶场和未认证 API |
| BloodHound MCP | 内网/AD；[社区项目仓库](https://github.com/mwnickerson/bloodhound_mcp)、[SpecterOps BloodHound Skill 文档](https://github.com/SpecterOps/skills/blob/main/plugins/bloodhound/README.md) | 5 | 4 | 3 | 2 | 4 | 76 | 条件性试点；只用合成/实验室数据，确认数据不离开测试环境 |
| Caido MCP Server | Web/API；[社区项目仓库](https://github.com/c0tton-fluff/caido-mcp-server)、[发布记录](https://github.com/c0tton-fluff/caido-mcp-server/releases) | 3 | 2 | 4 | 3 | 2 | 57 | 暂不试点；流量能力与 ARTEX 重叠，且依赖非开源 Caido |
| Kali MCP Server | 网络与服务发现；[Kali 工具说明](https://www.kali.org/tools/mcp-kali-server/)、[Kali 打包仓库](https://gitlab.com/kalilinux/packages/mcp-kali-server) | 4 | 1 | 2 | 1 | 5 | 50 | 淘汰；远程终端命令能力过宽，和 ARTEX 现有工具重复 |

分值按各项分数乘权重相加后除以 5。例如 ZAP = (5×30 + 4×25 + 2×20 + 4×15 + 5×10) ÷ 5 = 80。

### 候选详情

#### 1. OWASP ZAP MCP Integration：建议 Web/API 试点

- 能力：可启动/停止传统 Spider、AJAX Spider 和 Active Scan，查询扫描状态、Alerts、请求历史并生成报告；官方 API 指南说明可通过 OpenAPI/Swagger、GraphQL、WSDL 或 URL 列表导入 API 端点。
- 与 ARTEX 的差异：ARTEX 已有浏览器和 HTTP 流量能力；ZAP 补充的是成熟 DAST 引擎及其被动/主动扫描规则，不是再加一套浏览器控制工具。
- 接入与成熟度：ZAP 内部运行 HTTP MCP 服务，文档示例使用 8282 端口和 Authorization 安全密钥；ARTEX 支持 HTTP 类传输，但需在试点确认双方 MCP 协议版本、TLS 证书及认证头兼容。ZAP 主项目成熟，MCP 插件在官方公告中仍标注为 alpha，因此成熟度只给 2 分。
- 安全与限制：默认要求安全密钥并拒绝普通 HTTP；主动扫描会向目标发送攻击性请求，只能对明确授权的靶场执行。试点时还要在网络层限制扫描实例的出口，只能访问靶场地址。当前版本不直接支持登录目标应用，先只测未认证 API 或公开页面；需要登录态时不应把它当成已满足需求。
- 凭据与成本：MCP 安全密钥放在 ARTEX MCP 请求头配置中，使用 HTTPS 并校验证书。ZAP 是免费开源工具，运行成本主要是一个独立 ZAP 实例及其 CPU/内存占用；无需新增商业订阅。官方资料：[MCP 功能与安全配置](https://github.com/zaproxy/zaproxy-website/blob/main/site/content/blog/2026-04-02-zap-mcp-server/index.md)、[API 扫描方式](https://github.com/zaproxy/zaproxy-website/blob/main/site/content/faq/how-can-you-use-zap-to-scan-apis.md)、[ZAP API 许可说明](https://www.zaproxy.org/docs/api/)。
- 评分依据：实用价值 5（DAST 扫描补充明显）；接入匹配 4（HTTP 与认证头看起来可映射，协议细节待试）；成熟度 2（MCP 插件仍为 alpha）；安全 4（有密钥和 HTTPS 默认项，但主动扫描必须受范围约束）；许可成本 5（开源且无订阅费）。

#### 2. BloodHound MCP：满足数据隔离条件时试点

- 能力：连接 BloodHound CE/Enterprise，查询域、用户、组、计算机、ADCS 和攻击路径；支持图查询与相关数据资源。仓库列出 13 个组合工具，其中也包含 custom_nodes 写操作和 file_upload。
- 与 ARTEX 的差异：当前 ARTEX 已有网络发现工具和内网测试 Skill，但没有 BloodHound 图数据库的关系/攻击路径分析能力。其输出可在试点中作为资产关系或攻击路径事实，由开发者复核后记录；本轮不增加自动导入接口。
- 接入与成熟度：项目文档提供 stdio 配置；需要 Python 3.11+、uv、已加载数据的 BloodHound CE 实例和 API 凭据。项目有测试和持续提交，但由社区维护，未见正式 release 列表，因此成熟度给 3 分。SpecterOps 的 Skills 仓库记录了对此 MCP 的使用方式，不代表该 MCP 由 SpecterOps 官方维护。
- 安全与凭据：项目明确提示处理过的 BloodHound 数据会发送给 LLM 服务商；同时工具集包含写操作。README 描述的启动自检是只读请求，但没有据此证明 API 凭据可限制所有工具为只读。因此只在合成数据或专用 AD 靶场中试点，禁止导入生产目录数据；优先使用本地 LLM。若无法确认数据路径和写操作影响范围，则不启动试点。
- 凭据与成本：使用专用 BloodHound API Token ID/Key，通过 ARTEX MCP 的进程环境传递，不写入仓库或命令行参数；TLS 校验默认启用。MCP 仓库采用 GPL-3.0；运行成本包括 CE 实例的部署维护及实验域数据准备，企业版费用不纳入本次评估。来源：[项目 README 与配置](https://github.com/mwnickerson/bloodhound_mcp)、[SpecterOps BloodHound Skill 文档](https://github.com/SpecterOps/skills/blob/main/plugins/bloodhound/README.md)。
- 评分依据：实用价值 5（补足 AD 图关系和路径分析）；接入匹配 4（stdio 已支持）；成熟度 3（有测试/文档但为社区项目）；安全 2（敏感数据出境和写操作风险需实验室隔离）；许可成本 4（MCP 开源，CE 需自行运行维护）。

#### 3. Caido MCP Server：暂不试点

- 能力：通过 Caido 访问 HTTP 历史、搜索、请求重放、批量发送、Fuzz、竞态测试、Scope、Finding 和工作流；stdio 接入，有 MIT 许可的 MCP 服务端。
- 与 ARTEX 的差异：请求历史和重放是有价值的人工测试工作流，但 ARTEX 已有 Browser MCP、流量捕获和自定义 HTTP 工具；额外价值取决于团队是否已经把 Caido 作为主代理。
- 安全与维护：默认在工具输出中脱敏 Authorization、Cookie 等敏感头，并提供 OAuth 或本地访问令牌；但工具也能执行请求、Fuzz、修改 Scope/项目/规则及 Findings。不能只按只读工具评估其权限。项目持续发布，2026-10-29 有 v4.4.0；但 MCP 服务依赖 Caido 应用，其官方 FAQ 表明 Caido 并非开源，Basic 免费计划和付费计划能力不同。
- 成本与结论：MCP 服务端 MIT；Caido 应用需要单独部署并受其计划限制。已有 Caido 环境的团队可以单独评估，但对当前 ARTEX 使用场景，重叠带来的维护成本高于增量收益，低于 75 分。
- 来源：[MCP 服务功能、认证和脱敏说明](https://github.com/c0tton-fluff/caido-mcp-server)、[发布记录](https://github.com/c0tton-fluff/caido-mcp-server/releases)、[Caido 官方 FAQ 与计划](https://docs.caido.io/faq)。

#### 4. Kali MCP Server：淘汰

- 能力：Kali 官方包由 MCP bridge 与 Kali API server 组成，可以通过 AI 调用终端命令，包括 nmap、nxc、curl 和 gobuster 等。
- 与 ARTEX 的差异：ARTEX 已经有 nmap/自定义工具和内网测试 Skills；Kali MCP 的主要新增能力是把 Linux 终端命令暴露给 Agent，并无清晰、受限的专有能力可补足当前缺口。
- 安全与接入：终端命令入口使 MCP 权限面远大于单一扫描工具。Kali API server 默认绑定本机地址，但部署到 ARTEX 容器后仍需额外配置主机间通信；当前资料没有证明它提供细粒度命令 allowlist。即使其 bridge 使用 stdio，后端 API server 也不是 ARTEX 已确认支持的标准远程 MCP endpoint。
- 成本与结论：Kali 包本身不需商业订阅，但需要部署 Kali 环境并维护其 API server。因能力重复、命令权限宽且传输组合需额外验证，安全与接入门槛均未达试点线。
- 来源：[Kali 官方工具说明](https://www.kali.org/tools/mcp-kali-server/)、[Kali 打包仓库](https://gitlab.com/kalilinux/packages/mcp-kali-server)。

### 试点建议与验收条件

建议最多按以下顺序安排两个试点，不代表本轮已经安装或启用：

1. ZAP：使用隔离的 Web/API 靶场和 OpenAPI 描述，先确认 ARTEX 能识别该 MCP 的 HTTP transport；若不能识别，不加适配层，记录为不满足准入条件。连接后先运行 Spider 与被动扫描，再按明确规则运行有限的 Active Scan，并在网络层将扫描实例出口限制到靶场地址。确认能通过 ARTEX 配置完成 MCP 认证、启动/停止扫描并读取 Alert 与原始请求证据。由于当前 MCP 插件不直接支持目标应用认证，不把已认证业务路径作为本轮验收条件。
2. BloodHound：只有在已有隔离 AD 实验环境且能用合成数据时启动。先限制为查询/图分析场景，人工核对输出；使用已审批的数据处理模型，优先本地模型，并记录工具集中写操作是否能由目标权限或单独实例有效约束。任何一步不能满足时，停止该试点。

两个试点均需验证：

- MCP 只分配给指定 Agent，其他 Agent 无法发现或调用。
- 工具调用、失败和取消状态可追踪；长时间扫描可查询并停止；超时、进程退出和重连不会遗留不可控任务。
- 输出保留目标、时间、扫描/查询标识和原始证据引用，人工复核后能支持 ARTEX 资产、事实或漏洞记录，不要求自动导入。
- 限定范围、凭据、TLS 校验和数据留存符合测试环境约束。
- 任何需要增加 API、数据库、Agent 接口或按工具细分授权的需求记为后续开发缺口，不在该试点中临时修改。

### 淘汰与暂缓项汇总

- Caido：已有 ARTEX 流量与请求能力覆盖主要场景；仅当团队已在用 Caido 且出现明确重放/竞态测试缺口时重新评估。
- Kali MCP：远程终端命令权限过宽，与现有内置工具和 Skills 重复；不建议接入 ARTEX Agent。
- 未把商业托管 MCP 纳入候选：本次范围内没有发现必须依赖托管服务才能弥补的能力缺口；优先自托管也有利于控制授权数据边界。

## 本轮范围确认

本轮完成候选调研、评分和试点建议，未安装、启用或分配 MCP；未修改 API、数据库或 Agent 接口。试点需另行安排并保持在隔离、授权环境中。
