# 【已取代】ARTEX 集成 ZAP 与 BloodHound MCP 实施计划

## 摘要

状态：完成。Docker 默认部署、启动初始化和本机容器验收均已完成；全仓测试未在本轮运行。

将 OWASP ZAP MCP 和 BloodHound MCP 接入 ARTEX 现有的通用 MCP 管理、工具发现及 Agent 可见性流程，不新增专属工具协议、MCP 数据模型或 Agent 接口。Docker 默认部署会启动依赖、生成本机凭据、初始化 MCP 记录并授权给内置 Agent；管理页仍可调整启用状态和可见性。

默认 Docker 运行形态包含 ARTEX、其 PostgreSQL、BloodHound CE、CE PostgreSQL 和 Neo4j。ZAP runtime 和 BloodHound MCP 都随 ARTEX 镜像提供，分别作为 ARTEX 管理的 HTTP 服务进程和 stdio 子进程运行。

## 已核对的现状与关键决定

- ARTEX MCP 记录已包含 name、transport、command、args、env、url、enabled、insecure；连接层已有 stdio、Streamable HTTP、legacy SSE，新增服务复用这些字段和通路。
- MCP 工具发现会缓存工具列表；管理页已有刷新入口；Agent 可见性按 MCP server 授权，当前不是逐工具授权。默认 MCP 只在 Docker 显式启用 bundled defaults 时自动授权给内置 Agent；自定义 Agent 和原有权限不变。
- env 的当前含义随 transport 变化：stdio 时作为子进程环境变量；HTTP/SSE 时作为请求头映射。值保存在数据库，MCP 列表 API 当前会原样返回。
- ZAP 官方说明要求其 MCP listener 仅供 localhost 上的可信客户端访问；BloodHound MCP 上游使用 stdio，要求 BloodHound CE/Enterprise 和 API 凭据。
- ARTEX 依据：server/mcpdiscover.go、server/assembly.go、db/config.go、server/server_mgmt.go、web/src/app/(main)/system/mcp/page.tsx、Dockerfile、docker-compose.yml。
- 上游依据：[ZAP MCP Integration 与安全说明](https://www.zaproxy.org/docs/desktop/addons/mcp-integration/)、[ZAP MCP 配置项](https://www.zaproxy.org/docs/desktop/addons/mcp-integration/mcp-options/)、[ZAP Marketplace 版本状态](https://www.zaproxy.org/addons/?name=marketplace)、[BloodHound MCP README](https://github.com/mwnickerson/bloodhound_mcp)、[BloodHound MCP Releases](https://github.com/mwnickerson/bloodhound_mcp/releases)。

## 实施方案

### 通用 MCP 配置与凭据

- 在现有 MCP 管理页增加“添加预设”，包含 OWASP ZAP 和 BloodHound；预设只生成普通 MCP server 配置，不另建专用页面或 API。
- Docker 默认 MCP 记录在新数据库中启用并授权给内置 Agent；播种只运行一次，不覆盖已有同名记录和权限调整。手动添加的 MCP 仍遵循 UI 的禁用、未授权默认值。
- 在 env 字段旁说明 stdio 与 HTTP/SSE 的不同用途，并为凭据增加受限的环境变量引用格式：${ARTEX_MCP_SECRET_<NAME>}。ARTEX 仅解析此前缀，解析后的值仅传给 stdio 子进程或 HTTP 请求头，不写回数据库、API 响应或日志。
- 新预设不得填入明文 Token。未配置的引用在连接或发现时明确报出缺少的变量名；不回退为字面字符串。现存 MCP 字面 env 值继续兼容，本次不迁移旧记录。

### OWASP ZAP

- ARTEX 镜像以固定版本 ZAP runtime 为构建阶段，安装并校验 MCP Integration add-on `0.4.0`；截至本计划调研日期，该 add-on 为 alpha。
- `ARTEX_ZAP_ENABLED=true` 时，由 ARTEX 进程启动和监控 ZAP 子进程；默认 Compose 将此项设为 true，使用者可配置为 false。ZAP listener 仍只监听容器 loopback。
- ZAP MCP 使用 HTTP transport，listener 仅监听 ARTEX 容器内的 `127.0.0.1:8282`，Compose 不发布该端口。仅在 loopback 通道上关闭 ZAP Secure Only，仍要求安全密钥。不得把 listener 改为可从其他网络访问。
- ZAP 预设填写 localhost 地址，Authorization header 使用 ARTEX 环境变量引用。ARTEX 启动 ZAP 时将密钥写入权限为 `0600` 的临时配置文件，不放入 MCP 记录、代码或进程参数。
- MCP 工具授权默认覆盖内置 Agent，符合单用户本地部署；ARTEX 当前不会把 MCP 工具调用自动限制到任务 scope。主动扫描仍只能用于已授权靶场，部署验收需确认 8282 不能从宿主机或其他容器访问。

### BloodHound MCP

- 构建 ARTEX 镜像时安装 uv，并使用上游锁文件构建 BloodHound MCP；上游没有正式 release，依赖必须固定到经审查的 Git commit，不允许运行时从浮动分支下载或安装。
- BloodHound MCP 上游采用 GPL-3.0。镜像保留固定提交的源码与 LICENSE，并在 `/app/THIRD_PARTY_NOTICES.md` 标明来源；它作为独立 stdio 子进程运行，不与 ARTEX 二进制链接。
- MCP 以 stdio 子进程运行，使用独立 MCP 记录。BloodHound CE/Enterprise 地址、数据和生命周期不由 ARTEX 管理；本次不把 BloodHound、Postgres 或 Neo4j 服务打入 ARTEX Compose。
- BloodHound API Token ID/Key 通过 ARTEX 进程环境传递，再由 env 引用格式交给子进程。Domain/URL 等非凭据配置留在该 MCP 记录中。
- 该 MCP 暴露图查询之外的写入及文件上传工具，当前授权粒度是整个 MCP server。只连接专用的合成数据或 AD 实验室实例；不向生产 BloodHound 实例授权。工具输出可能进入 LLM 上下文，优先使用已批准的本地模型。

## 接口、兼容与失败处理

- 不增加 MCP 专属 API、数据表或 Agent tool wrapper；复用现有 MCP CRUD、工具缓存/刷新和 Agent 可见性 API。
- 仅增加通用 env 引用解析行为。普通字面配置维持原有行为；引用缺失或变量名非法时连接失败，错误只包含引用名，不包含凭据内容。
- MCP server 禁用或未分配给 Agent 时，不向该 Agent 暴露工具。ZAP 未启用或启动失败时，不阻断 ARTEX 主服务启动；首次启动会等待 ZAP listener 就绪后再开始工具发现。ZAP 进程运行中退出时，由 ARTEX 现有启动守护逻辑重启 ARTEX 进程并重新拉起 ZAP。
- 上游升级需显式更新 ZAP 镜像/add-on 版本或 BloodHound MCP commit，并重新完成安全与兼容回归。

## 测试与验收

- 单元测试覆盖 env 引用解析、变量缺失、HTTP header 与 stdio env 的分流、字面值兼容及日志不包含解析后凭据。
- API/UI 测试确认两个预设生成普通 MCP 配置、初始不授权 Agent、启用后可发现并刷新工具；配置读取不返回解析后的密钥。
- ZAP 集成测试使用隔离的未认证 API 靶场，验证 tools/list、信息查询、Spider、扫描状态和停止操作；确认 listener 只在共享 loopback 可访问，宿主机与其他容器不可访问。
- BloodHound 集成测试使用合成数据实例，验证 stdio 启动、工具发现、域信息和攻击路径查询；不调用写入/上传工具，不使用生产数据。
- 兼容回归覆盖已有 stdio、HTTP、SSE MCP、ScopeSentry 同步以及未使用 env 引用的旧 MCP 配置。
- 验收条件：默认 Docker 全新部署自动获得两个 MCP、内置 Agent 可见性和工具缓存；两者能按原生传输发现并调用工具；BloodHound token 不落入 MCP 配置/API/日志；ZAP 不可从外部网络访问；主动扫描仅用于明确授权范围。

## 范围与假设

- 默认 Docker 部署提供 BloodHound CE 和合成样本，供开箱体验；非 Docker 部署不会播种 bundled MCP 默认项。外部 BloodHound 实例接入可继续使用通用 MCP 配置。
- 风险模型按单用户本地部署，不按多租户隔离设计。`${ARTEX_MCP_SECRET_<NAME>}` 是可选的环境变量引用，用于避免该引用对应的凭据被写入 MCP 配置/API 响应；它不是本机秘密存储，也不保护已被控制的本机账户或进程。普通字面 env 仍兼容，使用者可按本机风险接受度决定是否使用引用。
- ZAP MCP 仍为 alpha；BloodHound MCP 为社区项目。上游每次升级均需固定版本并重新审核。
- 不增加逐工具授权、MCP 调用的任务 scope 强制校验或自动导入漏洞/资产数据；试点输出由人工核实后记录。
- 计划实施涉及 MCP 配置 UI、MCP 连接/凭据解析、Dockerfile、ARTEX 启动生命周期和对应回归测试；不改变其他 Agent、API、数据库业务接口。

## 实施记录（2026-11-08）

- 已在 MCP 管理页增加 ZAP 与 BloodHound 预设，保存时默认关闭；沿用现有 Agent 可见性授权。
- 已在 stdio、HTTP、SSE 连接以及 ScopeSentry HTTP 同步路径解析 `${ARTEX_MCP_SECRET_<NAME>}`。解析值只传给 MCP 子进程环境或 HTTP 请求头；缺失和格式错误返回不含凭据的错误。原有字面 env 配置保持兼容。
- ARTEX 镜像安装固定版本 uv `0.13.7`，从 BloodHound MCP 上游固定提交 `cdb17097e761c8a8622cb93bc3ba49a9e150bb6e` 获取源码，并运行 `uv sync --locked`。
- 补充第三方许可证说明：BloodHound MCP 上游 GPL-3.0 源码及 LICENSE 保留在镜像 `/opt/bloodhound-mcp`，并将来源和许可写入镜像 `/app/THIRD_PARTY_NOTICES.md`；ZAP 上游许可证/NOTICE 随 `/opt/zap` 保留。
- 按两容器部署要求修订 ZAP 运行形态：ZAP `2.17.0` 和 add-on `0.4.0` 被安装进 ARTEX 镜像，不再声明 ZAP Compose service。ARTEX 通过 `ARTEX_ZAP_ENABLED=true` 控制是否启动 ZAP 子进程；HTTP listener 仅使用容器内 loopback `127.0.0.1:8282`。
- ZAP 安全密钥通过 `-configfile` 指向权限为 `0600` 的临时配置文件传递，不出现在 ZAP 命令行参数中；临时目录在子进程关闭后清理。
- 已补充开发配置文档和 MCP 预设 Playwright 回归。

验证：Go 1.26.10 下的 ARTEX 启动/凭据定向测试、`mcphttp` 测试、MCP 预设 Playwright 测试、Compose 配置检查和 `git diff --check` 通过。全 Git 跟踪 Go 包测试使用临时 PostgreSQL 17 运行，但未全绿：失败在既有 Agent 图谱范围断言与 server 测试异步清理。直接在本机执行 `go test ./...` 还会扫描 `data/tasks` 中未跟踪的历史任务源码；干净 CI checkout 不包含这些文件。最终候选 ARTEX 镜像 `artex:iteration-dev-mcp-check` 构建成功；Compose 配置只列出 `artex` 和 `postgres` 两个服务。临时双容器环境中，ARTEX 健康检查正常，内置 ZAP 握手返回 add-on `0.4.0`，`tools/list` 返回 17 个工具；错误密钥返回 `401`，密钥临时配置文件权限为 `0600`。在 ARTEX 容器内的静态合成靶场验证 Spider 启动、状态查询和停止。BloodHound 固定提交和 `uv.lock` 依赖已构建；此前通过 ARTEX API 发现 13 个命名空间工具，并使用本地合成 API mock 完成域列表与最短路径只读查询。没有调用 BloodHound 写入、上传或删除工具。真实 BloodHound CE/Enterprise 实例尚未验证；API mock 不能证明真实实例版本兼容性。临时容器均已停止并自动清理，现有 ARTEX/Postgres 容器未重启或替换。

## 后续验证记录（2026-11-11）

- 修复 ZAP 子进程输出可能泄露 MCP 安全密钥的问题：stdout/stderr 使用流式脱敏 writer，ZAP 日志级别设为 `WARN`。单测覆盖跨多次写入的密钥片段；候选镜像实测 ARTEX 容器日志和 ZAP `.log` 文件均未出现合成密钥。
- 候选镜像健康检查通过；ZAP `initialize` 与 `tools/list` 成功返回 17 个工具，错误密钥返回 `401`。安全密钥只在权限为 `0700` 的临时 ZAP home 与 `0600` 的临时配置文件中供运行时读取，关闭时清理；命令行仅出现配置文件路径。容器没有发布端口，宿主机端口映射为空；另一容器访问 `127.0.0.1:8282` 被拒绝。
- 使用 ARTEX 容器内的静态合成靶场完成 Spider 和受限 Active Scan；先前候选构建已验证扫描状态、停止操作及历史查询。扫描没有触及外部目标。
- MCP 预设 Playwright 用例通过（1/1）；`npx tsc --noEmit`、静态前端构建、ARTEX 与凭据定向 Go 测试、`mcphttp` 测试通过。MCP 管理页 Biome 检查仍报告既有 13 项样式/可访问性诊断，未做无关重排。
- 全 Git 跟踪 Go 包在临时 PostgreSQL 上顺序运行后，`agent` 的 `TestGraphOverviewExpandsAssociatedCompanyScope` 因图谱覆盖数据缺少预期 `scope` 字段失败。此前将 `server` 包失败归因于异步测试清理；2026-11-11 提升权限后复跑发现实际失败为 `TestFindingDeliveryReportIsolationAndEvidenceVersion`，见下方追加记录。并行运行时曾额外出现数据库竞争失败，顺序运行未复现。
- 新增管理 API 回归：通过真实 `/api/mcp` 写入环境变量引用，并在测试进程中设置合成值；读取 MCP 列表确认只返回引用、未返回解析值，同时确认新配置默认禁用且没有 Agent 可见性记录。`go test ./server -run '^TestMgmtAPI$' -count=1` 通过。
- 新增 `connectMCP` Streamable HTTP 回归：本地 MCP mock 要求 Authorization 中包含测试进程解析出的合成值，再完成 initialize 与 tools/list。`go test ./server -run 'TestConnectMCPHTTPResolvesSecretAsHeader|TestResolveMCPEnv' -count=1` 通过。
- 新增 ScopeSentry 状态接口回归：临时 PostgreSQL 中配置 env 引用，本地 MCP mock 校验 `X-API-Key` 后返回 initialize/tools/list；`/api/sync/scopesentry/status` 报告 configured、enabled、reachable 均为 true。与管理 API、Streamable HTTP 用例一起通过：`go test ./server -run 'TestScopeSentryStatusResolvesSecretHeader|TestMgmtAPI|TestResolveMCPEnv|TestConnectMCPHTTPResolvesSecretAsHeader' -count=1`。
- MCP 预设 Playwright 用例使用 API mock 验证 UI 保存的 ZAP/BloodHound 配置默认禁用且未分配 Agent；它不是端到端连接真实后端的测试。
- 本机没有 BloodHound CE/Enterprise 容器或镜像。BloodHound MCP 仍只用本地 API mock 做了 stdio、工具发现和只读查询验证，因此真实 CE/Enterprise API 兼容性仍未验收。该验证需要单独提供已授权且仅含合成数据的实例；[BloodHound 官方 CE 安装文档](https://bloodhound.specterops.io/get-started/custom-installation)列出最低 8 GB RAM，并提醒低内存启动分析时 API 请求可能导致容器 OOM。当前 Docker VM 上限为 7.75 GiB，已有 ARTEX/PostgreSQL 占用约 442 MiB，余量约 7.32 GiB；不停止现有服务时没有足够余量再部署 CE。
- 本轮新增的临时 ARTEX、靶场及 PostgreSQL 验证容器已停止并自动移除；既有 `artex-local` 服务未重启、替换或访问其数据。
- 2026-11-11 在允许本机 loopback 的环境中用临时 PostgreSQL 17 顺序重跑 `go test -p 1 ./server -count=1`，仅 `TestFindingDeliveryReportIsolationAndEvidenceVersion` 失败：交付报文包含 `query-secret`。单独运行同一测试可复现。`deliveryHTTPPacket` 当前直接拼接录制的原始头和正文；该路径随后把报文传入报告 LLM，并将报文放进 API 响应。与此同时，未修改的 `TestDeliveryReportUsesProofPacketAndPreservesCredentials` 明确断言原始凭据应保留，两个既有测试的脱敏期望互相矛盾。相关交付报告代码和测试不属于本计划改动；因此不把此失败归因于 MCP 集成，也不在本计划内擅自改变报文行为。

## 真实 BloodHound CE 验收与资源评估（2026-11-11）

- 按用户授权，暂时停止原 ARTEX/PostgreSQL 后启动独立 BloodHound CE Compose；使用 SpecterOps 官方 AD 合成样本。CE API/UI、PostgreSQL、Neo4j 三项服务仅绑定本机临时端口，未使用生产或真实域数据。测试镜像为 `latest`，image ID：`sha256:47a21323d05185b284fff799c2b96bcc1d110f06f45b190f7ad83e69ef5e0d68`。
- 上游 MCP stdio 初始化与 `tools/list` 成功，发现 13 个工具；`domain_info(list)` 返回 5 个域，符合官方样本包含 3 个已采集域和额外可见受信域的说明。
- 只读 `graph_analysis(shortest_path)` 从普通样本用户 `TARGET@PHANTOM.CORP` 到 `ADMINISTRATOR@PHANTOM.CORP` 成功，展示 Domain Users 成员关系、对主机的管理权限及目标账号会话所在主机。另以 4 个并发请求执行 20 次只读路径 API 查询，全部成功，响应 p50 为 23 ms、p95 为 77 ms。未通过 MCP 调用上传、写入或删除工具；导入样本所用 API token 已撤销。
- 恢复 ARTEX/PostgreSQL 后，在 CE 路径查询期间采样 ARTEX `/api/health` 60 次，均返回 200，p50 为 2.6 ms、p95 为 7.1 ms、最大 15 ms；停止 CE 后同样采样 60 次，p50 为 4.1 ms、p95 为 5.3 ms、最大 7.1 ms。该轻量健康接口没有显示明显退化，但不能代表真实 Agent 或扫描负载下的延迟。
- 并发查询后的一次 Docker 资源采样：CE API/UI 2.21 GiB、Neo4j 911 MiB、CE PostgreSQL 63 MiB；同期 ARTEX 35 MiB、原 PostgreSQL 149 MiB，五个容器合计约 3.34 GiB。样本导入后空闲采样约 1.1 GiB。Docker VM 限额为 7.75 GiB；这些是小型合成样本的实测快照，不构成不同数据规模的上限承诺。
- [SpecterOps CE 文档](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart)给出的最低主机规格为 8 GB RAM、4 核；超过 5 万用户的大型环境规格为 96 GB RAM、12 核，并提醒启动图分析期间低内存可能 OOM。8 GB 是 CE 部署主机的最低规格，不是 Compose 为 CE 固定预留的容器内存；ARTEX 不会因此自动多占 8 GB。实际占用随域规模、导入和并发图查询变化。
- 历史结论：BloodHound 对基于已采集 AD 图数据的权限关系、横向移动和提权路径分析有实际增益；本次路径结果验证了用途。它不提供通用 Web 漏洞扫描能力。按本机评估当时建议保留为默认禁用、由用户提供实例并按需授权的可选 MCP；这不再代表当前部署决定。测试 CE 已正常停止，原 ARTEX/PostgreSQL 已恢复；临时 CE 数据卷保留，未删除。

## 默认 Docker 部署改造（2026-11-11）

按“GitHub 下载后默认能直接使用”调整原计划：Compose 默认启动 CE 及独立数据库，安装脚本生成本机随机密码并保护 `.env` 权限；ARTEX entrypoint 自动创建 MCP API token、空图数据时导入官方合成样本，并在启动环境中提供凭据引用。新数据库自动播种 ZAP/BloodHound MCP 并授权给内置 Agent；播种一次后尊重用户后续修改。ZAP 默认启动且 ARTEX 在 listener 就绪后才启动服务发现。BloodHound UI 仅绑定 loopback，图查询内存上限默认设为 1 GiB。该改造替代原“两容器、手动添加、默认不授权”的方案。

## 后续决策：移除 BloodHound 默认集成（2026-11-12）

经用户评审并确认，从 ARTEX 默认交付中移除 BloodHound CE、专用 PostgreSQL/Neo4j 服务、BloodHound MCP 二进制、合成样本和启动时 token/样本初始化。BloodHound 的 AD 图查询对已有目标数据有专项价值，但不是多数本地部署的常用基础能力；其默认部署增加三项容器服务、初始化步骤和资源占用。此前小型合成样本并发图查询时测得 CE API/UI 2.21 GiB、Neo4j 911 MiB、CE PostgreSQL 63 MiB；空闲时三者合计约 1.1 GiB。该数据仅代表当时的测试样本与负载。

当前默认部署恢复为 ARTEX 与 PostgreSQL 两个容器，ZAP 仍作为 ARTEX 容器内进程运行。通用 MCP 配置继续保留，用户可自行连接外部 BloodHound。升级时仅清除数据库中 command 精确匹配旧内置 MCP 路径的默认记录和 Agent 可见性；不会因显示名称相同而删除用户的其他 MCP 配置。

此仓库改动不停止已运行的旧 BloodHound 容器，也不删除本地镜像、Docker 数据卷或用户数据。旧 Compose 部署留下的容器和卷需要使用者另行决定是否清理。
