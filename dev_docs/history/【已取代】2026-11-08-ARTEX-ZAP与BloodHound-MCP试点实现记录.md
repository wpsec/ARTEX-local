# 【已取代】ARTEX ZAP 与 BloodHound MCP 试点实现记录

> 历史试点记录，描述 2026-11-08 至 2026-11-11 的实现与验收状态，不代表当前默认部署。BloodHound 默认集成已于 2026-11-12 移除；当前结构见[移除说明](【已完成】2026-11-12-BloodHound默认集成移除实现说明.md)。

## 试点阶段的部署模型

BloodHound 默认集成试点期间，Compose 曾配置 ARTEX、ARTEX PostgreSQL、BloodHound CE、BloodHound PostgreSQL 和 Neo4j。BloodHound UI 仅发布到宿主机 `127.0.0.1:18080`；两种数据库和 ZAP MCP listener 均不发布宿主机端口。

- BloodHound MCP 随 ARTEX 镜像安装，通过 stdio 子进程连接 Compose 中的 CE 实例。CE、应用 PostgreSQL 与 Neo4j 使用独立服务和数据卷。
- ZAP `2.17.0` 与 MCP Integration `0.4.0` 随 ARTEX 镜像安装。默认 `ARTEX_ZAP_ENABLED=true`；ARTEX 进程启动和监控 ZAP 子进程，不创建 ZAP Compose service。可在 `.env` 设为 `false` 以关闭。
- ZAP MCP listener 使用 `127.0.0.1:8282`，Compose 不发布该端口。ARTEX 在 ZAP listener 就绪后才继续启动，避免首次工具发现时连接被拒绝。

## 试点期间的配置与启动

`./install.sh` 的 Docker 安装会为 ARTEX PostgreSQL、BloodHound 管理员、BloodHound PostgreSQL 和 Neo4j 生成随机凭据，并将根目录 `.env` 权限设为 `0600`。手动部署时，从 `.env.example` 复制并为这四个密码填写各自唯一的随机值。

启动默认部署：

```sh
docker compose up -d
```

本地开发镜像与完整 BloodHound Compose 一起运行时，合并使用本地覆盖文件：

```sh
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

Docker entrypoint 在 ARTEX 启动前生成临时 ZAP key；该 key 不需要写入 `.env` 或 MCP 表单。BloodHound 首次就绪时，entrypoint 使用 `.env` 中的管理员凭据创建 API token，保存到 `data/bloodhound-mcp-token.json`（容器内权限 `0600`），只将 token 注入 ARTEX 运行环境。若 CE 图数据库为空，会自动导入官方合成样本；已有域数据时跳过导入。首次初始化默认等待 60 秒，可用 `ARTEX_BLOODHOUND_INITIAL_DELAY_SECONDS` 调整。

第一次部署期间 ARTEX 会等待 BloodHound CE API 可用（最多 5 分钟）及初始分析完成。若自动初始化失败，ARTEX 仍会启动并在日志中说明失败阶段；BloodHound MCP 在修复后可从管理页刷新工具。

默认数据库会插入 OWASP ZAP 与 BloodHound MCP 记录，设为启用并授权给内置 Agent。播种仅执行一次；已有同名记录、用户可见性选择和后续禁用/删除均不会被种子覆盖。Compose 默认不开放 BloodHound 数据库端口；BloodHound Web UI 绑定 `127.0.0.1:18080`。

ZAP MCP URL 为 `http://127.0.0.1:8282`，Authorization header 使用 `${ARTEX_MCP_SECRET_ZAP_KEY}` 引用。ARTEX 将密钥写入权限为 `0600` 的临时配置文件后启动 ZAP，不把密钥放入进程参数；临时 home 目录权限为 `0700`，ZAP 退出后临时文件与 home 目录会清理。ZAP 以 `WARN` 日志级别启动，ARTEX 对转发的 stdout/stderr 再做流式密钥脱敏。

MCP Integration add-on 仍标记为 alpha。构建会校验 ZAP 版本 `2.17.0` 与 add-on `0.4.0`；上游变化后需审查并显式更新版本。

## BloodHound 试点实现

BloodHound MCP 以 stdio 子进程运行，不需要单独启动 MCP server 容器。ARTEX 镜像在构建阶段从上游固定提交 `cdb17097e761c8a8622cb93bc3ba49a9e150bb6e` 拉取源码，并执行 `uv sync --locked`。升级时需审查并更新固定提交。

该上游使用 GPL-3.0。BloodHound MCP 作为独立程序运行，未链接进 ARTEX 二进制；镜像保留对应提交的源码和 `LICENSE` 于 `/opt/bloodhound-mcp`。许可证与来源索引位于镜像 `/app/THIRD_PARTY_NOTICES.md`。ZAP 镜像目录 `/opt/zap` 保留 Apache 2.0 许可证全文 `ApacheLicense-2.0.txt` 及 ZAP `2.17.0` 的 `LEGALNOTICE.md`。

默认 BloodHound MCP 连接 Compose 服务名 `bloodhound:8080`，使用内部 HTTP 通信和运行时生成的 token。官方 `ad_sampledata.zip` 只包含合成 AD 数据，放在 `third_party/bloodhound/` 并在构建镜像时复制进去。

该上游 MCP 包含图查询、写入和文件上传工具。默认授权给内置 Agent，适合单用户本地试用；BloodHound 数据服务只初始化合成样本。导入真实 AD 数据前确认授权范围，图查询和工具输出可能进入 LLM 上下文。

## 凭据引用

MCP 配置中的 `env` 按传输方式传递：stdio 作为子进程环境变量，HTTP/SSE 作为请求头。凭据值使用 `${ARTEX_MCP_SECRET_<NAME>}` 引用；ARTEX 在建立连接时从自身进程环境读取引用值，不把解析值写回 MCP 记录。普通字面量配置仍然兼容，现有记录不会自动迁移。

当前部署假设是单用户本地使用。环境变量引用避免凭据值进入数据库配置和 MCP 列表 API，但不是本机秘密存储；它不防护本机账户或 ARTEX 进程已被控制。使用者可以按本机风险接受度选择引用或现有字面配置，不增加秘密管理服务或轮换系统。

## 历史集成验证记录

- Compose 服务列表确认仅包含 `artex` 与 `postgres`。候选 ARTEX 镜像在临时 ARTEX+PostgreSQL 两容器环境启动成功；ARTEX 健康检查正常，ZAP MCP initialize 握手返回 `0.4.0`，`tools/list` 返回 17 个工具。
- 嵌入式 ZAP 对错误密钥返回 `401`；密钥配置文件权限为 `0600`。在容器内的静态合成靶场完成 Spider 启动、状态查询和停止。
- 后续容器复验确认 ARTEX 健康检查正常、`tools/list` 返回 17 个工具；合成密钥不在 ARTEX 容器日志或 ZAP `.log` 文件中。临时 home 为 `0700`；无宿主机端口映射，其他容器无法访问 ZAP loopback listener。还在该合成靶场运行受限 Active Scan。
- BloodHound 固定提交和 `uv.lock` 依赖构建成功。stdio 握手、工具发现、合成域列表和最短路径只读查询通过；测试使用的是本地 API mock，不是真实 BloodHound CE/Enterprise，因此仍需在实际授权实验实例确认版本兼容性。
- Go 1.26.10 下，ARTEX 启动/凭据相关定向测试、`mcphttp` 测试、MCP 预设 Playwright 回归和 Compose 配置检查通过。全 Git 跟踪 Go 包测试使用临时 PostgreSQL 17 运行，但未全绿：`agent` 的图谱范围断言失败；`server` 最新复跑失败于既有交付报告测试 `TestFindingDeliveryReportIsolationAndEvidenceVersion`。当前交付报文保留原始凭据，而另一既有单测要求报文脱敏，相关实现和测试不在 MCP 集成改动范围。直接在本机执行 `go test ./...` 还会扫描 `data/tasks` 中未跟踪的历史任务源码；干净 CI checkout 不包含这些文件。
- BloodHound 官方 CE 安装文档列出最低 8 GB RAM，并提醒低内存启动分析期间可能 OOM。本机 Docker VM 上限为 7.75 GiB，现有 ARTEX/PostgreSQL 占用约 442 MiB，剩余约 7.32 GiB；没有停止既有服务来腾挪资源。真实实例验收需要单独提供仅含合成数据的授权实验环境。
- `GET /api/mcp` 管理 API 回归通过：保存的 env 引用原样返回，测试中设置的合成环境变量值未出现在响应中；新配置默认禁用且未授权给任何 Agent。Playwright 预设用例也通过 API mock 验证保存内容。
- `connectMCP` 的 Streamable HTTP 本地集成回归通过：HTTP mock 校验 Authorization 收到解析后的合成值，并返回 MCP initialize 与 tools/list 响应。
- ScopeSentry 状态接口回归通过：在临时 PostgreSQL 中配置凭据引用，HTTP mock 校验 `X-API-Key`，接口报告数据源可达；测试后恢复配置并移除临时数据库。
- 本轮集成验证使用的临时容器已停止并自动移除；既有本地 ARTEX 与 PostgreSQL 容器未重启或替换。
- 2026-11-11 提升权限后使用 Go 1.27.1 重跑 `go test -p 1 ./server -count=1`，其余 server 测试通过，唯一失败仍是 `TestFindingDeliveryReportIsolationAndEvidenceVersion`，断言 `query-secret` 不得出现在交付报文中；同测试单独运行可复现。`deliveryHTTPPacket` 直接组合原始 HTTP 头和正文，且报告流程会将该报文交给 LLM 并返回 API。另一个既有单测 `TestDeliveryReportUsesProofPacketAndPreservesCredentials` 却要求保留原始凭据，表明两处既有预期不一致。MCP 集成未修改该路径，本轮不扩大范围改动交付报告。

## BloodHound CE 实例验收（2026-11-11）

按用户授权使用 SpecterOps 官方合成 AD 样本启动独立 CE Compose。BloodHound API/UI、PostgreSQL、Neo4j 三个服务正常运行；MCP stdio 初始化和工具发现通过，返回 13 个工具。域列表返回 5 个域，包含 3 个已采集域及额外可见域。只读最短路径查询成功展示从普通用户 `TARGET@PHANTOM.CORP` 到 `ADMINISTRATOR@PHANTOM.CORP` 的权限链。没有通过 MCP 调用上传、写入或删除工具；导入样本所用临时 API token 已撤销。

ARTEX/PostgreSQL 与 CE 同机运行时，以 4 个并发请求执行 20 次 BloodHound 最短路径 API 查询，均成功。ARTEX `/api/health` 的 60 次响应 p50 为 2.6 ms、p95 为 7.1 ms、最大 15 ms；停止 CE 后同样采样的 p50 为 4.1 ms、p95 为 5.3 ms、最大 7.1 ms。该健康接口采样没有显示明显退化，不能代替真实 Agent 或扫描负载基准。

样本导入后空闲时 CE 三容器合计约 1.1 GiB；并发查询后一次资源采样为 CE API/UI 2.21 GiB、Neo4j 911 MiB、CE PostgreSQL 63 MiB。同一时点 ARTEX 35 MiB、原 PostgreSQL 149 MiB，五个容器合计约 3.34 GiB；Docker VM 限额为 7.75 GiB。SpecterOps 文档列出 CE 最低主机规格 8 GB RAM、4 核，超过 5 万用户的大型环境建议 96 GB RAM、12 核；8 GB 是主机最低规格，不是固定的单容器内存预留。本结果仅适用于小型合成样本，数据量与并发图查询会影响占用。

历史评审结论建议维持默认禁用并由使用者单独部署 CE；该决定后来一度调整为默认 Compose 提供 CE 和合成样本。该默认集成已于 2026-11-12 移除。历史资源数据仍可用于参考；完整试点记录见[实施计划历史](【已取代】2026-11-08-ARTEX-ZAP与BloodHound-MCP集成计划.md)。

## 当时的默认 Compose 验收（2026-11-11）

- 使用当前源码构建 Linux/arm64 ARTEX 镜像后启动默认 Compose；ARTEX、ARTEX PostgreSQL、BloodHound CE、CE PostgreSQL 和 Neo4j 均运行，数据库健康检查通过。`GET /api/health` 返回 200。
- BloodHound entrypoint 成功创建并保存 MCP token（文件权限 `0600`），向空白 CE 图导入官方合成样本。重启 ARTEX 后复用 token 和样本标记，没有再次等待首次初始化或重复导入。
- MCP 工具缓存显示 ZAP 17 个工具、BloodHound 13 个工具；当前数据库记录均启用，两者各对 8 个内置 Agent 可见。当前 ARTEX PostgreSQL 已有此前的 MCP 记录，因此本机验收确认的是连接、发现和可见性，不是空数据库首次播种分支的隔离验收；播种代码已编译，未运行测试套件。
- `.env` 和 token 文件权限均为 `0600`。BloodHound Web UI 只映射到 `127.0.0.1:18080`，PostgreSQL、Neo4j 和 ZAP 的 `8282` listener 未发布宿主机端口。
- 空闲时 `docker stats` 采样约：ARTEX 542 MiB、ARTEX PostgreSQL 97 MiB、BloodHound 113 MiB、CE PostgreSQL 61 MiB、Neo4j 846 MiB，合计约 1.62 GiB。该快照对应当前小型合成样本，不是资源上限；图数据和查询会增加占用。官方仍建议主机至少 8 GB 内存。
- 部署过程中保留了现有 ARTEX PostgreSQL 数据卷和 7 条任务记录；因当前本机 PostgreSQL 账号与 `.env` 不一致，已同步角色密码到本机随机配置值，未重建或清空数据卷。此前独立 CE 容器已停止但没有删除其卷。
