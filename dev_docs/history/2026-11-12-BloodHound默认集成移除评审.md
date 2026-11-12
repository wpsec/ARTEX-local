# 【已完成】BloodHound 默认集成移除评审

## 评审范围

评审默认 Compose 服务、镜像内容、安装配置、MCP 数据库播种与兼容迁移、MCP 管理页面、渗透测试 Skill 路由及用户文档。

## 结论

建议并已按用户确认移除 BloodHound 的默认集成。BloodHound 对有目标 AD 图数据的权限关系和路径分析有明确专项用途，但它不是 ARTEX 的通用自主测试基础能力。此前小型合成数据并发查询时，CE API/UI、Neo4j、CE PostgreSQL 分别采样为 2.21 GiB、911 MiB、63 MiB；空闲时三个服务合计约 1.1 GiB。数据规模、查询并发和 Docker 环境会改变实际使用量。

默认交付保留 ARTEX、PostgreSQL 和容器内 ZAP。通用 MCP 不变，用户可按需接入外部 BloodHound。

## 发现与处理

- 默认 Compose 只定义 ARTEX 与 PostgreSQL，未包含 BloodHound CE、专用 PostgreSQL 或 Neo4j；安装配置不生成相关凭据。
- ARTEX 镜像与启动入口不包含 BloodHound MCP、样本数据或自动创建 Token/导入样本的逻辑。
- MCP 管理页不再展示 BloodHound 内置预设；ZAP 预设与通用 MCP 表单保留。
- 一次性启动迁移仅删除名称、stdio transport 和命令路径都匹配旧内置 BloodHound MCP 的旧记录及其 Agent 可见性；后续创建的记录不会在每次启动时被重复匹配。
- 内网测试 Skill 不再强制要求 BloodHound MCP，因此没有该服务时仍可执行；目标数据匹配时才把外部 BloodHound 作为可选查询能力。
- 默认文档描述两容器部署，并明确旧版遗留容器与数据卷不会被本次源码变更自动清理。

## 未解决事项

旧版部署留下的 BloodHound 容器、镜像及数据卷仍需操作员另行处理。本次没有触碰这些本机 Docker 资源，也没有构建或运行测试。
