# BloodHound 默认集成移除说明

## 当前部署结构

默认 Docker Compose 只启动 ARTEX 和 PostgreSQL。OWASP ZAP 与 MCP Integration add-on 仍随 ARTEX 镜像提供，由 ARTEX 在主容器内管理 ZAP 进程。BloodHound CE、其专用 PostgreSQL/Neo4j、BloodHound MCP 包、合成样本和启动引导已从默认交付移除。

通用 MCP 配置能力不变。需要 AD 图分析的用户可单独部署 BloodHound，并在系统的 MCP 页面配置外部 MCP 服务；ARTEX 不再自动创建或授权该服务。

## 旧数据库兼容

服务启动时，数据库迁移执行一次，只删除同时满足以下条件的旧内置 MCP 记录：名称为 `BloodHound`、transport 为 `stdio`，且 command 精确等于旧内置路径 `/opt/bloodhound-mcp/.venv/bin/bloodhound-mcp`。迁移同时删除对应 Agent 可见性；工具缓存按外键级联删除。仅名称相同但使用其他命令或 HTTP/SSE transport 的 MCP 服务会保留。迁移完成后不会重复匹配后续由用户创建的记录。

此次迁移不会清理历史 BloodHound 容器、镜像、Docker 数据卷或主机文件。旧版 Compose 创建的 BloodHound 容器在 Compose 文件移除服务后会成为遗留容器；操作员需要自行确认是否停止并清理。不要使用 `docker compose down -v`，它会一并删除数据库数据卷。

## 评审依据与验证边界

BloodHound 对已采集 Active Directory 图中的权限关系及攻击路径查询有专项作用，但不是 Web/API 测试的基础依赖。此前小型合成样本的并发图查询采样中，CE API/UI 为 2.21 GiB、Neo4j 为 911 MiB、CE PostgreSQL 为 63 MiB；空闲采样三项服务合计约 1.1 GiB。这些数据只描述当时的 Docker 资源快照，不代表所有数据规模的内存上限。

本次核对默认 Compose、镜像构建文件、安装配置、MCP 初始化、旧记录迁移、MCP 管理页、Skill 路由和用户文档。按仓库交付约定，本轮未启动容器、构建镜像或运行测试；交付前执行 `git diff --check` 做补丁格式检查。
