# 安全修复记录

## 范围

本次处理更新接口的 CSRF、改密后的旧 JWT 撤销、工作区符号链接越界，以及审计中命中的 Next.js、sharp 和 pgx 依赖版本。

Agent 执行隔离、登录请求资源限制、自定义 HTTP 工具 SSRF、通知 SSRF 和 API Recon Skill 的 TLS 行为本轮不处理：前两项可能影响 Agent 能力或当前不值得增加限制，SSRF 守卫变更会影响现有网络工具能力，API Recon 需要人工触发。

## 实现

- Cookie 和 URL 查询参数只为安全方法提供认证；查询参数中的 token 仅接受在日志、更新、活动和 side-question SSE 路由。写请求使用 `Authorization: Bearer`，阻止跨站表单凭浏览器自动附带的 Cookie 触发变更。
- 同源 SSE 使用 Cookie，不把 JWT 放进 URL。开发环境或显式配置的跨源 SSE 仍通过 URL 传递 token，以兼容原有 `EventSource` 用法；服务端将这种方式限制在 SSE 路由。
- 修改密码前持久化轮换 JWT 签名密钥，并返回由新密钥签发的 token 给当前会话；其它已签发 token 在后续请求中失效。此实现按单个 ARTEX 服务进程运行；多副本部署需要共享的会话版本或撤销存储。
- 登录使用读锁，改密使用写锁，避免轮换密钥与保存新密码之间仍有旧密码登录并拿到新 token 的并发窗口。
- 工作区路径只保留清理后的相对路径；列目录、读取、写入、创建目录、删除、下载和上传均经 `os.Root` 执行，由根目录句柄阻止符号链接越出工作区。工作区内相对符号链接仍可访问。
- 依赖修复目标：Next.js `16.4.5`、sharp `0.35.5`、pgx `v5.12.0`。

## 兼容性与验证

- 前端 API 已通过 Bearer header 发起写请求；Next.js 页面守卫仍使用 Cookie，不影响页面路由。
- 本轮未运行测试或构建；已对 Go 文件执行 `gofmt`，`git diff --check` 通过。
