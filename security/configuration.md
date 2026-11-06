# 安全配置与兼容性

## 管理员登录与密码变更

`/api/auth/login` 对每个实际 TCP 来源每分钟允许 10 次尝试，全实例的单一管理员账号每分钟允许 100 次尝试。达到限制时返回 HTTP 429 与 `Retry-After`。限流独立于伪装门控，不信任客户端可填写的 `X-Forwarded-For` / `X-Real-IP`。反向代理后的客户端会共用代理来源的额度。窗口和来源记录保存在进程内，重启会重置。

密码变更会在同一数据库事务中替换密码、增加凭据版本并移除旧 refresh token。版本写入失败会回滚密码；并发使用同一旧密码的变更只允许一个成功。登录只会签发密码验证前捕捉的版本，避免在密码重置期间把旧密码换成新版本凭据。

初始设置仍由现有门控保护：非 loopback 监听默认开启门控，loopback 默认关闭；`ARTEX_GATE=on` / `off` 可以显式指定。使用 loopback 后端加公开反向代理时，应显式开启门控或在代理层限制初次设置访问。

## LLM 与 MCP 的凭据

测试、列模型、更新全局 LLM 和保存 profile 时，空 API key 只有在提供商、规范化后的 endpoint 和代理均未改变时才复用已存凭据。更改其中任一项需要重新填写凭据；模型、限流和思考参数等普通编辑仍可保留原凭据。官方默认 URL、常见完整 API 路径、主机名大小写和默认端口会被规范化。

本机和企业内网的 LLM / MCP endpoint 仍受支持。HTTP 客户端允许同来源的路径重定向，但拒绝跨 scheme、主机或端口转发 API key。ScopeSentry 更改 URL 时也要求重新提供 API key；现有私网连接用途保持可用。

stdio MCP 子进程只自动保留 PATH、HOME、临时目录、locale 和证书路径等运行所需的环境值。服务器的数据库、LLM 等其它环境值会在启动子进程前清空。MCP 明确配置的环境变量优先并会保留；依赖代理、特定 API key 或其它环境变量的 MCP 应在自己的环境配置中填写。此功能减少无意继承的凭据，不是进程沙箱。

## 录制代理的目标 TLS

默认验证上游目标证书。对于明确授权的自签或无效证书测试目标，可以设置 `ARTEX_PROXY_SSL_INSECURE=true` 或 `1`；未设置、`false`、`0` 和其它值均保持验证。该例外接受未验证的目标身份，应按测试范围明确选择。

## SMTP

`tls=true` 仍表示隐式 TLS，通常用于端口 465。`tls=false` 通常用于 587，默认要求服务器提供 STARTTLS；服务器不支持或 TLS 握手失败时不发送邮件正文。

明确可信且不支持 TLS 的中继可在渠道设置中开启“允许明文邮件”（`allow_insecure=true`）。这允许在对端未提供 STARTTLS 时明文投递，包括漏洞详情；已经开始但失败的 TLS 握手不会降级。更改此选项时须重新填写该渠道保存的密码。使用本机中继还须保留现有的 `ARTEX_NOTIFY_ALLOW_LOCAL=1` 配置。

## 安装与重置脚本

`install.sh` 要求先按 Docker 官方文档安装 Docker / Compose，不再下载并直接执行在线安装脚本。生成的 `config.json` 以 0600 权限原子替换；新建和复用的 `.env` 均设置为 0600。

`reset-password.sh` 只读取 `.env` 中的 `POSTGRES_USER`、`POSTGRES_DB`、`POSTGRES_PASSWORD` 字面值，文件上限 64 KiB。支持空值、普通值、单引号值和没有展开/转义的双引号值；值含空格或 `$` 时用单引号，例如 `POSTGRES_PASSWORD='literal$value with spaces'`。不会执行 shell 代码或进行 `${...}`、命令替换、反斜杠转义。使用 Compose 插值的部署应显式提供已展开的数据库参数。未知变量不能覆盖脚本的 SQL、PATH 或执行方式。

重置脚本不再输出 DSN 内容。应用日志对 PostgreSQL URL 中的密码和全部 query options 隐藏值，对 keyword / malformed DSN 输出固定遮罩。

## PostgreSQL 回归验证

安全回归使用单独的 `ARTEX_AUTH_TEST_DSN`，指向可丢弃的测试 PostgreSQL。每个用例创建并删除自己的 schema。未设置时会明确 SKIP；需要数据库行为保证的 CI 应将这些跳过视为未完成验证，而非通过。密码重置脚本的数据库用例还需要 `psql` 与测试角色创建 `pgcrypto` 的权限。
