# 更新通道

在「系统配置 → 版本与更新」选择更新通道。选择立即重新检查，保存在目前浏览器，
并同步同一浏览器的其他分页与顶栏提示。手动「检查更新」会略过该通道的缓存。

| 通道 | 查询目标 | 没有 Release 时 |
| --- | --- | --- |
| 正式版（默认） | GitHub 最新正式 Release；排除预发布、草稿 | 显示一般提示，可改选 main |
| Nightly / 预发布 | 最新发布的 prerelease，或标签为 `nightly` / `nightly-*` 的非草稿 Release | 显示尚未发布 nightly，可改选 main |
| Main 最新提交 | `knowlet/artex-ymh` 的 `main` 当前提交 | 直接显示提交、时间、变更及该提交的源码下载 |

Nightly 依发布时间选取并将标签解析为完整提交 SHA，不把可移动的 `nightly` 标签
当作固定版本。Nightly 与 main 的源码下载链接都锁定检查所得的提交。
不同通道的结果、错误、缓存时间与并发请求各自隔离。无 Release 缓存 30 分钟；
真正的查询错误缓存 2 分钟，取消的请求不覆盖已有缓存。

Nightly/main 利用 Go 构建内的 `vcs.revision` / `vcs.modified` 判断提交是否相同。
没有完整 VCS 信息、或包含未提交改动时，会明确显示无法比较，不显示「已是最新」。
不同提交仅表示目标不同，不保证其是当前分支的后继；请先查看目标变更。

## 升级方式

Nightly 与 main 提供目标信息与原始码下载，需要自行编译、备份后替换部署。
可在新的 Git checkout 检出页面显示的完整提交，再沿用项目的 `build.sh` 流程。
带 `.git` 的干净 checkout 可让 Go 记录提交信息；原始码 ZIP 本身不包含 `.git`。

此 fork 的既有独立签名发布链尚未完成审核，`selfupdate.InstallEnabled` 仍为 false；
选择通道不会开启二进制下载、暂存、替换或自动重启。Nightly/main 额外固定为
`source_only: true`，即使未来正式版安装策略改变，也不会隐式安装源码目标。

## API

`GET /api/update/check?channel=stable|nightly|main&force=1`；省略 `channel` 等同 stable。
其他值返回 400，不接受任意仓库、分支或更新 URL。

响应增加 `channel`、`source_only`、`release_status`；源码通道另外返回 `target_commit`、
`current_commit` 与 `source_url`。无 Release 时 `release_status=no_release`，说明在
`message`，没有 `error`，保留旧 `error_code=no_release` 供旧客户端识别。
无权限、不可见仓库、限流、无效元数据与引用缺失仍是各自的真实错误。

## 验证边界

自动测试使用固定 HTTP transport 与构建信息 fixture；不发布 nightly、操作部署、
启动付费模型、扫描外部目标或替换执行文件。正式浏览器交互与部署升级另行验收。
