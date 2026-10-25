# 可验证的 tools.tar.gz

`images/tools.tar.gz` 是 CI 构建产物，不是需要提交到 Git 的二进制。
当前仅提供 **Linux/amd64 主机工具包**；Windows EXE 是单独的 Windows 文件，
不代表本包能在 Windows 或 Linux/arm64 主机上运行。macOS/arm64 用户应使用匹配
架构的 Linux/amd64 环境，不能直接执行这些 ELF 文件。

## 获取与安装

在 GitHub Actions 的 **tools-bundle** 成功运行中下载 `tools-linux-amd64` artifact，
将其中的 `tools.tar.gz` 和 `tools.tar.gz.sha256` 放到项目根目录的 `images/`。
合并后的版本发版流程也会将这两个文件附加到 Release；Release 的签名
`SHA256SUMS` 会覆盖工具包。普通 CI artifact 不带 minisign 签名。

先确认 artifact 来自可信的仓库、commit 和 workflow。旁边的 SHA-256 文件只检查
完整性，不是独立的来源认证；Release 用户还应验证已信任公钥的签名校验和。

```bash
# 从项目根目录执行；不要以 root 身份解压来源不明的文件。
(cd images && sha256sum -c tools.tar.gz.sha256)
# 有源码时，额外检查归档结构、内部文件哈希与文件格式。
python3 scripts/build_tools_bundle.py --verify images/tools.tar.gz
# 有既有工具时先备份；包内不含数据库、配置、密钥或其他 data 内容。
tar -xzf images/tools.tar.gz
(cd data/tools && sha256sum -c SHA256SUMS)
ARTEX_TOOLS_MANIFEST="$PWD/data/tools/tools-manifest.json" ./artex doctor
```

Compose 的 `./data:/app/data` 挂载使文件出现在容器的 `/app/data/tools/`。
需要让启动自检使用新清单时，在 artex 服务的 environment 添加：

```yaml
ARTEX_TOOLS_MANIFEST: /app/data/tools/tools-manifest.json
```

然后重建容器配置（不需要重新构建平台镜像）。单次容器内检查可以执行：

```bash
docker compose exec -e ARTEX_TOOLS_MANIFEST=/app/data/tools/tools-manifest.json artex /app/artex doctor
```

解压只提供文件，**不会注册或自动执行工具**。按 README 在“工具 → 自定义工具”
中注册 `kind=shell`，并填写执行环境中的绝对路径。不要把宿主机路径填进容器。

## 范围与运行依赖

`packaging/tools-manifest.json` 的 17 项必须全部被来源锁文件明确分类：

- 14 项随包提供：suo5、suo5-payloads（JSP/PHP/ASPX）、chisel、gogo、naabu、
  httpx、katana、fscan、mimikatz、laZagne、ligolo-agent、ligolo-proxy、peass
  （linpeas.sh / winPEASx64.exe）、penelope。
- impacket、pypykatz、nxc 按原 README 保持外部 Python 工具，需要在部署环境建立
  venv 后按上游说明安装。不要复制 CI runner 的 venv；入口脚本含绝对路径。
  它们在 bundle.json 中明确标记为 external，不生成假文件，也不冒充离线可用。
  安装后将 `tools/impacket` 指向对应 venv 的 bin 目录，`tools/pypykatz` 和
  `tools/nxc` 指向各自入口，或注册对应 venv 的绝对路径。

主机仍需满足上游运行依赖，例如 Python 3、libpcap 或浏览器，以及相应操作系统
权限。本流水线只检查文件格式和完整性，不启动监听器、不运行扫描、不验证目标
环境能力。上游版本固定不等于不存在漏洞，升级仍需审查兼容性与安全公告。

## 来源、版本与校验

`packaging/tools-sources.lock.json` 记录版本、精确下载 URL、选取的归档成员、
输出路径、权限和来源校验信息。**不解析 latest，不在构建时自动接受新哈希**。

发布附件以 SHA-256 钉住；ligolo 的 checksum 清单本身也先校验固定 SHA-256。
源文件与授权文件使用 GitHub 返回的 Git blob SHA-1 身份校验（含 Git blob
header，不是普通文件 SHA-1，也不宣称这是 SHA-256）。Mimikatz 的旧 Release
没有附件 digest，因此仅接受原部署清单已钉住的 x64/mimikatz.exe 内容；归档中
其他文件不进入产物。LaZagne 沿用原清单的 EXE SHA-256。任何不符都会失败，
不能为了让 CI 通过而删除校验。

三个 Windows EXE（mimikatz.exe、laZagne.exe、winPEASx64.exe）的固定内容均已
确认是 amd64。来源锁使用明确的 `pe-amd64` 检查：构建和独立验证都会检查
DOS/PE 签名、完整 COFF 头的边界，以及 `Machine = 0x8664`；x86、ARM64、
未知架构和截断头会失败。它不是完整的 Windows 加载器兼容性测试。依据与回归
验证见 [PE-VALIDATION.md](PE-VALIDATION.md)。

这是根据公开来源重新建立的工具包，不声称与失落的原作者交付包逐字节一致。
包内 `tools-manifest.json` 根据实际文件重新计算 SHA-256，不复用不匹配的历史
部署哈希，也不改写仓库原清单。目录项由内部 `SHA256SUMS` 覆盖。

每个上游的授权/声明文件保存在 `licenses/`，版本源码链接保存在来源锁和
`bundle.json`。这些第三方文件不是被统一重新授权成 ARTEX 的协议；再分发时
还需遵守各上游许可及对应源码提供要求。

## 本地构建与维护

```bash
python3 -m unittest discover -s scripts -p 'test_build_tools_bundle.py' -v
python3 scripts/build_tools_bundle.py --validate
python3 scripts/build_tools_bundle.py
python3 scripts/build_tools_bundle.py --verify images/tools.tar.gz
```

仅依赖 Python 3.12+ 标准库。下载缓存位于 `.cache/tools-bundle/`，缓存内容每次
仍会校验。输出采用固定排序、uid/gid、文件权限和 gzip/tar 时间戳；同一锁文件、
清单、说明文档、SOURCE_DATE_EPOCH 与压缩工具链下可重复得到相同字节。
SOURCE_DATE_EPOCH 默认 0，CI 连续构建两次并比较 SHA-256。

更新版本必须审查上游发布资产及授权文件，再明确修改锁文件并跑完整 CI。
缺文件、摘要不符、错误架构、归档路径穿越、重复成员、链接、特殊文件或超出大小
限制都会阻止发布；下载的工具永远不会在构建过程中被执行。
