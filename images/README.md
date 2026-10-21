# 工具包构建产物

README 提到的 `images/tools.tar.gz` 由 GitHub Actions 的 **tools-bundle**
workflow 生成，不把第三方二进制提交进 Git。

下载成功运行的 `tools-linux-amd64` artifact，将 `tools.tar.gz` 与
`tools.tar.gz.sha256` 放在本目录。Tag Release 也会附带这两个文件。

完整的构建、校验、解压、Docker 路径及 Python 工具说明见
[packaging/TOOLS.md](../packaging/TOOLS.md)。

当前包提供 14 项工具/资源，另 3 项 Python venv 工具明确保持外部安装。
