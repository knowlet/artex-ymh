# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/artex。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/artex ./cmd/artex
#   docker build -t artex:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
ARG NODE_DIST_BASE=https://nodejs.org/dist
ARG NODE_VERSION=22.23.4
# Node: official tarball + 同源 SHASUMS256 校验（与 Dockerfile.source 一致）。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && rm -rf /var/lib/apt/lists/*
RUN set -e; \
    cd /tmp; \
    curl -fsSL -o "node-v${NODE_VERSION}-linux-x64.tar.gz" "${NODE_DIST_BASE}/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.gz"; \
    curl -fsSL "${NODE_DIST_BASE}/v${NODE_VERSION}/SHASUMS256.txt" \
      | grep "node-v${NODE_VERSION}-linux-x64.tar.gz" | sha256sum -c -; \
    tar -xzf "node-v${NODE_VERSION}-linux-x64.tar.gz" -C /usr/local --strip-components=1; \
    rm -f "node-v${NODE_VERSION}-linux-x64.tar.gz"
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# 版本钉死（2026-09-13 自 npm registry 的 latest 取值）：@latest 会让同一 Dockerfile
# 在不同时间构建出不同镜像，升级时应有意识地 bump 并记录，而不是被隐式漂移。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@0.0.80 @playwright/cli@0.1.19 playwright@1.65.0 \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# 预编译好的对应架构二进制（dist/amd64/artex 或 dist/arm64/artex）
COPY dist/${TARGETARCH}/artex /app/artex
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# Reviewed offline intelligence and maintenance commands; no tool installation
# or update runs during the image build or server startup.
COPY packaging/discovery-data-manifest.json packaging/vulnerability-intel.json packaging/projectdiscovery-lock.json packaging/nuclei-cve-index.json packaging/tools-manifest.json /app/packaging/
COPY packaging/discovery/ /app/packaging/discovery/
COPY scripts/update_projectdiscovery.py scripts/install_projectdiscovery.py scripts/update_vulnerability_intel.py scripts/update_nuclei_index.py scripts/build_intel_pack.py /app/scripts/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
