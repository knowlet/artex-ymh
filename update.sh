#!/usr/bin/env bash
# ARTEX 更新脚本：① Docker 更新（源码重建）  ② 本地编译更新（重建二进制）
# 与 install.sh 对应：install 负责首次落地，update 负责升级到新版本。
# ARTEX 的 schema 变更在启动时执行；这不能转换 PostgreSQL 大版本的数据目录。
# Docker 更新先核对 PG_VERSION，再分别启动数据库和应用，保留现有数据卷。
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }

# ── 可选：同步仓库到最新代码（compose/脚本/本地编译源码都靠它更新）───────
sync_repo(){
  [ -d .git ] && command -v git >/dev/null 2>&1 || { warn "非 git 工作副本，跳过 git pull"; return; }
  [ "$(ask '拉取最新代码 (git pull --ff-only)? (y/n)' y)" = y ] || return
  if ! git pull --ff-only; then
    warn "git pull 未能快进（本地有改动或分支分叉）——请手动处理后重试，本次沿用当前代码"
  fi
}

# Hold the lock until this process exits. flock is released by the kernel even
# if the updater is killed. Without flock, a directory lock is removed on exit.
acquire_update_lock(){
  local lock_key lock_file
  lock_key="$(pwd -P | cksum | awk '{print $1}')"
  lock_file="${TMPDIR:-/tmp}/artex-docker-update.${lock_key}.lock"
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$lock_file"
    if ! flock -n 9; then
      info "另一个更新正在构建或部署，等待它结束后继续…"
      flock 9
    fi
    return 0
  fi
  local lock_dir="${lock_file}.d" announced=0 pid
  while ! mkdir "$lock_dir" 2>/dev/null; do
    pid="$(cat "$lock_dir/pid" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      rm -rf -- "$lock_dir"
      continue
    fi
    if [ "$announced" -eq 0 ]; then
      info "另一个更新正在构建或部署，等待它结束后继续…"
      announced=1
    fi
    sleep 1
  done
  printf '%s\n' "$$" > "$lock_dir/pid"
  # shellcheck disable=SC2064
  trap "rm -rf -- $(printf '%q' "$lock_dir")" EXIT INT TERM
}

# ── ① Docker 更新 ───────────────────────────────
update_docker(){
  # artex-ymh:local is one mutable tag. Hold the lock across the whole
  # build-and-deploy sequence so an older build cannot finish last.
  acquire_update_lock

  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
    || die "未检测到 docker / docker compose，请先用 ./install.sh 安装部署"
  [ -f .env ] || die "未找到 .env，请先运行 ./install.sh 完成首次部署"

  info "检查 PostgreSQL 数据目录与目标镜像的大版本…"
  bash scripts/check_postgres_version.sh

  # 仓库默认用 Dockerfile.source 构建 artex-ymh:local，pull_policy 为 never。
  # pull artex / ARTEX_TAG 不会更新该镜像，必须先构建成功再动运行中的服务。
  info "从当前源码重建 ARTEX 镜像…"
  docker compose build artex
  info "启动 PostgreSQL 并等待健康检查…"
  docker compose up -d --no-deps --wait --wait-timeout 120 postgres
  info "重建 ARTEX（启动时应用 schema 变更）…"
  # 防止 up artex 经 depends_on 再次重建 postgres 或其他本地定制服务。
  docker compose up -d --no-deps --no-build --pull never artex
  ok "更新完成 → http://localhost:8787"
  info "查看日志：docker compose logs -f artex"
  info "清理旧镜像（可选）：docker image prune -f"
}

# ── ② 本地编译更新 ──────────────────────────────
update_local(){
  command -v go >/dev/null 2>&1 || die "未检测到 Go（>=1.26）：https://go.dev/dl/"
  [ -f config.json ] || warn "未找到 config.json——若首次部署请改用 ./install.sh"
  ok "Go: $(go version)"

  if command -v npm >/dev/null 2>&1; then
    info "重建前端静态产物…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "重新编译内嵌单二进制…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o artex ./cmd/artex
  else
    warn "未检测到 npm：编译**不内嵌前端**的后端（前端需另跑 npm run dev）"
    CGO_ENABLED=0 go build -o artex ./cmd/artex
  fi
  ok "编译完成 → ./artex"
  warn "请重启正在运行的 artex 进程以生效（重启时会自动迁移 schema）"
}

echo "=============================="
echo "  ARTEX 更新"
echo "  1) Docker 更新（源码重建）"
echo "  2) 本地更新（go 重新编译）"
echo "=============================="
case "$(ask '选择' 1)" in
  1) sync_repo; update_docker ;;
  2) sync_repo; update_local ;;
  *) die "无效选择" ;;
esac
