# Sourced by update.sh and install.sh. Both publish the mutable artex-ymh:local
# tag on one Docker daemon. The lock is a network on that daemon, named from
# docker info's ID, so every client of that daemon shares it. A directory
# under /tmp does not: it is world-writable, kill -0 on another user's
# process returns EPERM, and someone who cannot open the daemon can hold the
# name. Only a Docker client can create or remove this network.

UPDATE_LOCK_NET=
UPDATE_LOCK_REAPER=
UPDATE_LOCK_REAPER_WAIT=0

release_update_lock(){
  if [ -n "${UPDATE_LOCK_REAPER:-}" ]; then
    docker network rm "$UPDATE_LOCK_REAPER" >/dev/null 2>&1 || true
    UPDATE_LOCK_REAPER=
  fi
  if [ -n "${UPDATE_LOCK_NET:-}" ]; then
    docker network rm "$UPDATE_LOCK_NET" >/dev/null 2>&1 || true
    UPDATE_LOCK_NET=
  fi
}

# Linux: field 22 of /proc/pid/stat (clock ticks since boot).
# macOS: ps lstart, because /proc is absent. Empty if neither works.
proc_starttime(){
  local pid=$1 stat rest value
  if [ -r "/proc/$pid/stat" ]; then
    stat=$(cat "/proc/$pid/stat") || return 0
    rest=${stat#*') '}
    value=$(printf '%s\n' "$rest" | awk '{print $20}')
    case "$value" in
      ""|*[!0-9]*) return 0 ;;
    esac
    printf '%s\n' "$value"
    return 0
  fi
  value=$(ps -p "$pid" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//') || true
  [ -n "$value" ] || return 0
  printf '%s\n' "$value"
}

# 0 when pid is still the process that started at start.
# 1 when it is gone or the PID has been reused.
# 2 when the process exists but no start time can be read.
owner_state(){
  local pid=$1 start=$2 current
  if [ -z "$pid" ]; then
    return 1
  fi
  if [ -d /proc ]; then
    [ -d "/proc/$pid" ] || return 1
  elif ! ps -p "$pid" >/dev/null 2>&1; then
    return 1
  fi
  current=$(proc_starttime "$pid" || true)
  if [ -n "$start" ] && [ -n "$current" ]; then
    if [ "$start" = "$current" ]; then
      return 0
    fi
    return 1
  fi
  return 2
}

lock_label(){
  docker network inspect -f "{{index .Labels \"$2\"}}" "$1" 2>/dev/null || true
}

# Remove name only when a second read still shows the same dead owner.
# Two waiters can observe one dead reaper; the later remove must not delete
# the reaper a replacement has since created.
reap_if_unchanged(){
  local name=$1 pid=$2 start=$3 again_pid again_start state
  again_pid=$(lock_label "$name" artex.lock/pid)
  again_start=$(lock_label "$name" artex.lock/start)
  [ "$again_pid" = "$pid" ] && [ "$again_start" = "$start" ] || return 0
  state=0
  owner_state "$again_pid" "$again_start" || state=$?
  if [ "$state" -eq 1 ]; then
    docker network rm "$name" >/dev/null 2>&1 || true
  fi
}

reap_stale_update_lock(){
  local net=$1 dead_pid=$2 dead_start=$3 reap=${1}reap
  local rpid rstart start waited state
  start=$(proc_starttime $$ || true)
  if ! docker network create \
      --label "artex.lock/pid=$$" \
      --label "artex.lock/start=$start" \
      --label "artex.lock/wall=$(date +%s)" \
      "$reap" >/dev/null 2>&1; then
    rpid=$(lock_label "$reap" artex.lock/pid)
    rstart=$(lock_label "$reap" artex.lock/start)
    if [ -z "$rpid" ]; then
      waited=${UPDATE_LOCK_REAPER_WAIT:-0}
      waited=$((waited + 1))
      UPDATE_LOCK_REAPER_WAIT=$waited
      if [ "$waited" -ge 5 ]; then
        die "更新锁的回收记录没有进程号，已停止。确认没有更新在运行后删除网络：$reap"
      fi
      sleep 1
      return 0
    fi
    UPDATE_LOCK_REAPER_WAIT=0
    state=0
    owner_state "$rpid" "$rstart" || state=$?
    if [ "$state" -eq 0 ]; then
      sleep 1
      return 0
    fi
    if [ "$state" -eq 2 ]; then
      # The process is alive and we cannot timestamp it. Do not delete it.
      sleep 1
      return 0
    fi
    reap_if_unchanged "$reap" "$rpid" "$rstart"
    return 0
  fi
  UPDATE_LOCK_REAPER_WAIT=0
  UPDATE_LOCK_REAPER=$reap
  reap_if_unchanged "$net" "$dead_pid" "$dead_start"
  docker network rm "$reap" >/dev/null 2>&1 || true
  UPDATE_LOCK_REAPER=
}

# 0: keep waiting. 1: reap.
owner_holds_lock(){
  local pid=$1 start=$2 wall=$3 state now
  state=0
  owner_state "$pid" "$start" || state=$?
  if [ "$state" -eq 0 ]; then
    return 0
  fi
  if [ "$state" -eq 1 ]; then
    return 1
  fi
  # Alive, but neither /proc nor ps could identify the process. A normal
  # update removes this network when it exits, so a waiter does not sit here
  # for the whole bound. The bound only applies to a live PID we cannot
  # timestamp; a dead PID is state 1 and is reaped immediately.
  case "$wall" in
    ""|*[!0-9]*) return 1 ;;
  esac
  now=$(date +%s)
  if [ $((now - wall)) -lt 7200 ]; then
    return 0
  fi
  return 1
}

acquire_update_lock(){
  local daemon_id net start pid st wall announced empty_wait state
  command -v docker >/dev/null 2>&1 || die "未检测到 docker，无法锁定 artex-ymh:local"
  daemon_id=$(docker info --format '{{.ID}}') || die "无法读取 Docker daemon ID，已停止更新"
  daemon_id=$(printf '%s' "$daemon_id" | tr -d '[:space:]')
  case "$daemon_id" in
    ""|*/*|*..*|*[!A-Za-z0-9._-]*) die "Docker daemon ID 无效，已停止更新" ;;
  esac
  net=artexymh$daemon_id
  start=$(proc_starttime $$ || true)
  wall=$(date +%s)
  announced=0
  empty_wait=0
  trap release_update_lock EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  while ! docker network create \
      --label "artex.lock/pid=$$" \
      --label "artex.lock/start=$start" \
      --label "artex.lock/wall=$wall" \
      "$net" >/dev/null 2>&1; do
    pid=$(lock_label "$net" artex.lock/pid)
    st=$(lock_label "$net" artex.lock/start)
    wall=$(lock_label "$net" artex.lock/wall)
    if [ -z "$pid" ]; then
      empty_wait=$((empty_wait + 1))
      if [ "$empty_wait" -ge 5 ]; then
        die "更新锁没有进程号，已停止。确认没有更新在运行后删除网络：$net"
      fi
      sleep 1
      continue
    fi
    empty_wait=0
    if owner_holds_lock "$pid" "$st" "$wall"; then
      if [ "$announced" -eq 0 ]; then
        info "另一个更新正在构建或部署，等待它结束后继续…"
        announced=1
      fi
      sleep 1
      continue
    fi
    reap_stale_update_lock "$net" "$pid" "$st"
  done
  UPDATE_LOCK_NET=$net
}
