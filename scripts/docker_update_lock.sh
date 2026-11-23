#!/usr/bin/env bash
# Sourced by update.sh and install.sh. Both publish the mutable artex-ymh:local
# tag on one Docker daemon. The lock is a running container on that daemon,
# named from docker info's ID. A network with no containers is not a lock:
# docker network prune deletes it while the build is still using the tag.
# Removal uses the container ID from the same inspect as the owner labels.

UPDATE_LOCK_ID=
UPDATE_LOCK_REAPER_ID=
UPDATE_LOCK_REAPER_WAIT=0

release_update_lock(){
  if [ -n "${UPDATE_LOCK_REAPER_ID:-}" ]; then
    docker rm -f "$UPDATE_LOCK_REAPER_ID" >/dev/null 2>&1 || true
    UPDATE_LOCK_REAPER_ID=
  fi
  if [ -n "${UPDATE_LOCK_ID:-}" ]; then
    docker rm -f "$UPDATE_LOCK_ID" >/dev/null 2>&1 || true
    UPDATE_LOCK_ID=
  fi
}

lock_host(){
  local id=
  if [ -r /etc/machine-id ]; then
    id=$(tr -d '[:space:]' < /etc/machine-id)
  elif [ -r /etc/hostid ]; then
    id=$(tr -d '[:space:]' < /etc/hostid)
  fi
  if [ -z "$id" ]; then
    id=$(hostname 2>/dev/null || true)
  fi
  printf '%s\n' "$id"
}

# pid:[inode] on Linux. "host" where the OS has no PID namespaces (macOS),
# so two local clients still share one namespace token.
lock_pidns(){
  if [ -e /proc/self/ns/pid ]; then
    readlink /proc/self/ns/pid 2>/dev/null || true
    return 0
  fi
  printf '%s\n' host
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

# Image that can stay running for the whole critical section. Prefer one
# already present. Otherwise pull the Postgres image this deploy uses.
# Prints the image, or returns 2 when it cannot be pulled. Callers invoke
# this from a command substitution, so a die here would not stop the script.
lock_image(){
  local image=${POSTGRES_IMAGE:-postgres:16-alpine}
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker pull "$image" >/dev/null || return 2
  fi
  printf '%s\n' "$image"
}

# Print the new container ID.
# 1: the name is already taken.
# 2: the image could not be pulled.
# 3: the container did not stay running.
# A stopped container is removed by docker container prune, and an unused
# network is removed by network prune, so the lock has to be running.
start_lock_container(){
  local name="$1" image id running start host pidns uid
  image=$(lock_image) || return 2
  start=$(proc_starttime $$ || true)
  host=$(lock_host)
  pidns=$(lock_pidns)
  uid=$(id -u)
  if ! id=$(docker run -d --name "$name" --network none --pull never --restart no \
      --label "artex.lock/pid=$$" \
      --label "artex.lock/start=$start" \
      --label "artex.lock/wall=$(date +%s)" \
      --label "artex.lock/host=$host" \
      --label "artex.lock/pidns=$pidns" \
      --label "artex.lock/uid=$uid" \
      --entrypoint sleep \
      "$image" infinity 2>/dev/null); then
    return 1
  fi
  if [ -z "$id" ]; then
    return 3
  fi
  running=$(docker container inspect -f '{{.State.Running}}' "$id" 2>/dev/null || true)
  if [ "$running" != true ]; then
    docker rm -f "$id" >/dev/null 2>&1 || true
    return 3
  fi
  printf '%s\n' "$id"
}

# status from start_lock_container: 0 held, 1 busy, other is fatal.
take_lock_container(){
  local name="$1" status=0
  LOCK_TAKE_ID=
  LOCK_TAKE_ID=$(start_lock_container "$name") || status=$?
  if [ "$status" -eq 0 ]; then
    return 0
  fi
  if [ "$status" -eq 1 ]; then
    return 1
  fi
  if [ "$status" -eq 2 ]; then
    die "无法拉取锁容器镜像：${POSTGRES_IMAGE:-postgres:16-alpine}"
  fi
  die "锁容器没有保持运行，已停止。更新锁必须是正在运行的容器，否则 prune 会把它删掉。"
}

# 0: this process is still the owner.
# 1: same host, namespace, and UID, and the PID is gone or reused.
# 2: same host and namespace, but no start time can be compared.
# 3: different host or PID namespace.
# 4: /proc hides another UID, so a missing PID is not proof of death.
owner_state(){
  local pid="$1" start="$2" host="$3" pidns="$4" uid="$5"
  local current our_host our_ns our_uid
  our_host=$(lock_host)
  our_ns=$(lock_pidns)
  our_uid=$(id -u)
  if [ -z "$our_host" ] || [ -z "$our_ns" ] || [ -z "$host" ] || [ -z "$pidns" ] \
    || [ "$host" != "$our_host" ] || [ "$pidns" != "$our_ns" ]; then
    return 3
  fi
  if [ -z "$pid" ]; then
    return 1
  fi
  if [ -d /proc ]; then
    if [ ! -d "/proc/$pid" ]; then
      # hidepid=2 hides another user's live process. Our own PID stays visible.
      if [ -z "$uid" ] || [ "$uid" != "$our_uid" ]; then
        return 4
      fi
      return 1
    fi
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

# 0 when the wall clock cannot bound the wait, or the two-hour bound has passed.
lock_wait_expired(){
  local wall=$1 now
  case "$wall" in
    ""|*[!0-9]*) return 0 ;;
  esac
  now=$(date +%s)
  [ $((now - wall)) -ge 7200 ]
}

lock_record(){
  # '|' is not IFS whitespace, so an empty label stays an empty field.
  docker container inspect -f '{{.Id}}|{{index .Config.Labels "artex.lock/pid"}}|{{index .Config.Labels "artex.lock/start"}}|{{index .Config.Labels "artex.lock/wall"}}|{{index .Config.Labels "artex.lock/host"}}|{{index .Config.Labels "artex.lock/pidns"}}|{{index .Config.Labels "artex.lock/uid"}}' "$1" 2>/dev/null || true
}

read_lock(){
  local record="$1"
  LOCK_ID= LOCK_PID= LOCK_START= LOCK_WALL= LOCK_HOST= LOCK_PIDNS= LOCK_UID=
  [ -n "$record" ] || return 1
  IFS='|' read -r LOCK_ID LOCK_PID LOCK_START LOCK_WALL LOCK_HOST LOCK_PIDNS LOCK_UID <<EOF
$record
EOF
}

# 0: keep waiting. 1: same namespace and the owner is gone. 2: stop, the
# unreadable owner has passed the bound. 3: stop, another host or namespace.
# 4: stop, another UID is not visible in /proc.
owner_holds_lock(){
  local pid="$1" start="$2" wall="$3" host="$4" pidns="$5" uid="$6" state
  state=0
  owner_state "$pid" "$start" "$host" "$pidns" "$uid" || state=$?
  if [ "$state" -eq 0 ]; then
    return 0
  fi
  if [ "$state" -eq 1 ]; then
    return 1
  fi
  if [ "$state" -eq 3 ]; then
    return 3
  fi
  if [ "$state" -eq 4 ]; then
    return 4
  fi
  if lock_wait_expired "$wall"; then
    return 2
  fi
  return 0
}

# Remove only the container ID whose labels still name this dead owner.
reap_if_unchanged(){
  local name="$1" want_id="$2" want_pid="$3" want_start="$4" state
  read_lock "$(lock_record "$name")" || return 0
  [ "$LOCK_ID" = "$want_id" ] || return 0
  [ "$LOCK_PID" = "$want_pid" ] && [ "$LOCK_START" = "$want_start" ] || return 0
  state=0
  owner_state "$LOCK_PID" "$LOCK_START" "$LOCK_HOST" "$LOCK_PIDNS" "$LOCK_UID" || state=$?
  if [ "$state" -eq 1 ]; then
    docker rm -f "$LOCK_ID" >/dev/null 2>&1 || true
    return 0
  fi
  if [ "$state" -eq 3 ]; then
    die "更新锁由另一台主机或另一个 PID namespace 持有，无法按 PID 判断它是否已结束，已停止。确认没有更新在运行后删除容器：$name"
  fi
  if [ "$state" -eq 4 ]; then
    die "更新锁由其他用户持有，当前 /proc 看不到该进程，无法确认它是否仍在运行，已停止。确认没有更新在运行后删除容器：$name"
  fi
  if [ "$state" -eq 2 ] && lock_wait_expired "$LOCK_WALL"; then
    die "更新锁读不到持有者的启动时间，两小时上限已到，已停止。确认没有更新在运行后删除容器：$name"
  fi
}

reap_stale_update_lock(){
  local net="$1" dead_id="$2" dead_pid="$3" dead_start="$4" reap="${1}reap"
  local rpid rstart waited state
  if ! take_lock_container "$reap"; then
    read_lock "$(lock_record "$reap")" || true
    rpid=$LOCK_PID
    rstart=$LOCK_START
    if [ -z "$rpid" ]; then
      waited=${UPDATE_LOCK_REAPER_WAIT:-0}
      waited=$((waited + 1))
      UPDATE_LOCK_REAPER_WAIT=$waited
      if [ "$waited" -ge 5 ]; then
        die "更新锁的回收记录没有进程号，已停止。确认没有更新在运行后删除容器：$reap"
      fi
      sleep 1
      return 0
    fi
    UPDATE_LOCK_REAPER_WAIT=0
    state=0
    owner_state "$rpid" "$rstart" "$LOCK_HOST" "$LOCK_PIDNS" "$LOCK_UID" || state=$?
    if [ "$state" -eq 0 ]; then
      sleep 1
      return 0
    fi
    if [ "$state" -eq 3 ]; then
      die "更新锁的回收记录属于另一台主机或另一个 PID namespace，无法按 PID 判断它是否已结束，已停止。确认没有更新在运行后删除容器：$reap"
    fi
    if [ "$state" -eq 4 ]; then
      die "更新锁的回收记录由其他用户持有，当前 /proc 看不到该进程，无法确认它是否仍在运行，已停止。确认没有更新在运行后删除容器：$reap"
    fi
    if [ "$state" -eq 2 ]; then
      if lock_wait_expired "$LOCK_WALL"; then
        die "更新锁的回收记录读不到启动时间，两小时上限已到，已停止。确认没有更新在运行后删除容器：$reap"
      fi
      sleep 1
      return 0
    fi
    reap_if_unchanged "$reap" "$LOCK_ID" "$rpid" "$rstart"
    return 0
  fi
  UPDATE_LOCK_REAPER_WAIT=0
  UPDATE_LOCK_REAPER_ID=$LOCK_TAKE_ID
  reap_if_unchanged "$net" "$dead_id" "$dead_pid" "$dead_start"
  docker rm -f "$UPDATE_LOCK_REAPER_ID" >/dev/null 2>&1 || true
  UPDATE_LOCK_REAPER_ID=
}

acquire_update_lock(){
  local daemon_id net
  local seen_id seen_pid seen_start announced empty_wait state
  command -v docker >/dev/null 2>&1 || die "未检测到 docker，无法锁定 artex-ymh:local"
  daemon_id=$(docker info --format '{{.ID}}') || die "无法读取 Docker daemon ID，已停止更新"
  daemon_id=$(printf '%s' "$daemon_id" | tr -d '[:space:]')
  case "$daemon_id" in
    ""|*/*|*..*|*[!A-Za-z0-9._-]*) die "Docker daemon ID 无效，已停止更新" ;;
  esac
  net=artexymh$daemon_id
  if [ -z "$(lock_host)" ] || [ -z "$(lock_pidns)" ]; then
    die "无法确认本机或 PID namespace，已停止更新"
  fi
  announced=0
  empty_wait=0
  trap release_update_lock EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  while true; do
    if take_lock_container "$net"; then
      UPDATE_LOCK_ID=$LOCK_TAKE_ID
      break
    fi
    read_lock "$(lock_record "$net")" || true
    if [ -z "$LOCK_PID" ]; then
      empty_wait=$((empty_wait + 1))
      if [ "$empty_wait" -ge 5 ]; then
        die "更新锁没有进程号，已停止。确认没有更新在运行后删除容器：$net"
      fi
      sleep 1
      continue
    fi
    empty_wait=0
    state=0
    owner_holds_lock "$LOCK_PID" "$LOCK_START" "$LOCK_WALL" "$LOCK_HOST" "$LOCK_PIDNS" "$LOCK_UID" || state=$?
    if [ "$state" -eq 0 ]; then
      if [ "$announced" -eq 0 ]; then
        info "另一个更新正在构建或部署，等待它结束后继续…"
        announced=1
      fi
      sleep 1
      continue
    fi
    if [ "$state" -eq 2 ]; then
      die "更新锁读不到持有者的启动时间，两小时上限已到，已停止。确认没有更新在运行后删除容器：$net"
    fi
    if [ "$state" -eq 3 ]; then
      die "更新锁由另一台主机或另一个 PID namespace 持有，无法按 PID 判断它是否已结束，已停止。确认没有更新在运行后删除容器：$net"
    fi
    if [ "$state" -eq 4 ]; then
      die "更新锁由其他用户持有，当前 /proc 看不到该进程，无法确认它是否仍在运行，已停止。确认没有更新在运行后删除容器：$net"
    fi
    seen_id=$LOCK_ID
    seen_pid=$LOCK_PID
    seen_start=$LOCK_START
    reap_stale_update_lock "$net" "$seen_id" "$seen_pid" "$seen_start"
  done
}
