# Sourced by update.sh and install.sh. Both build the mutable artex-ymh:local tag.
# The directory is the lock every caller takes, with or without flock. flock, when
# present, is held in addition so the kernel drops that fd if the process is
# killed; it is not a second protocol. INT and TERM exit so the EXIT trap
# releases the directory before compose up continues.

UPDATE_LOCK_DIR=
UPDATE_LOCK_REAPER=
UPDATE_LOCK_REAPER_WAIT=0

release_update_lock(){
  if [ -n "${UPDATE_LOCK_REAPER:-}" ]; then
    rm -rf -- "$UPDATE_LOCK_REAPER"
    UPDATE_LOCK_REAPER=
  fi
  if [ -n "${UPDATE_LOCK_DIR:-}" ]; then
    rm -rf -- "$UPDATE_LOCK_DIR"
    UPDATE_LOCK_DIR=
  fi
}

# Remove a directory lock whose owner died, at most one waiter at a time, and
# only if it still names the dead PID the caller read. Two waiters can read the
# same dead PID; without the recheck the second would delete the lock the
# first had just taken, and both would build. A reaper killed between mkdir
# and cleanup is itself recognised by its dead PID and cleared.
#
# A reaper with no PID yet is the window between mkdir and the pid write. Do
# not delete it: a live updater may still be publishing the PID. Wait a bounded
# number of times. The caller retries this function without sleeping, so the
# sleep has to be here; past the bound, stop instead of spinning.
reap_stale_update_lock(){
  local lock_hold=$1 dead_pid=$2 reaper=$1.reap current waited
  refuse_symlink "$reaper"
  if ! mkdir -- "$reaper" 2>/dev/null; then
    current=$(cat "$reaper/pid" 2>/dev/null || true)
    if [ -z "$current" ]; then
      waited=${UPDATE_LOCK_REAPER_WAIT:-0}
      waited=$((waited + 1))
      UPDATE_LOCK_REAPER_WAIT=$waited
      if [ "$waited" -ge 5 ]; then
        die "更新锁的回收目录没有进程号，已停止。确认没有更新在运行后删除：$reaper"
      fi
      sleep 1
      return 0
    fi
    UPDATE_LOCK_REAPER_WAIT=0
    if ! kill -0 "$current" 2>/dev/null; then
      rm -rf -- "$reaper"
    fi
    return 0
  fi
  UPDATE_LOCK_REAPER_WAIT=0
  UPDATE_LOCK_REAPER=$reaper
  printf '%s\n' "$$" > "$reaper/pid"
  chmod 777 -- "$reaper" 2>/dev/null || true
  chmod 644 -- "$reaper/pid" 2>/dev/null || true
  refuse_symlink "$lock_hold"
  current=$(cat "$lock_hold/pid" 2>/dev/null || true)
  if [ "$current" = "$dead_pid" ] && ! owner_holds_lock "$current" "$lock_hold"; then
    rm -rf -- "$lock_hold"
  fi
  rm -rf -- "$reaper"
  UPDATE_LOCK_REAPER=
}

refuse_symlink(){
  if [ -L "$1" ]; then
    die "更新锁是符号链接，已拒绝：$1"
  fi
}

# Field 22 of /proc/pid/stat (starttime). Empty when /proc is unavailable.
# Combined with the PID, it identifies one process: a reused PID has a new value.
proc_starttime(){
  local stat=/proc/$1/stat
  [ -r "$stat" ] || return 0
  awk -F ')' 'NF > 1 {
    n = split($2, f, " ")
    if (n >= 20 && f[20] ~ /^[0-9]+$/) print f[20]
  }' "$stat"
}

# 0: keep waiting. 1: the recorded owner is gone or is a reused PID.
owner_holds_lock(){
  local pid=$1 hold=$2 recorded current started now err
  err=$(kill -0 "$pid" 2>&1 >/dev/null || true)
  if [ -n "$err" ]; then
    case "$err" in
      *"not permitted"*) ;;
      *) return 1 ;;
    esac
  fi
  recorded=$(cat "$hold/starttime" 2>/dev/null || true)
  current=$(proc_starttime "$pid" || true)
  if [ -n "$recorded" ] && [ -n "$current" ]; then
    if [ "$recorded" = "$current" ]; then
      return 0
    fi
    return 1
  fi
  # No starttime to compare (another OS, or a lock that only stored a PID).
  # A live-looking PID must not wait forever.
  # No starttime. A timestamp bounds the wait; a PID alone does not.
  started=$(cat "$hold/started" 2>/dev/null || true)
  case "$started" in
    ""|*[!0-9]*) return 1 ;;
  esac
  now=$(date +%s)
  if [ $((now - started)) -lt 7200 ]; then
    return 0
  fi
  return 1
}

# Shared by every client of one daemon. Not mode 700 under one home: another
# user of the same daemon builds the same artex-ymh:local tag.
prepare_shared_dir(){
  local dir=$1
  if [ -L "$dir" ]; then
    die "更新锁目录是符号链接，已拒绝：$dir"
  fi
  if [ ! -d "$dir" ]; then
    mkdir -p -- "$dir" || die "无法创建更新锁目录：$dir"
  fi
  if [ -L "$dir" ] || [ ! -d "$dir" ]; then
    die "更新锁目录是符号链接，已拒绝：$dir"
  fi
  if [ -n "$(find "$dir" -maxdepth 0 -user "$(id -u)" -print)" ]; then
    chmod 777 -- "$dir" || die "无法设置更新锁目录权限：$dir"
    if [ -L "$dir" ] || [ -z "$(find "$dir" -maxdepth 0 -perm 777 -print)" ]; then
      die "更新锁目录权限异常：$dir"
    fi
    return 0
  fi
  [ -w "$dir" ] || die "无法写入更新锁目录：$dir"
}

# Hold the lock until this process exits.
acquire_update_lock(){
  local daemon_id lock_root lock_dir lock_file lock_umask
  local lock_hold announced pid empty_wait start
  # artex-ymh:local is one tag per daemon, shared by every user and every
  # spelling of DOCKER_HOST. docker info's ID is that daemon. A path under
  # one home, or a hash of the host string, lets a second client build it.
  command -v docker >/dev/null 2>&1 || die "未检测到 docker，无法锁定 artex-ymh:local"
  daemon_id=$(docker info --format '{{.ID}}') || die "无法读取 Docker daemon ID，已停止更新"
  daemon_id=$(printf '%s' "$daemon_id" | tr -d '[:space:]')
  case "$daemon_id" in
    ""|*/*|*..*) die "Docker daemon ID 无效，已停止更新" ;;
  esac
  lock_root=/tmp/artex-ymh-update-locks
  prepare_shared_dir "$lock_root"
  lock_dir=$lock_root/$daemon_id
  prepare_shared_dir "$lock_dir"
  lock_file=$lock_dir/docker-update.lock
  refuse_symlink "$lock_file"
  if [ -e "$lock_file" ] && [ ! -f "$lock_file" ]; then
    die "更新锁路径不是普通文件：$lock_file"
  fi

  lock_hold=$lock_file.d
  announced=0
  empty_wait=0
  # Exit on the signal. The EXIT trap releases the directory we hold.
  trap release_update_lock EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  refuse_symlink "$lock_hold"
  if [ -e "$lock_hold" ] && [ ! -d "$lock_hold" ]; then
    die "更新锁路径不是目录：$lock_hold"
  fi
  while ! mkdir -- "$lock_hold" 2>/dev/null; do
    refuse_symlink "$lock_hold"
    pid=$(cat "$lock_hold/pid" 2>/dev/null || true)
    if [ -z "$pid" ]; then
      # Same window as an empty reaper: the owner has not published a PID.
      # Sleep, and stop after the bound instead of waiting forever.
      empty_wait=$((empty_wait + 1))
      if [ "$empty_wait" -ge 5 ]; then
        die "更新锁目录没有进程号，已停止。确认没有更新在运行后删除：$lock_hold"
      fi
      sleep 1
      continue
    fi
    empty_wait=0
    if ! owner_holds_lock "$pid" "$lock_hold"; then
      reap_stale_update_lock "$lock_hold" "$pid"
      continue
    fi
    if [ "$announced" -eq 0 ]; then
      info "另一个更新正在构建或部署，等待它结束后继续…"
      announced=1
    fi
    sleep 1
  done
  UPDATE_LOCK_DIR=$lock_hold
  # Publish identity before the PID so a waiter never sees a PID-only lock.
  printf '%s\n' "$(date +%s)" > "$lock_hold/started"
  start=$(proc_starttime "$$" || true)
  printf '%s\n' "$start" > "$lock_hold/starttime"
  printf '%s\n' "$$" > "$lock_hold/pid"
  chmod 644 -- "$lock_hold/pid" "$lock_hold/starttime" "$lock_hold/started" || die "无法设置更新锁权限：$lock_hold"
  # Open the directory only after the identity files are readable.
  chmod 777 -- "$lock_hold" || die "无法设置更新锁目录权限：$lock_hold"

  if command -v flock >/dev/null 2>&1; then
    lock_umask=$(umask)
    umask 000
    # Append so a pre-existing file is not truncated before the lock is held.
    # Mode 666 so another user of this daemon can flock the same file.
    if ! exec 9>>"$lock_file"; then
      umask "$lock_umask"
      die "无法打开更新锁：$lock_file"
    fi
    umask "$lock_umask"
    chmod 666 -- "$lock_file" 2>/dev/null || true
    refuse_symlink "$lock_file"
    if ! flock -n 9; then
      info "另一个更新正在构建或部署，等待它结束后继续…"
      flock 9
    fi
  fi
}
