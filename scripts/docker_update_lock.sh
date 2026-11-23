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
  refuse_symlink "$lock_hold"
  current=$(cat "$lock_hold/pid" 2>/dev/null || true)
  if [ "$current" = "$dead_pid" ] && ! kill -0 "$current" 2>/dev/null; then
    rm -rf -- "$lock_hold"
  fi
  rm -rf -- "$reaper"
  UPDATE_LOCK_REAPER=
}

prepare_private_dir(){
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
  # find -user/-perm work with both GNU and BSD (macOS) find; stat -c is
  # GNU-only and BSD stat rejects it.
  if [ -z "$(find "$dir" -maxdepth 0 -user "$(id -u)" -print)" ]; then
    die "更新锁目录必须属于当前用户：$dir"
  fi
  chmod 700 -- "$dir" || die "无法设置更新锁目录权限：$dir"
  if [ -L "$dir" ] || [ -z "$(find "$dir" -maxdepth 0 -perm 700 -print)" ]; then
    die "更新锁目录权限异常：$dir"
  fi
}

refuse_symlink(){
  if [ -L "$1" ]; then
    die "更新锁是符号链接，已拒绝：$1"
  fi
}

# Unset DOCKER_HOST and the engine's default socket are the same daemon.
# DOCKER_CONTEXT=default is that daemon too. Any other host string stays as given.
daemon_scope_name(){
  local host=${DOCKER_HOST:-}
  host=${host%/}
  case "$host" in
    ""|unix:///var/run/docker.sock)
      if [ -n "${DOCKER_CONTEXT:-}" ] && [ "$DOCKER_CONTEXT" != default ]; then
        printf 'context:%s\n' "$DOCKER_CONTEXT"
      else
        printf 'default\n'
      fi
      ;;
    *)
      printf '%s\n' "$host"
      ;;
  esac
}

# Hold the lock until this process exits.
acquire_update_lock(){
  local state_home lock_dir daemon_scope scope_key lock_file lock_umask
  local lock_hold announced pid empty_wait
  # One directory per user. XDG_STATE_HOME is ignored so two updates from the
  # same home cannot miss each other by exporting a different state directory.
  # The directory stays under that home, mode 700. A shared /tmp name can be
  # created by a user who cannot access Docker, and kill -0 returns EPERM for
  # another user's live process, which is indistinguishable from a dead owner.
  if [ -z "${HOME:-}" ]; then
    die "无法创建更新锁：HOME 未设置"
  fi
  state_home=$HOME/.local/state
  lock_dir=$state_home/artex-ymh
  prepare_private_dir "$lock_dir"

  daemon_scope=$(daemon_scope_name)
  scope_key=$(printf '%s' "artex-ymh:local|$daemon_scope" | cksum | awk '{print $1}')
  lock_file=$lock_dir/docker-update.$scope_key.lock
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
    if ! kill -0 "$pid" 2>/dev/null; then
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
  printf '%s\n' "$$" > "$lock_hold/pid"

  if command -v flock >/dev/null 2>&1; then
    lock_umask=$(umask)
    umask 077
    # Append so a pre-existing file is not truncated before the lock is held.
    if ! exec 9>>"$lock_file"; then
      umask "$lock_umask"
      die "无法打开更新锁：$lock_file"
    fi
    umask "$lock_umask"
    refuse_symlink "$lock_file"
    if ! flock -n 9; then
      info "另一个更新正在构建或部署，等待它结束后继续…"
      flock 9
    fi
  fi
}
