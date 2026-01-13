#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
mkdir -p "$ROOT_DIR/logs"

PY_BIN="${PYTHON_BIN:-python3}"
WATCH_DIR="${RCLONE_UPLOAD_WATCH_DIR:-$ROOT_DIR/up}"
MODE="${RCLONE_UPLOAD_MODE:-move}"
STATE_FILE="${RCLONE_UPLOAD_STATE_FILE:-$ROOT_DIR/logs/rclone_upload_state.json}"

# 兼容旧逻辑：若没显式指定 DEST，则尝试从 /root/u/milo.conf 取 milolist[0]
DEST="${RCLONE_UPLOAD_DEST:-}"
if [[ -z "$DEST" && -f "/root/u/milo.conf" ]]; then
  # shellcheck source=/dev/null
  source /root/u/milo.conf || true
  if [[ -n "${milolist[0]:-}" ]]; then
    DEST="${milolist[0]}:milo/strip"
  fi
fi

if [[ -z "$DEST" ]]; then
  echo "ERROR: 缺少上传目标。请设置环境变量 RCLONE_UPLOAD_DEST (例如: remote:milo/strip)，或提供 /root/u/milo.conf (milolist[0])." >&2
  exit 2
fi

# 默认参数：尽量复刻旧 do.sh 的行为（上传队列 up/、move、删小 mp4、清空空目录、rclone 稳定性参数）
exec "$PY_BIN" "$ROOT_DIR/rclone_upload.py" \
  --watch \
  --watch-dir "$WATCH_DIR" \
  --dest "$DEST" \
  --mode "$MODE" \
  --state-file "$STATE_FILE" \
  --scan-interval "${RCLONE_UPLOAD_SCAN_INTERVAL:-10}" \
  --min-age "${RCLONE_UPLOAD_MIN_AGE:-30}" \
  --stable-checks "${RCLONE_UPLOAD_STABLE_CHECKS:-3}" \
  --retries "${RCLONE_UPLOAD_RETRIES:-10}" \
  --retry-sleep "${RCLONE_UPLOAD_RETRY_SLEEP:-30}" \
  --min-size-bytes "${RCLONE_UPLOAD_MIN_SIZE_BYTES:-5242880}" \
  --min-size-ext "${RCLONE_UPLOAD_MIN_SIZE_EXTS:-.mp4}" \
  --delete-small \
  --prune-empty-dirs \
  --rclone-arg="--buffer-size=${RCLONE_UPLOAD_BUFFER_SIZE:-32M}" \
  --rclone-arg="--transfers=${RCLONE_UPLOAD_TRANSFERS:-4}" \
  --rclone-arg="--checkers=${RCLONE_UPLOAD_CHECKERS:-8}" \
  --rclone-arg="--tpslimit=${RCLONE_UPLOAD_TPSLIMIT:-2}" \
  --rclone-arg="--contimeout=${RCLONE_UPLOAD_CONTIMEOUT:-15s}" \
  --rclone-arg="--timeout=${RCLONE_UPLOAD_TIMEOUT:-5m}" \
  --rclone-arg="--low-level-retries=${RCLONE_UPLOAD_LOW_LEVEL_RETRIES:-20}" \
  --rclone-arg="--retries=${RCLONE_UPLOAD_RCLONE_RETRIES:-10}" \
  --rclone-arg="--retries-sleep=${RCLONE_UPLOAD_RCLONE_RETRIES_SLEEP:-30s}" \
  --rclone-arg="--log-file=${RCLONE_UPLOAD_RCLONE_LOG_FILE:-$ROOT_DIR/logs/rclone_transfer.log}" \
  --rclone-arg="--log-level=${RCLONE_UPLOAD_RCLONE_LOG_LEVEL:-NOTICE}" \
  --rclone-arg="--stats=${RCLONE_UPLOAD_STATS:-10s}" \
  --rclone-arg="--stats-log-level=NOTICE" \
  "$@"
