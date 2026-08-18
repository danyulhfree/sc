#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

exec "$PYTHON_BIN" "$ROOT_DIR/rclone_upload.py" \
  --watch-dir "${SC_UPLOAD_DIR:-$ROOT_DIR/up}" \
  --status-file "${SC_UPLOAD_STATUS_FILE:-$ROOT_DIR/logs/uploader_status.json}" \
  --lock-file "${SC_UPLOAD_LOCK_FILE:-$ROOT_DIR/logs/uploader.lock}" \
  --helper "${SC_UPLOAD_HELPER:-$ROOT_DIR/fic_upload_once.sh}" \
  --min-size-bytes "${SC_UPLOAD_MIN_SIZE_BYTES:-5242880}" \
  --interval "${SC_UPLOAD_INTERVAL_SECONDS:-10}" \
  "$@"
