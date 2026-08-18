#!/usr/bin/env bash
# Legacy Python recorder compatibility. The Go recorder handles this internally.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SC_LOG_DIR:-$ROOT_DIR/logs}"
LOG_FILE="$LOG_DIR/move_sh.log"
FFMPEG_PATH="${FFMPEG_PATH:-ffmpeg}"
mkdir -p "$LOG_DIR"

log_message() { printf '%s - %s\n' "$(date '+%Y/%m/%d %H:%M:%S')" "$*" >>"$LOG_FILE"; }

if (($# < 5)); then
  log_message "错误：需要 5 个参数"
  exit 2
fi
full_path="$1"
filename="$2"
source_dir="$3"
model_name="$4"
basename_no_ext="$5"

if [[ ! "$model_name" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || [[ "$filename" != "$(basename "$filename")" ]]; then
  log_message "错误：不安全的模型名或文件名: model='$model_name' file='$filename'"
  exit 2
fi
if [[ ! -f "$full_path" || ! -r "$full_path" ]]; then
  log_message "错误：原始文件不存在或不可读: $full_path"
  exit 1
fi

file_size=$(stat -c '%s' -- "$full_path" 2>/dev/null || stat -f '%z' -- "$full_path" 2>/dev/null || printf '0\n')
if ((file_size < 10240)); then
  log_message "删除过小文件 (${file_size} bytes): $filename"
  rm -f -- "$full_path"
  exit 0
fi

fixed_file="${source_dir%/}/${basename_no_ext}_fixed.mp4"
if "$FFMPEG_PATH" -y -fflags +genpts -i "$full_path" -c copy -avoid_negative_ts make_zero -movflags +faststart "$fixed_file" >>"$LOG_FILE" 2>&1 \
  && [[ -s "$fixed_file" ]]; then
  if ! mv -f -- "$fixed_file" "$full_path"; then
    log_message "警告：无法用修复文件替换原文件"
    rm -f -- "$fixed_file"
  fi
else
  log_message "警告：ffmpeg 修复失败，保留原文件"
  rm -f -- "$fixed_file"
fi

target_dir="${SC_UPLOAD_DIR:-$ROOT_DIR/up}/$model_name"
mkdir -p -- "$target_dir" || exit 1
target="$target_dir/$filename"
if [[ -e "$target" ]]; then
  target="$target_dir/${basename_no_ext}_$(date '+%s').mp4"
fi
if mv -- "$full_path" "$target"; then
  log_message "文件已移动到上传队列: $target"
  exit 0
fi
log_message "错误：移动文件失败: $full_path"
exit 1
