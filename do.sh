#!/bin/bash
source /root/u/milo.conf
num=${#milolist[@]}
((num--))
runtime=0

# 定义小文件的大小阈值(单位:字节)，默认为5MB
MIN_FILE_SIZE=$((5 * 1024 * 1024))
LOG_FILE="rclone_upload.log"
CLEAN_LOG="file_cleanup.log"
# 传输稳定性与重试参数（可按需调整）
CONNECT_TIMEOUT="15s"       # 建连超时
IO_TIMEOUT="5m"             # 传输空闲超时，超过该时间无数据传输则中断并重试
EXPECT_CONTINUE="2s"        # HTTP 100-continue 等待时间
RETRIES=10                   # 高层重试次数
LOW_LEVEL_RETRIES=20         # 底层重试次数
RETRIES_SLEEP="30s"         # 重试间隔
TRANSFERS=4                  # 并发传输数
CHECKERS=8                   # 并发校验数
TPSLIMIT=2                   # 每秒请求限制，视网盘策略可适当调大/调小
BUFFER_SIZE="32M"           # 缓冲区大小
STATS="30s"                 # 统计输出间隔（配合 -P）
# 进程看门狗（可用 timeout/gtimeout 包装 rclone，防止永久挂起）
MAX_RCLONE_RUN="6h"         # rclone 单次运行最长允许时间
KILL_AFTER="30s"            # 超时后宽限期，随后强制 kill
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
else
  TIMEOUT_BIN=""
fi

# 函数: 清理过小的文件
function cleanup_small_files() {
    local directory="$1"
    local current_time=$(date "+%Y-%m-%d %H:%M:%S")
    
    echo "[${current_time}] 开始清理目录 ${directory} 中的小文件 (小于 ${MIN_FILE_SIZE} 字节)" >> $CLEAN_LOG
    
    find "$directory" -type f -name "*.mp4" -size -${MIN_FILE_SIZE}c | while read -r file; do
        # 根据操作系统类型使用不同的stat命令
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            file_size=$(stat -f "%z" "$file")
        else
            # Linux及其他系统
            file_size=$(stat -c "%s" "$file")
        fi
        echo "[${current_time}] 删除小文件: $file (大小: ${file_size} 字节)" >> $CLEAN_LOG
        rm -f "$file"
    done
    
    # 清理空目录
    find "$directory" -type d -empty -delete
    
    echo "[${current_time}] 清理完成" >> $CLEAN_LOG
}

while [ true ]
do
  # 检查和清理过小的录制文件 (每次循环都执行)
  if [ -d "videos" ]; then
    cleanup_small_files "videos"
  fi
  
  # 处理上传队列
  while [ -d "up" ]
  do
      temp=${milolist[0]}
      echo "$temp"
      echo "保存ts到${temp}:milo/strip"
      
      # 清理上传目录中的小文件
      cleanup_small_files "up"
      
      # 定义变量
      source_dir="up"
      dest_dir="${temp}:milo/strip"

      # 若 up 为空则跳过，避免无意义的 rclone 调用
      if [ -z "$(ls -A "$source_dir" 2>/dev/null)" ]; then
        sleep 10
        continue
      fi

      # 组装 rclone 命令
      RCLONE_CMD=(
        rclone move "$source_dir" "$dest_dir"
        --buffer-size "$BUFFER_SIZE"
        --transfers "$TRANSFERS"
        --checkers "$CHECKERS"
        --tpslimit "$TPSLIMIT"
        -P --stats "$STATS"
        --contimeout "$CONNECT_TIMEOUT"
        --timeout "$IO_TIMEOUT"
        --expect-continue-time "$EXPECT_CONTINUE"
        --low-level-retries "$LOW_LEVEL_RETRIES"
        --retries "$RETRIES"
        --retries-sleep "$RETRIES_SLEEP"
        --log-file="$LOG_FILE" --log-level=ERROR
      )

      # 执行 rclone（若有 timeout/gtimeout 则使用，看门狗防卡死）
      if [ -n "$TIMEOUT_BIN" ]; then
        "$TIMEOUT_BIN" -k "$KILL_AFTER" "$MAX_RCLONE_RUN" "${RCLONE_CMD[@]}"
      else
        "${RCLONE_CMD[@]}"
      fi
      rc=$?
      if [ $rc -ne 0 ]; then
        echo "rclone 发生错误 (退出码: $rc)，可能是网络抖动或网盘限速导致，稍后将重试..."
      fi

      # 检查日志中是否有上传失败的文件
      failed_files=$(grep -E "Failed to (copy|move)" "$LOG_FILE" | awk -F ' : ' '{print $2}' | awk -F': ' '{print $1}')
      if [ -n "$failed_files" ]; then
        echo "以下文件上传失败，将删除这些文件："
        echo "$failed_files"

        # 删除上传失败的文件
        while IFS= read -r file; do
          if [ -f "$source_dir/$file" ]; then
              rm -f "$source_dir/$file"
              echo "已删除文件：$source_dir/$file"
          fi
        done <<< "$failed_files"
      fi

      # 清理日志文件
      rm -f "$LOG_FILE"

      # 执行 rclone rmdirs 清理空目录
      rclone rmdirs "$source_dir"
      
      # 检查up目录是否存在且为空
      if [ ! -d "$source_dir" ] || [ -z "$(ls -A $source_dir 2>/dev/null)" ]; then
          echo "up上传成功，目录已清空"
          let runtime++
          if [ $runtime -ge 25 ]
          then
              source /root/u/milo.conf
              runtime=0
          fi
      fi
      sleep 60
  done
  sleep 10
done
