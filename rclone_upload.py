#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Optional, Tuple, Union

# 强制行缓冲，确保日志立即输出
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(line_buffering=True)


DEFAULT_INCLUDE_EXTS = {
    ".mp4",
    ".mkv",
    ".flv",
    ".ts",
    ".mp3",
    ".m4a",
    ".srt",
    ".ass",
}

DEFAULT_EXCLUDE_GLOBS = [
    ".DS_Store",
    "Thumbs.db",
    "*.tmp",
    "*.part",
    "*.partial",
    "*.download",
    "*.aria2",
]


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def log(level: str, msg: str) -> None:
    print(f"[{level} {_ts()}] {msg}", flush=True)


def parse_bool(s: Optional[Union[str, bool]]) -> Optional[bool]:
    if s is None:
        return None
    if isinstance(s, bool):
        return s
    v = str(s).strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return None


def load_recorder_config(config_path: Path) -> dict[str, str]:
    if not config_path.exists():
        return {}

    parser = configparser.RawConfigParser()
    try:
        parser.read(config_path, encoding="utf-8-sig")
    except Exception as e:
        log("WARN", f"读取配置失败: {config_path} ({e})")
        return {}

    def _get(section: str, key: str) -> str:
        try:
            return (parser.get(section, key, fallback="") or "").strip()
        except Exception:
            return ""

    return {
        "video_save_path": _get("录制设置", "直播保存路径(不填则默认)"),
        "converts_to_mp4": _get("录制设置", "录制完成后自动转为mp4格式"),
        "video_save_type": _get("录制设置", "视频保存格式ts|mkv|flv|mp4|mp3音频|m4a音频"),
    }


def resolve_watch_dir(project_root: Path, config_ini: Path, override: Optional[str]) -> Path:
    if override:
        return Path(os.path.expandvars(os.path.expanduser(override))).resolve()

    cfg = load_recorder_config(config_ini)
    raw = cfg.get("video_save_path", "").strip()
    if raw:
        p = Path(os.path.expandvars(os.path.expanduser(raw)))
        return (p if p.is_absolute() else (project_root / p)).resolve()

    # 兼容本仓库默认结构：优先用 ./up 作为上传队列目录
    if (project_root / "up").exists():
        return (project_root / "up").resolve()

    return (project_root / "downloads").resolve()


def split_csv(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def normalize_exts(exts: list[str]) -> set[str]:
    out: set[str] = set()
    for e in exts:
        if not e:
            continue
        e = e.strip().lower()
        if not e:
            continue
        if not e.startswith("."):
            e = "." + e
        out.add(e)
    return out


def should_exclude(rel_posix: str, name: str, exclude_globs: list[str]) -> bool:
    for pat in exclude_globs:
        if fnmatch(name, pat) or fnmatch(rel_posix, pat):
            return True
    return False


def is_small_file(path: Path, size: int, *, min_size_bytes: int, min_size_exts: set[str]) -> bool:
    if min_size_bytes <= 0:
        return False
    if min_size_exts and path.suffix.lower() not in min_size_exts:
        return False
    return int(size) < int(min_size_bytes)


def prune_empty_dirs(root: Path) -> int:
    removed = 0
    if not root.exists():
        return removed

    for dirpath, _, _ in os.walk(root, topdown=False):
        p = Path(dirpath)
        if p == root:
            continue
        try:
            next(p.iterdir())
        except StopIteration:
            try:
                p.rmdir()
                removed += 1
            except OSError:
                pass
        except OSError:
            pass
    return removed


@dataclass
class Seen:
    size: int
    mtime: float
    stable_hits: int
    last_seen: float


def join_rclone_path(dest_root: str, rel_posix: str) -> str:
    root = dest_root.rstrip("/")
    rel = rel_posix.lstrip("/")
    if not rel:
        return root
    if root.endswith(":"):
        return root + rel
    return root + "/" + rel


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_state(state_path: Path) -> dict[str, Any]:
    if not state_path.exists():
        return {"version": 1, "uploads": {}}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "uploads": {}}


def mark_uploaded(state: dict[str, Any], rel_posix: str, size: int, mtime: float) -> None:
    uploads = state.setdefault("uploads", {})
    uploads[rel_posix] = {"size": size, "mtime": mtime, "uploaded_at": time.time()}


def already_uploaded(state: dict[str, Any], rel_posix: str, size: int, mtime: float) -> bool:
    uploads = state.get("uploads", {})
    entry = uploads.get(rel_posix)
    if not isinstance(entry, dict):
        return False
    try:
        return int(entry.get("size")) == int(size) and float(entry.get("mtime")) == float(mtime)
    except Exception:
        return False


def build_rclone_base_cmd(rclone_bin: str, rclone_config: Optional[str], extra_args: list[str]) -> list[str]:
    cmd = [rclone_bin]
    if rclone_config:
        cmd.extend(["--config", rclone_config])
    cmd.extend(extra_args)
    return cmd


def run_rclone_file(
    *,
    action: str,
    source: Path,
    dest: str,
    rclone_base: list[str],
    dry_run: bool,
    retries: int,
    retry_sleep: float,
    show_progress: bool = True,
) -> bool:
    if action not in {"copyto", "moveto"}:
        raise ValueError(f"unsupported action: {action}")

    cmd = [*rclone_base, action, str(source), dest]
    # 添加 --progress 以显示实时进度
    if show_progress and "--progress" not in cmd and "-P" not in cmd:
        cmd.append("--progress")

    if dry_run:
        log("INFO", f"[DRY-RUN] {' '.join(cmd)}")
        return True

    for attempt in range(1, retries + 1):
        try:
            log("INFO", f"rclone {action}: {source} -> {dest} (attempt {attempt}/{retries})")
            # 使用 Popen 让 stderr 实时输出到终端（rclone 的进度信息走 stderr）
            # stdout 不太重要，可以捕获用于 DEBUG
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=None,  # stderr 直接继承到终端，显示实时进度
                text=True,
            )
            stdout_data, _ = proc.communicate()
            if proc.returncode == 0:
                if stdout_data and stdout_data.strip():
                    log("INFO", stdout_data.strip())
                return True
            if stdout_data and stdout_data.strip():
                log("WARN", stdout_data.strip())
        except FileNotFoundError:
            log("ERROR", f"找不到 rclone: {rclone_base[0]}")
            return False
        except Exception as e:
            log("WARN", f"执行 rclone 异常: {e}")

        if attempt < retries:
            time.sleep(retry_sleep)

    return False


def run_rclone_dir(
    *,
    action: str,
    source_dir: Path,
    dest: str,
    files_to_upload: list[str],
    rclone_base: list[str],
    dry_run: bool,
    retries: int,
    retry_sleep: float,
    show_progress: bool = True,
) -> bool:
    """使用 rclone copy/move 批量上传目录中指定的文件列表。
    
    利用 --files-from 参数指定要上传的文件，rclone 会使用 --transfers 并发上传。
    """
    if action not in {"copy", "move"}:
        raise ValueError(f"unsupported action: {action}")
    
    if not files_to_upload:
        return True
    
    # 创建临时文件列表
    import tempfile
    files_from_path = Path(tempfile.gettempdir()) / f"rclone_files_{os.getpid()}.txt"
    try:
        files_from_path.write_text("\n".join(files_to_upload) + "\n", encoding="utf-8")
    except Exception as e:
        log("ERROR", f"创建文件列表失败: {e}")
        return False
    
    cmd = [*rclone_base, action, str(source_dir), dest, f"--files-from={files_from_path}"]
    if show_progress and "--progress" not in cmd and "-P" not in cmd:
        cmd.append("--progress")
    
    if dry_run:
        log("INFO", f"[DRY-RUN] {' '.join(cmd)}")
        log("INFO", f"[DRY-RUN] 文件列表: {files_to_upload}")
        try:
            files_from_path.unlink()
        except Exception:
            pass
        return True
    
    success = False
    for attempt in range(1, retries + 1):
        try:
            log("INFO", f"rclone {action}: {source_dir} -> {dest} ({len(files_to_upload)} 个文件, attempt {attempt}/{retries})")
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=None,  # stderr 直接继承到终端，显示实时进度
                text=True,
            )
            stdout_data, _ = proc.communicate()
            if proc.returncode == 0:
                if stdout_data and stdout_data.strip():
                    log("INFO", stdout_data.strip())
                success = True
                break
            if stdout_data and stdout_data.strip():
                log("WARN", stdout_data.strip())
        except FileNotFoundError:
            log("ERROR", f"找不到 rclone: {rclone_base[0]}")
            break
        except Exception as e:
            log("WARN", f"执行 rclone 异常: {e}")
        
        if attempt < retries:
            time.sleep(retry_sleep)
    
    # 清理临时文件
    try:
        files_from_path.unlink()
    except Exception:
        pass
    
    return success


def wait_until_stable(path: Path, *, stable_checks: int, interval: float, max_wait: float) -> Tuple[bool, int, float]:
    start = time.time()
    prev: Optional[Tuple[int, float]] = None
    hits = 0

    while True:
        try:
            st = path.stat()
        except FileNotFoundError:
            return False, 0, 0.0

        cur = (int(st.st_size), float(st.st_mtime))
        if prev is None:
            prev = cur
            hits = 0
        elif cur == prev:
            hits += 1
            if hits >= stable_checks:
                return True, cur[0], cur[1]
        else:
            prev = cur
            hits = 0

        if time.time() - start >= max_wait:
            return False, cur[0], cur[1]

        time.sleep(interval)


def iter_files(watch_dir: Path, include_exts: set[str], exclude_globs: list[str]) -> list[Path]:
    files: list[Path] = []
    if not watch_dir.exists():
        return files
    for p in watch_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.name.startswith("."):
            continue
        rel = p.relative_to(watch_dir).as_posix()
        if should_exclude(rel, p.name, exclude_globs):
            continue
        if include_exts and p.suffix.lower() not in include_exts:
            continue
        files.append(p)
    return files


def scan_stable_files(
    *,
    watch_dir: Path,
    include_exts: set[str],
    exclude_globs: list[str],
    seen: dict[str, Seen],
    min_age: float,
    stable_checks: int,
    min_size_bytes: int,
    min_size_exts: set[str],
    delete_small: bool,
    state: dict[str, Any],
    now: float,
) -> Tuple[list[Tuple[Path, str, int, float]], bool]:
    stable: list[Tuple[Path, str, int, float]] = []
    current_keys: set[str] = set()
    did_local_delete = False

    for p in iter_files(watch_dir, include_exts, exclude_globs):
        try:
            st = p.stat()
        except FileNotFoundError:
            continue

        rel = p.relative_to(watch_dir).as_posix()
        current_keys.add(rel)

        size = int(st.st_size)
        mtime = float(st.st_mtime)

        if already_uploaded(state, rel, size, mtime):
            continue

        # watch 模式下，先等文件“老一点”，避免处理仍在写入的文件
        if (now - mtime) < min_age:
            prev = seen.get(rel)
            if prev is None:
                seen[rel] = Seen(size=size, mtime=mtime, stable_hits=0, last_seen=now)
            else:
                if prev.size != size or prev.mtime != mtime:
                    prev.size = size
                    prev.mtime = mtime
                    prev.stable_hits = 0
                prev.last_seen = now
            continue

        if is_small_file(p, size, min_size_bytes=min_size_bytes, min_size_exts=min_size_exts):
            if delete_small:
                try:
                    p.unlink()
                    did_local_delete = True
                    log("INFO", f"删除过小文件: {p} ({size} bytes)")
                except Exception as e:
                    log("WARN", f"删除过小文件失败: {p} ({e})")
            continue

        prev = seen.get(rel)
        if prev is None:
            seen[rel] = Seen(size=size, mtime=mtime, stable_hits=0, last_seen=now)
            continue

        if prev.size == size and prev.mtime == mtime:
            prev.stable_hits += 1
        else:
            prev.size = size
            prev.mtime = mtime
            prev.stable_hits = 0
        prev.last_seen = now

        if prev.stable_hits >= stable_checks:
            stable.append((p, rel, size, mtime))

    # prune deleted files from seen
    for k in list(seen.keys()):
        if k not in current_keys and (now - seen[k].last_seen) > (min_age + 60):
            del seen[k]

    stable.sort(key=lambda x: x[1])
    return stable, did_local_delete


def derive_hook_matcher(save_file_path: str, target_ext: Optional[str]) -> Tuple[Path, re.Pattern[str]]:
    p = Path(save_file_path)
    name = p.name
    if target_ext:
        name = re.sub(r"\.[^.]+$", target_ext, name)

    escaped = re.escape(name)

    def repl(m: re.Match[str]) -> str:
        width = (m.group(1) or "").strip()
        if width.isdigit():
            return rf"\d{{{int(width)}}}"
        return r"\d+"

    # ffmpeg segment filename, e.g. xxx_%03d.ts
    pattern = re.sub(r"%0?(\d*)d", repl, escaped)
    return p.parent, re.compile(rf"^{pattern}$")


def upload_hook(
    *,
    save_file_path: str,
    save_type: Optional[str],
    converts_to_mp4: Optional[bool],
    dest_root: str,
    watch_dir: Path,
    include_exts: set[str],
    exclude_globs: list[str],
    min_size_bytes: int,
    min_size_exts: set[str],
    delete_small: bool,
    rclone_base: list[str],
    mode: str,
    dry_run: bool,
    retries: int,
    retry_sleep: float,
    stable_checks: int,
    interval: float,
    max_wait: float,
    state: dict[str, Any],
    state_file: Path,
) -> int:
    save_type_norm = (save_type or "").strip().upper()
    want_mp4 = bool(converts_to_mp4) and save_type_norm == "TS"

    target_ext = ".mp4" if want_mp4 else None
    parent, matcher = derive_hook_matcher(save_file_path, target_ext)

    start = time.time()
    matched: list[Path] = []
    while True:
        try:
            matched = [p for p in parent.iterdir() if p.is_file() and matcher.match(p.name)]
        except FileNotFoundError:
            matched = []
        if matched:
            break
        if time.time() - start >= max_wait:
            log("WARN", f"未找到匹配文件(超时): {parent}")
            return 0
        time.sleep(interval)

    exit_code = 0
    action = "moveto" if mode == "move" else "copyto"

    for p in sorted(matched):
        if p.name.startswith("."):
            continue
        if include_exts and p.suffix.lower() not in include_exts:
            continue
        try:
            rel = p.resolve().relative_to(watch_dir.resolve()).as_posix()
        except Exception:
            rel = p.name
        if should_exclude(rel, p.name, exclude_globs):
            continue

        ok, size, mtime = wait_until_stable(p, stable_checks=stable_checks, interval=interval, max_wait=max_wait)
        if not ok:
            log("WARN", f"文件长时间不稳定，跳过: {p}")
            continue
        if is_small_file(p, size, min_size_bytes=min_size_bytes, min_size_exts=min_size_exts):
            if delete_small and not dry_run:
                try:
                    p.unlink()
                    log("INFO", f"删除过小文件: {p} ({size} bytes)")
                except Exception as e:
                    log("WARN", f"删除过小文件失败: {p} ({e})")
            continue
        if already_uploaded(state, rel, size, mtime):
            continue

        dest = join_rclone_path(dest_root, rel)
        if run_rclone_file(
            action=action,
            source=p,
            dest=dest,
            rclone_base=rclone_base,
            dry_run=dry_run,
            retries=retries,
            retry_sleep=retry_sleep,
        ):
            if not dry_run:
                mark_uploaded(state, rel, size, mtime)
                atomic_write_json(state_file, state)
        else:
            exit_code = 2

    return exit_code


def main() -> int:
    project_root = Path(__file__).resolve().parent
    default_config_ini = project_root / "config" / "config.ini"

    ap = argparse.ArgumentParser(description="自动扫描录制文件并用 rclone 上传（支持 watch/once 以及录制完成 hook）")
    ap.add_argument("--dest", help="rclone 目标路径，例如: remote:backup/xhs (或 1f:milo/xhs)")
    ap.add_argument("--dest-env", default="RCLONE_UPLOAD_DEST", help="从该环境变量读取 --dest (默认: RCLONE_UPLOAD_DEST)")
    ap.add_argument("--watch-dir", help="要扫描的目录（默认从配置读取，否则为 ./up 或 ./downloads）")
    ap.add_argument("--state-file", help="上传状态文件（默认: ./logs/rclone_upload_state.json）")

    ap.add_argument("--mode", choices=["copy", "move"], default="copy", help="copy: 保留本地文件；move: 上传后删除本地")
    ap.add_argument("--rclone", default="rclone", help="rclone 可执行文件名/路径 (默认: rclone)")
    ap.add_argument("--rclone-config", help="rclone 配置文件路径（可选）")
    ap.add_argument("--rclone-arg", action="append", default=[], help="额外 rclone 参数，可重复，如: --rclone-arg=--transfers=4")

    ap.add_argument("--include-ext", default=",".join(sorted(DEFAULT_INCLUDE_EXTS)), help="只处理这些扩展名(逗号分隔)")
    ap.add_argument("--exclude-glob", action="append", default=[], help="排除匹配的文件/路径(glob)，可重复")

    ap.add_argument("--scan-interval", type=float, default=10.0, help="watch 模式扫描间隔秒数")
    ap.add_argument("--min-age", type=float, default=30.0, help="文件最后修改时间距现在>=该秒数才会尝试上传")
    ap.add_argument("--stable-checks", type=int, default=3, help="连续稳定检查次数（配合扫描间隔/等待间隔）")
    ap.add_argument("--wait-interval", type=float, default=2.0, help="hook/等待稳定时的检查间隔秒数")
    ap.add_argument("--max-wait", type=float, default=600.0, help="等待文件出现/稳定的最大秒数（hook）")

    ap.add_argument("--retries", type=int, default=3, help="每个文件 rclone 重试次数")
    ap.add_argument("--retry-sleep", type=float, default=5.0, help="rclone 重试间隔秒数")
    ap.add_argument("--dry-run", action="store_true", help="仅打印要执行的 rclone 命令，不实际上传/不写入状态")

    ap.add_argument("--min-size-bytes", type=int, default=0, help="小于该字节数的文件将跳过（<=0 表示不启用）")
    ap.add_argument(
        "--min-size-ext",
        default="",
        help="仅对这些扩展名启用 min-size-bytes（逗号分隔；留空表示对所有 include-ext 生效）",
    )
    ap.add_argument("--delete-small", action="store_true", help="配合 min-size-bytes：删除过小文件（仅在判定安全时执行）")
    ap.add_argument("--prune-empty-dirs", action="store_true", help="在 move/删除小文件后，清理 watch_dir 下的空目录")

    ap.add_argument("--watch", action="store_true", help="循环扫描并上传")
    ap.add_argument("--once", action="store_true", help="只扫描上传一次然后退出")

    # 参数兼容：DouyinLiveRecorder 录制完成后自定义脚本（python）会自动追加这些参数
    ap.add_argument("--record_name")
    ap.add_argument("--save_file_path")
    ap.add_argument("--save_type")
    ap.add_argument("--split_video_by_time")
    ap.add_argument("--converts_to_mp4")

    args = ap.parse_args()

    dest = (args.dest or os.environ.get(args.dest_env) or "").strip()
    if not dest:
        log("ERROR", f"缺少 --dest（或设置环境变量 {args.dest_env}）")
        return 2

    watch_dir = resolve_watch_dir(project_root, default_config_ini, args.watch_dir)
    state_file = Path(args.state_file).expanduser().resolve() if args.state_file else (project_root / "logs" / "rclone_upload_state.json")

    include_exts = normalize_exts(split_csv(args.include_ext))
    exclude_globs = [*DEFAULT_EXCLUDE_GLOBS, *args.exclude_glob]

    min_size_bytes = max(0, int(args.min_size_bytes))
    min_size_exts = normalize_exts(split_csv(args.min_size_ext)) if args.min_size_ext else set()
    if min_size_bytes > 0 and not min_size_exts:
        min_size_exts = set(include_exts)

    rclone_base = build_rclone_base_cmd(args.rclone, args.rclone_config, args.rclone_arg)

    state = load_state(state_file)
    seen: dict[str, Seen] = {}

    converts_to_mp4 = parse_bool(args.converts_to_mp4)

    # hook 模式：给了 save_file_path 且未显式要求 watch/once 时，默认按 hook 执行后退出
    if args.save_file_path and not args.watch and not args.once:
        return upload_hook(
            save_file_path=args.save_file_path,
            save_type=args.save_type,
            converts_to_mp4=converts_to_mp4,
            dest_root=dest,
            watch_dir=watch_dir,
            include_exts=include_exts,
            exclude_globs=exclude_globs,
            min_size_bytes=min_size_bytes,
            min_size_exts=min_size_exts,
            delete_small=bool(args.delete_small),
            rclone_base=rclone_base,
            mode=args.mode,
            dry_run=bool(args.dry_run),
            retries=max(1, int(args.retries)),
            retry_sleep=max(0.0, float(args.retry_sleep)),
            stable_checks=max(1, int(args.stable_checks)),
            interval=max(0.2, float(args.wait_interval)),
            max_wait=max(1.0, float(args.max_wait)),
            state=state,
            state_file=state_file,
        )

    if not args.watch and not args.once:
        log("ERROR", "请指定 --watch 或 --once，或者通过录制完成 hook 调用(传入 --save_file_path)")
        return 2

    log("INFO", f"watch_dir: {watch_dir}")
    log("INFO", f"dest: {dest}")
    log("INFO", f"mode: {args.mode}")
    log("INFO", f"include_ext: {','.join(sorted(include_exts))}")
    if min_size_bytes > 0:
        log("INFO", f"min_size_bytes: {min_size_bytes} (exts: {','.join(sorted(min_size_exts))}) delete_small={bool(args.delete_small)}")
    if args.prune_empty_dirs:
        log("INFO", "prune_empty_dirs: enabled")
    if args.dry_run:
        log("INFO", "DRY-RUN: 不会实际上传/不会写入状态")

    action_dir = "move" if args.mode == "move" else "copy"

    def maybe_prune(need: bool) -> None:
        if not need or not args.prune_empty_dirs:
            return
        removed = prune_empty_dirs(watch_dir)
        if removed:
            log("INFO", f"已清理空目录: {removed} 个")

    def do_one_pass_watch() -> int:
        now = time.time()
        stable, did_local_delete = scan_stable_files(
            watch_dir=watch_dir,
            include_exts=include_exts,
            exclude_globs=exclude_globs,
            seen=seen,
            min_age=max(0.0, float(args.min_age)),
            stable_checks=max(1, int(args.stable_checks)),
            min_size_bytes=min_size_bytes,
            min_size_exts=min_size_exts,
            delete_small=bool(args.delete_small) and not bool(args.dry_run),
            state=state,
            now=now,
        )
        if not stable:
            maybe_prune(did_local_delete)
            return 0

        # 收集待上传文件的相对路径列表
        files_to_upload = [rel for _, rel, _, _ in stable]
        file_info = {rel: (size, mtime) for _, rel, size, mtime in stable}
        
        rc = 0
        if run_rclone_dir(
            action=action_dir,
            source_dir=watch_dir,
            dest=dest,
            files_to_upload=files_to_upload,
            rclone_base=rclone_base,
            dry_run=bool(args.dry_run),
            retries=max(1, int(args.retries)),
            retry_sleep=max(0.0, float(args.retry_sleep)),
        ):
            # 批量上传成功，记录所有文件状态
            if not args.dry_run:
                for rel in files_to_upload:
                    size, mtime = file_info[rel]
                    mark_uploaded(state, rel, size, mtime)
                atomic_write_json(state_file, state)
        else:
            rc = 2
        
        maybe_prune(args.mode == "move" or did_local_delete)
        return rc

    def do_one_pass_once() -> int:
        now = time.time()
        rc = 0
        min_age_val = max(0.0, float(args.min_age))
        stable_checks_val = max(1, int(args.stable_checks))
        interval = max(0.2, float(args.wait_interval))
        max_wait_val = max(1.0, float(args.max_wait))
        did_local_delete = False
        
        # 收集待上传文件
        files_to_upload: list[str] = []
        file_info: dict[str, tuple[int, float]] = {}

        for p in sorted(iter_files(watch_dir, include_exts, exclude_globs), key=lambda x: x.as_posix()):
            try:
                st = p.stat()
            except FileNotFoundError:
                continue
            if (now - float(st.st_mtime)) < min_age_val:
                continue

            size = int(st.st_size)
            mtime = float(st.st_mtime)
            if is_small_file(p, size, min_size_bytes=min_size_bytes, min_size_exts=min_size_exts):
                if args.delete_small and not args.dry_run:
                    try:
                        p.unlink()
                        did_local_delete = True
                        log("INFO", f"删除过小文件: {p} ({size} bytes)")
                    except Exception as e:
                        log("WARN", f"删除过小文件失败: {p} ({e})")
                continue

            try:
                rel = p.resolve().relative_to(watch_dir.resolve()).as_posix()
            except Exception:
                rel = p.name

            if already_uploaded(state, rel, size, mtime):
                continue

            ok, size2, mtime2 = wait_until_stable(p, stable_checks=stable_checks_val, interval=interval, max_wait=max_wait_val)
            if not ok:
                continue
            if is_small_file(p, size2, min_size_bytes=min_size_bytes, min_size_exts=min_size_exts):
                if args.delete_small and not args.dry_run:
                    try:
                        p.unlink()
                        did_local_delete = True
                        log("INFO", f"删除过小文件: {p} ({size2} bytes)")
                    except Exception as e:
                        log("WARN", f"删除过小文件失败: {p} ({e})")
                continue
            if already_uploaded(state, rel, size2, mtime2):
                continue
            
            files_to_upload.append(rel)
            file_info[rel] = (size2, mtime2)
        
        if not files_to_upload:
            maybe_prune(did_local_delete)
            return 0
        
        if run_rclone_dir(
            action=action_dir,
            source_dir=watch_dir,
            dest=dest,
            files_to_upload=files_to_upload,
            rclone_base=rclone_base,
            dry_run=bool(args.dry_run),
            retries=max(1, int(args.retries)),
            retry_sleep=max(0.0, float(args.retry_sleep)),
        ):
            if not args.dry_run:
                for rel in files_to_upload:
                    size, mtime = file_info[rel]
                    mark_uploaded(state, rel, size, mtime)
                atomic_write_json(state_file, state)
        else:
            rc = 2

        maybe_prune(args.mode == "move" or did_local_delete)
        return rc

    if args.once:
        return do_one_pass_once()

    try:
        while True:
            do_one_pass_watch()
            time.sleep(max(0.2, float(args.scan_interval)))
    except KeyboardInterrupt:
        log("INFO", "收到 Ctrl+C，退出")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

