#!/usr/bin/env python3
"""SC upload queue supervisor for the shared official 1Fichier client."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EXIT_STATES = {
    0: "idle",
    10: "uncertain",
    75: "blocked",
    76: "rate_limited",
    77: "auth_error",
    78: "flood_lock",
    124: "timeout",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log(level: str, message: str) -> None:
    print(f"[{utc_now()}] [{level}] {message}", flush=True)


@dataclass(frozen=True)
class QueueFile:
    path: Path
    relative: str
    size: int
    mtime_ns: int


def scan_queue(root: Path) -> list[QueueFile]:
    if not root.exists():
        return []
    files: list[QueueFile] = []
    for path in sorted(root.rglob("*.mp4")):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            stat = path.stat()
            files.append(
                QueueFile(
                    path=path,
                    relative=path.relative_to(root).as_posix(),
                    size=stat.st_size,
                    mtime_ns=stat.st_mtime_ns,
                )
            )
        except OSError:
            continue
    return files


def prune_empty_dirs(root: Path) -> int:
    if not root.exists():
        return 0
    removed = 0
    directories = sorted(
        (path for path in root.rglob("*") if path.is_dir() and not path.is_symlink()),
        key=lambda item: len(item.parts),
        reverse=True,
    )
    for directory in directories:
        try:
            directory.rmdir()
            removed += 1
        except OSError:
            pass
    return removed


def delete_small_files(root: Path, minimum: int) -> list[QueueFile]:
    deleted: list[QueueFile] = []
    for item in scan_queue(root):
        if item.size >= minimum:
            continue
        try:
            item.path.unlink()
            deleted.append(item)
            log("WARN", f"删除小于 {minimum} bytes 的 MP4: {item.relative} ({item.size} bytes)")
        except OSError as error:
            log("ERROR", f"无法删除小文件 {item.relative}: {error}")
    prune_empty_dirs(root)
    return deleted


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_status(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            return value
    except (OSError, ValueError):
        pass
    return {"version": 1, "state": "starting"}


class Uploader:
    def __init__(
        self,
        watch_dir: Path,
        status_file: Path,
        helper: Path,
        min_size_bytes: int,
        command_timeout: int,
    ) -> None:
        self.watch_dir = watch_dir
        self.status_file = status_file
        self.helper = helper
        self.min_size_bytes = min_size_bytes
        self.command_timeout = command_timeout
        self.status = load_status(status_file)

    def write_status(self, state: str, **changes: Any) -> None:
        queue = scan_queue(self.watch_dir)
        self.status.update(changes)
        self.status.update(
            {
                "version": 1,
                "updated_at": utc_now(),
                "state": state,
                "queue_files": len(queue),
                "queue_bytes": sum(item.size for item in queue),
            }
        )
        atomic_write_json(self.status_file, self.status)

    def run_once(self) -> int:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        deleted = delete_small_files(self.watch_dir, self.min_size_bytes)
        queue = scan_queue(self.watch_dir)
        if not queue:
            self.write_status("idle", last_cleanup_count=len(deleted))
            return 0
        if not self.helper.is_file() or not os.access(self.helper, os.X_OK):
            message = f"上传辅助脚本不可执行: {self.helper}"
            self.write_status(
                "error",
                last_error={"message": message, "code": 75, "at": utc_now()},
            )
            log("ERROR", message)
            return 75

        before = {item.relative: item for item in queue}
        self.write_status("uploading", last_cleanup_count=len(deleted))
        log("INFO", f"提交上传队列: {len(queue)} files, {sum(item.size for item in queue)} bytes")
        try:
            completed = subprocess.run(
                [str(self.helper), str(self.watch_dir)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=self.command_timeout,
                check=False,
            )
            output = (completed.stdout or "").strip()
            if output:
                print(output, flush=True)
            code = int(completed.returncode)
        except subprocess.TimeoutExpired as error:
            output = str(error)
            code = 124
        except OSError as error:
            output = str(error)
            code = 75

        after = {item.relative: item for item in scan_queue(self.watch_dir)}
        removed = [item for relative, item in before.items() if relative not in after]
        prune_empty_dirs(self.watch_dir)
        if code == 0:
            changes: dict[str, Any] = {"last_error": None}
            if removed:
                confirmed = removed[-1]
                changes["last_success"] = {
                    "path": confirmed.relative,
                    "bytes": confirmed.size,
                    "at": utc_now(),
                }
            self.write_status("idle", **changes)
            return 0

        state = EXIT_STATES.get(code, "error")
        message = output[-2000:] if output else f"upload helper exited with {code}"
        self.write_status(
            state,
            last_error={
                "path": queue[0].relative,
                "message": message,
                "code": code,
                "at": utc_now(),
            },
        )
        log("ERROR", f"上传批次未确认，文件保留: state={state}, exit={code}")
        return code


def acquire_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise RuntimeError(f"another SC uploader holds {path}")
    handle.seek(0)
    handle.truncate()
    handle.write(f"{os.getpid()}\n")
    handle.flush()
    return handle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-dir", type=Path, required=True)
    parser.add_argument("--status-file", type=Path, required=True)
    parser.add_argument("--lock-file", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--min-size-bytes", type=int, default=5 * 1024 * 1024)
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--command-timeout", type=int, default=14_500)
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.min_size_bytes < 1 or args.interval <= 0 or args.command_timeout < 1:
        raise SystemExit("invalid numeric argument")
    try:
        lock = acquire_lock(args.lock_file.resolve())
    except RuntimeError as error:
        log("ERROR", str(error))
        return 75

    stopping = False

    def request_stop(_signum, _frame) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    uploader = Uploader(
        args.watch_dir.resolve(),
        args.status_file.resolve(),
        args.helper.resolve(),
        args.min_size_bytes,
        args.command_timeout,
    )
    try:
        while not stopping:
            result = uploader.run_once()
            if args.once:
                return result
            deadline = time.monotonic() + args.interval
            while not stopping and time.monotonic() < deadline:
                time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        uploader.write_status("stopped")
        return 0
    finally:
        lock.close()


if __name__ == "__main__":
    raise SystemExit(main())
