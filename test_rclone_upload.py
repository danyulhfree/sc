from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import rclone_upload


class UploaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.queue = self.root / "up"
        self.queue.mkdir()
        self.status = self.root / "uploader_status.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def helper(self, body: str) -> Path:
        path = self.root / "helper.sh"
        path.write_text("#!/usr/bin/env bash\nset -eu\n" + body + "\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def uploader(self, helper: Path) -> rclone_upload.Uploader:
        return rclone_upload.Uploader(self.queue, self.status, helper, 5 * 1024 * 1024, 5)

    def add_file(self, name: str, size: int) -> Path:
        path = self.queue / "model" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            handle.truncate(size)
        return path

    def test_small_mp4_is_deleted_and_empty_directory_pruned(self) -> None:
        small = self.add_file("small.mp4", 1024)
        result = self.uploader(self.helper("exit 0")).run_once()
        self.assertEqual(result, 0)
        self.assertFalse(small.exists())
        self.assertFalse((self.queue / "model").exists())
        state = json.loads(self.status.read_text(encoding="utf-8"))
        self.assertEqual(state["queue_files"], 0)

    def test_confirmed_success_can_remove_source(self) -> None:
        source = self.add_file("ok.mp4", 6 * 1024 * 1024)
        helper = self.helper('find "$1" -type f -name "*.mp4" -delete\nexit 0')
        result = self.uploader(helper).run_once()
        self.assertEqual(result, 0)
        self.assertFalse(source.exists())
        state = json.loads(self.status.read_text(encoding="utf-8"))
        self.assertEqual(state["last_success"]["path"], "model/ok.mp4")

    def test_failure_and_uncertain_results_retain_source(self) -> None:
        for code, expected in ((1, "error"), (10, "uncertain")):
            with self.subTest(code=code):
                source = self.add_file(f"keep-{code}.mp4", 6 * 1024 * 1024)
                result = self.uploader(self.helper(f"exit {code}")).run_once()
                self.assertEqual(result, code)
                self.assertTrue(source.exists())
                state = json.loads(self.status.read_text(encoding="utf-8"))
                self.assertEqual(state["state"], expected)

    def test_process_lock_rejects_competitor(self) -> None:
        lock_path = self.root / "uploader.lock"
        first = rclone_upload.acquire_lock(lock_path)
        try:
            with self.assertRaises(RuntimeError):
                rclone_upload.acquire_lock(lock_path)
        finally:
            first.close()

    def test_shell_adapter_uses_fixed_official_api_arguments(self) -> None:
        capture = self.root / "arguments.json"
        guard = self.root / "guard.sh"
        guard.write_text(
            "fic_guard_acquire() { return 0; }\n"
            "fic_guard_release() { return 0; }\n"
            "fic_guard_record_status() { return 0; }\n",
            encoding="utf-8",
        )
        client = self.root / "fake_client.py"
        client.write_text(
            "import json, os, sys\n"
            "open(os.environ['ARG_CAPTURE'], 'w', encoding='utf-8').write(json.dumps(sys.argv[1:]))\n",
            encoding="utf-8",
        )
        source = self.queue.resolve()
        environment = os.environ.copy()
        environment.update(
            {
                "FIC_GUARD_LIB": str(guard),
                "FIC_UPLOAD_CLI": str(client),
                "FIC_UPLOAD_STATE": str(self.root / "fic.db"),
                "ARG_CAPTURE": str(capture),
            }
        )
        helper = Path(__file__).with_name("fic_upload_once.sh")
        completed = subprocess.run(
            [str(helper), str(source)],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        arguments = json.loads(capture.read_text(encoding="utf-8"))
        self.assertIn("--component", arguments)
        self.assertEqual(arguments[arguments.index("--component") + 1], "sc")
        self.assertEqual(arguments[arguments.index("--remote") + 1], "1f")
        self.assertEqual(arguments[arguments.index("--destination") + 1], "milo/strip")
        self.assertEqual(arguments[arguments.index("--source") + 1], str(source))


if __name__ == "__main__":
    unittest.main()
