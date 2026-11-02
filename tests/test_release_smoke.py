#!/usr/bin/env python3
"""Verify a native release binary without touching the user's environment."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_release_smoke.py BINARY VERSION")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    expected = sys.argv[2]
    with tempfile.TemporaryDirectory(prefix="upkit-release-smoke-") as temporary:
        root = Path(temporary)
        env = os.environ.copy()
        for name in (
            "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
            "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR", "TMP", "TEMP", "TMPDIR",
        ):
            env[name] = str(root)

        def run(*args):
            result = subprocess.run(
                [binary, *args],
                cwd=root,
                env=env,
                capture_output=True,
                timeout=20,
                check=True,
            )
            if b"\x1b" in result.stdout or b"\x1b" in result.stderr:
                raise RuntimeError("non-interactive output contained terminal escapes")
            return result.stdout

        if run("--version").decode().strip() != f"upkit {expected}":
            raise RuntimeError("binary version did not match the release")
        if b"Usage:" not in run("--help"):
            raise RuntimeError("binary help was unavailable")
        report = json.loads(
            run(
                "--offline", "--non-interactive", "--json",
                "--home", str(root / "managed"), "--bindir", str(root / "bin"),
                "version",
            )
        )
        if report.get("version") != expected:
            raise RuntimeError("JSON version did not match the release")
        if any(root.iterdir()):
            raise RuntimeError("inspection unexpectedly changed the isolated home")
    print("Standalone release smoke test passed")


if __name__ == "__main__":
    main()
