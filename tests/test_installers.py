import hashlib
import http.server
import json
import os
import pathlib
import platform
import subprocess
import tempfile
import threading
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
WINDOWS = os.name == "nt"
EXTENSION = ".exe" if WINDOWS else ""
BINARY = ROOT / "target" / "debug" / f"upkit{EXTENSION}"


class Installers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="upkit installer test ")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.bin_dir = self.root / "bin"
        arch = "aarch64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
        system = {"Linux": "unknown-linux-gnu", "Darwin": "apple-darwin", "Windows": "pc-windows-msvc"}[platform.system()]
        self.asset = f"upkit-{arch}-{system}{EXTENSION}"
        self.binary = BINARY.read_bytes()
        self.assets = {
            self.asset: self.binary,
            "SHA256SUMS": f"{hashlib.sha256(self.binary).hexdigest()}  {self.asset}\n".encode(),
        }
        self.requests = []
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.requests.append(self.path)
                data = fixture.assets.get(self.path.removeprefix("/release/"))
                self.send_response(200 if data is not None else 404)
                self.end_headers()
                if data is not None:
                    self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.env = dict(os.environ)
        self.env.update(
            HOME=str(self.root),
            USERPROFILE=str(self.root),
            XDG_DATA_HOME=str(self.root / "data"),
            LOCALAPPDATA=str(self.root / "local"),
            UPKIT_INSTALLER="standalone",
            UPKIT_INSTALL_DIR=str(self.bin_dir),
            UPKIT_RELEASE_BASE_URL=f"http://127.0.0.1:{self.server.server_port}/release",
            UPKIT_NO_PATH_UPDATE="1",
        )

    def run_command(self, command):
        return subprocess.run(command, env=self.env, cwd=ROOT, capture_output=True, text=True, timeout=90)

    def install(self, release=VERSION):
        if WINDOWS:
            command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "install.ps1"), "-Release", release]
        else:
            command = ["sh", str(ROOT / "install.sh"), "--release", release]
        return self.run_command(command)

    def existing(self, data=b"previous installation"):
        self.bin_dir.mkdir(parents=True)
        destination = self.bin_dir / f"upkit{EXTENSION}"
        destination.write_bytes(data)
        destination.chmod(0o755)
        return destination

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_install_and_replace(self):
        destination = self.existing()
        self.assert_success(self.install())
        self.assertEqual(destination.read_bytes(), self.binary)
        result = self.run_command([str(destination), "--version"])
        self.assert_success(result)
        self.assertEqual(result.stdout.strip(), f"upkit {VERSION}")
        self.assertIn(f"/release/{self.asset}", self.requests)

    def test_latest(self):
        self.assert_success(self.install("latest"))
        self.assertEqual((self.bin_dir / f"upkit{EXTENSION}").read_bytes(), self.binary)

    def test_local_release_fixture(self):
        release_dir = self.root / "release assets"
        release_dir.mkdir()
        for name, data in self.assets.items():
            (release_dir / name).write_bytes(data)
        self.env["UPKIT_RELEASE_BASE_URL"] = str(release_dir)
        self.assert_success(self.install())
        self.assertEqual((self.bin_dir / f"upkit{EXTENSION}").read_bytes(), self.binary)
        self.assertEqual(self.requests, [])

    def test_checksum_failure_preserves_existing_install(self):
        destination = self.existing()
        self.assets["SHA256SUMS"] = f"{'0' * 64}  {self.asset}\n".encode()
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA256 mismatch", result.stderr)
        self.assertEqual(destination.read_bytes(), b"previous installation")

    def test_missing_checksum_preserves_existing_install(self):
        destination = self.existing()
        self.assets["SHA256SUMS"] = b""
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(destination.read_bytes(), b"previous installation")

    def test_wrong_version_preserves_existing_install(self):
        destination = self.existing()
        result = self.install("0.0.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)
        self.assertEqual(destination.read_bytes(), b"previous installation")

    def test_invalid_release_does_not_download(self):
        self.assertNotEqual(self.install("../invalid").returncode, 0)
        self.assertEqual(self.requests, [])

    @unittest.skipIf(WINDOWS, "POSIX shell syntax")
    def test_shell_syntax(self):
        self.assert_success(self.run_command(["sh", "-n", str(ROOT / "install.sh")]))

    @unittest.skipIf(WINDOWS, "Unix target detection")
    def test_unsupported_architecture_does_not_download(self):
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        uname = fake_bin / "uname"
        uname.write_text('#!/bin/sh\nif [ "$1" = -s ]; then echo Linux; else echo unsupported; fi\n')
        uname.chmod(0o755)
        self.env["PATH"] = str(fake_bin) + os.pathsep + self.env["PATH"]
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(self.requests, [])

    def test_standalone_self_update(self):
        destination = self.existing(self.binary)
        result = self.run_command([str(destination), "self-update", "--yes", "--json"])
        self.assert_success(result)
        report = json.loads(result.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(report["via"], "github")
        self.assertEqual(destination.read_bytes(), self.binary)
        self.assertIn(f"/release/{self.asset}", self.requests)

    def test_self_update_dry_run_does_not_download(self):
        destination = self.existing(self.binary)
        result = self.run_command([str(destination), "self-update", "--yes", "--json", "--dry-run"])
        self.assert_success(result)
        self.assertEqual(json.loads(result.stdout)["via"], "github")
        self.assertEqual(self.requests, [])

    def test_cargo_install_keeps_cargo_self_update(self):
        cargo_home = self.root / "cargo"
        self.bin_dir = cargo_home / "bin"
        self.env["CARGO_HOME"] = str(cargo_home)
        destination = self.existing(self.binary)
        result = self.run_command([str(destination), "self-update", "--yes", "--json", "--dry-run"])
        self.assert_success(result)
        self.assertEqual(json.loads(result.stdout)["via"], "cargo")
        self.assertEqual(self.requests, [])

    def test_self_update_checksum_failure_preserves_binary(self):
        destination = self.existing(self.binary)
        self.assets["SHA256SUMS"] = f"{'0' * 64}  {self.asset}\n".encode()
        result = self.run_command([str(destination), "self-update", "--yes", "--json"])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)["ok"])
        self.assertEqual(destination.read_bytes(), self.binary)


if __name__ == "__main__":
    unittest.main()
