import hashlib
import http.server
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import threading
import time
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
WINDOWS = os.name == "nt"
EXTENSION = ".exe" if WINDOWS else ""
BINARY = ROOT / "target" / "debug" / f"upkit{EXTENSION}"
POWERSHELL = "powershell.exe" if WINDOWS else os.environ.get("UPKIT_PWSH") or shutil.which("pwsh")


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
            APPDATA=str(self.root / "appdata"),
            XDG_DATA_HOME=str(self.root / "data"),
            XDG_CONFIG_HOME=str(self.root / "config"),
            XDG_CACHE_HOME=str(self.root / "cache"),
            XDG_STATE_HOME=str(self.root / "state"),
            XDG_RUNTIME_DIR=str(self.root),
            LOCALAPPDATA=str(self.root / "local"),
            CARGO_HOME=str(self.root / "cargo"),
            RUSTUP_HOME=str(self.root / "rustup"),
            TMP=str(self.root),
            TEMP=str(self.root),
            TMPDIR=str(self.root),
            UPKIT_INSTALLER="standalone",
            UPKIT_INSTALL_DIR=str(self.bin_dir),
            UPKIT_RELEASE_BASE_URL=f"http://127.0.0.1:{self.server.server_port}/release",
            UPKIT_NO_PATH_UPDATE="1",
        )
        if WINDOWS:
            self.env.update(
                HOMEDRIVE=self.root.drive,
                HOMEPATH=str(self.root)[len(self.root.drive):],
            )

    def run_command(self, command):
        return subprocess.run(command, env=self.env, cwd=ROOT, capture_output=True, text=True, timeout=90)

    def install(self, release=VERSION):
        if WINDOWS:
            command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "install.ps1"), "-Release", release]
        else:
            command = ["sh", str(ROOT / "install.sh"), "--release", release]
        return self.run_command(command)

    def powershell_installer_fixture(self, pause=False):
        if not POWERSHELL:
            self.skipTest("PowerShell is unavailable; set UPKIT_PWSH to run the isolated PowerShell fixture")

        arch = "aarch64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
        self.asset = f"upkit-{arch}-pc-windows-msvc.exe"
        self.assets = {
            self.asset: self.binary,
            "SHA256SUMS": f"{hashlib.sha256(self.binary).hexdigest()}  {self.asset}\n".encode(),
        }

        script = ROOT / "install.ps1"
        if not pause and WINDOWS:
            return script

        source = script.read_text()
        if not WINDOWS:
            download = "    Download-Asset $asset $download\n"
            self.assertEqual(source.count(download), 1)
            source = source.replace(download, download + "    & chmod +x $download\n", 1)
        if pause:
            commit = "        [System.IO.File]::Move($staged, $destination)\n"
            self.assertEqual(source.count(commit), 1)
            source = source.replace(
                commit,
                "        while (-not (Test-Path -LiteralPath $env:UPKIT_TEST_CONTINUE -PathType Leaf)) { Start-Sleep -Milliseconds 5 }\n" + commit,
                1,
            )
        fixture = self.root / "install-fixture.ps1"
        fixture.write_text(source)
        return fixture

    def install_powershell(self, script=None):
        script = script or self.powershell_installer_fixture()
        command = [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-Release", VERSION, "-InstallDir", str(self.bin_dir)]
        return self.run_command(command)

    def install_powershell_at_commit(self, change_during_commit):
        script = self.powershell_installer_fixture(pause=True)
        continue_path = self.root / "continue-install"
        self.env["UPKIT_TEST_CONTINUE"] = str(continue_path)
        command = [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-Release", VERSION, "-InstallDir", str(self.bin_dir)]
        process = subprocess.Popen(command, env=self.env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 30
            while not list(self.bin_dir.glob(".upkit-old-*.exe")):
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    self.fail(f"PowerShell installer exited before the commit barrier:\n{stdout}{stderr}")
                if time.monotonic() >= deadline:
                    self.fail("PowerShell installer did not reach the commit barrier")
                time.sleep(0.01)
            change_during_commit()
            continue_path.touch()
            stdout, stderr = process.communicate(timeout=90)
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
            self.env.pop("UPKIT_TEST_CONTINUE", None)

    def existing(self, data=b"previous installation"):
        self.bin_dir.mkdir(parents=True)
        destination = self.bin_dir / f"upkit{EXTENSION}"
        destination.write_bytes(data)
        destination.chmod(0o755)
        return destination

    def existing_powershell(self, data=b"previous installation"):
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        destination = self.bin_dir / "upkit.exe"
        destination.write_bytes(data)
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

    @unittest.skipIf(WINDOWS, "POSIX installer")
    def test_shell_rejects_directory_and_symlink_destination(self):
        self.bin_dir.mkdir(parents=True)
        destination = self.bin_dir / "upkit"
        destination.mkdir()
        marker = destination / "keep"
        marker.write_text("preserve")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), "preserve")
        self.assertEqual(sorted(path.name for path in destination.iterdir()), ["keep"])

        destination.rename(self.root / "existing-directory")
        destination.symlink_to(self.root / "existing-directory", target_is_directory=True)
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(destination.is_symlink())
        self.assertEqual(sorted(path.name for path in destination.iterdir()), ["keep"])
        destination.unlink()
        destination.symlink_to(self.root / "missing")
        self.assertNotEqual(self.install().returncode, 0)
        self.assertTrue(destination.is_symlink())
        self.assertEqual(list(self.bin_dir.glob(".upkit.*")), [])

    def test_install_preserves_unrelated_legacy_backup_file(self):
        if not WINDOWS and not POWERSHELL:
            self.skipTest("PowerShell is unavailable")
        destination = self.existing_powershell()
        unrelated_backup = self.bin_dir / "upkit.old.exe"
        unrelated_backup.write_bytes(b"unrelated user file")

        self.assert_success(self.install_powershell())
        self.assertEqual(destination.read_bytes(), self.binary)
        self.assertEqual(unrelated_backup.read_bytes(), b"unrelated user file")

    @unittest.skipUnless(WINDOWS, "Windows PowerShell installer")
    def test_install_refuses_reparse_point_destination(self):
        self.bin_dir.mkdir()
        target = self.root / "outside.exe"
        target.write_bytes(b"outside fixture")
        destination = self.bin_dir / "upkit.exe"
        try:
            destination.symlink_to(target)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"Windows symlinks unavailable: {error}")

        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(destination.is_symlink())
        self.assertEqual(target.read_bytes(), b"outside fixture")

    @unittest.skipUnless(POWERSHELL, "PowerShell 7 fixture is not configured")
    def test_powershell_failed_commit_restores_previous_binary(self):
        original = b"previous installation"
        destination = self.existing_powershell(original)
        backup = self.bin_dir / "upkit.old.exe"
        backup.write_bytes(b"unrelated user backup")

        def remove_staged_file():
            staged = [path for path in self.bin_dir.glob(".upkit-*.exe") if not path.name.startswith(".upkit-old-")]
            self.assertEqual(len(staged), 1)
            staged[0].unlink()

        result = self.install_powershell_at_commit(remove_staged_file)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(backup.read_bytes(), b"unrelated user backup")
        self.assertEqual(list(self.bin_dir.glob(".upkit-old-*.exe")), [])
        self.assertEqual([path for path in self.bin_dir.glob(".upkit-*.exe") if not path.name.startswith(".upkit-old-")], [])

    @unittest.skipUnless(POWERSHELL, "PowerShell 7 fixture is not configured")
    def test_powershell_concurrent_destination_change_keeps_backup(self):
        original = b"previous installation"
        concurrent = b"concurrent destination"
        destination = self.existing_powershell(original)
        unrelated_backup = self.bin_dir / "upkit.old.exe"
        unrelated_backup.write_bytes(b"unrelated user backup")

        def create_concurrent_destination():
            destination.write_bytes(concurrent)

        result = self.install_powershell_at_commit(create_concurrent_destination)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("previous binary remains at", result.stderr)
        self.assertEqual(destination.read_bytes(), concurrent)
        self.assertEqual(unrelated_backup.read_bytes(), b"unrelated user backup")
        backups = list(self.bin_dir.glob(".upkit-old-*.exe"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)
        self.assertIn(backups[0].name, result.stderr)
        self.assertEqual([path for path in self.bin_dir.glob(".upkit-*.exe") if not path.name.startswith(".upkit-old-")], [])

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

    def test_duplicate_checksum_preserves_existing_install(self):
        destination = self.existing()
        digest = hashlib.sha256(self.binary).hexdigest()
        self.assets["SHA256SUMS"] = f"{digest}  {self.asset}\n{digest}  {self.asset}\n".encode()
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(destination.read_bytes(), b"previous installation")

    def test_binary_checksum_marker(self):
        digest = hashlib.sha256(self.binary).hexdigest()
        self.assets["SHA256SUMS"] = f"{digest} *{self.asset}\n".encode()
        self.assert_success(self.install())
        self.assertEqual((self.bin_dir / f"upkit{EXTENSION}").read_bytes(), self.binary)

    def test_duplicate_checksum_binary_marker_preserves_existing_install(self):
        destination = self.existing()
        digest = hashlib.sha256(self.binary).hexdigest()
        self.assets["SHA256SUMS"] = f"{digest}  {self.asset}\n{digest} *{self.asset}\n".encode()
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(destination.read_bytes(), b"previous installation")

    def test_malformed_checksum_entry_preserves_existing_install(self):
        destination = self.existing()
        digest = hashlib.sha256(self.binary).hexdigest()
        self.assets["SHA256SUMS"] = f"{digest}  {self.asset} extra\n".encode()
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(destination.read_bytes(), b"previous installation")

    def test_valid_and_malformed_duplicate_checksum_preserves_existing_install(self):
        destination = self.existing()
        digest = hashlib.sha256(self.binary).hexdigest()
        self.assets["SHA256SUMS"] = f"{digest}  {self.asset}\ninvalid  {self.asset}\n".encode()
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
