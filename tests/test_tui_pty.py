#!/usr/bin/env python3
"""Unix terminal tests using isolated homes, fixtures, and fake installers."""
import fcntl
import json
import os
import pty
import re
import select
import signal
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path


def controlling_pty_preexec(slave_fd):
    """Give a PTY child its own controlling terminal for accurate size checks."""
    def attach():
        os.setsid()
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

    return attach


def terminal_text(output):
    without_controls = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b" ", output)
    return re.sub(rb"\s+", b" ", without_controls)


def terminal_screen_text(output, rows, columns):
    # shortcut: handles cursor-position and erase CSI only; upgrade if this TUI emits other screen controls.
    screen = [[" "] * columns for _ in range(rows)]
    row = column = 0

    def write(data):
        nonlocal row, column
        for char in data.decode("utf-8", errors="replace"):
            if char == "\r":
                column = 0
            elif char == "\n":
                row = min(rows - 1, row + 1)
                column = 0
            elif char == "\b":
                column = max(0, column - 1)
            elif char == "\t":
                column = min(columns - 1, (column + 8) & ~7)
            elif char.isprintable():
                if 0 <= row < rows and 0 <= column < columns:
                    screen[row][column] = char
                column += 1

    data = bytes(output)
    cursor = 0
    for match in re.finditer(rb"\x1b\[([0-9;?]*)([A-Za-z])", data):
        write(data[cursor : match.start()])
        params = match.group(1).decode("ascii", errors="ignore").lstrip("?")
        command = match.group(2).decode("ascii")
        values = [int(value) if value.isdigit() else 0 for value in params.split(";") if value]
        if command in ("H", "f"):
            row = max(0, (values[0] if values and values[0] else 1) - 1)
            column = max(0, (values[1] if len(values) > 1 and values[1] else 1) - 1)
        elif command == "J":
            mode = values[0] if values else 0
            if mode == 2:
                screen = [[" "] * columns for _ in range(rows)]
            elif mode == 1:
                for line in range(row + 1):
                    end = column + 1 if line == row else columns
                    screen[line][:end] = [" "] * end
            else:
                for line in range(row, rows):
                    start = column if line == row else 0
                    screen[line][start:] = [" "] * (columns - start)
        elif command == "K":
            mode = values[0] if values else 0
            start = 0 if mode == 1 else column
            end = column + 1 if mode == 1 else columns
            if mode == 2:
                start = 0
            screen[row][start:end] = [" "] * max(0, end - start)
        elif command == "A":
            row = max(0, row - (values[0] if values else 1))
        elif command == "B":
            row = min(rows - 1, row + (values[0] if values else 1))
        elif command == "C":
            column = min(columns - 1, column + (values[0] if values else 1))
        elif command == "D":
            column = max(0, column - (values[0] if values else 1))
        cursor = match.end()
    write(data[cursor:])
    return "\n".join("".join(line).rstrip() for line in screen).encode("utf-8")


def fixture_git():
    candidates = [Path("/usr/bin/git"), Path("/bin/git")]
    path = shutil.which("git")
    if path:
        candidates.append(Path(path))
    for candidate in candidates:
        try:
            path = candidate.resolve(strict=True)
            if os.access(path, os.X_OK):
                with path.open("rb") as executable:
                    if executable.read(4) == b"\x7fELF":
                        return str(path)
        except (OSError, RuntimeError):
            continue
    return None


def private_etc_opt_namespace_command(unshare, mount, namespace_args, etc_opt, command):
    return [
        unshare,
        *namespace_args,
        "/bin/sh",
        "-c",
        '"$1" --make-rprivate / && "$1" --bind "$2" /etc/opt && shift 2 && exec "$@"',
        "upkit-private-etc-opt",
        mount,
        str(etc_opt),
        *map(str, command),
    ]


def private_etc_opt_namespace_available(unshare, mount, namespace_args):
    if (
        sys.platform != "linux"
        or not unshare
        or not mount
        or not Path("/etc/opt").is_dir()
    ):
        return False
    with tempfile.TemporaryDirectory(prefix="upkit-etc-opt-namespace-") as temporary:
        etc_opt = Path(temporary) / "etc" / "opt"
        etc_opt.mkdir(parents=True)
        try:
            probe = subprocess.run(
                private_etc_opt_namespace_command(
                    unshare, mount, namespace_args, etc_opt, ["/bin/true"]
                ),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return probe.returncode == 0


def existing_terminal_test_binary():
    repository = Path(__file__).resolve().parents[1]
    roots = {repository / "target"}
    if target_dir := os.environ.get("CARGO_TARGET_DIR"):
        roots.add(Path(target_dir).resolve())
    app_binary = Path(os.environ.get("UPKIT_TUI_TEST_BINARY", "target/debug/upkit")).resolve()
    if app_binary.parent.name in ("debug", "release"):
        roots.add(app_binary.parent.parent)

    for root in roots:
        for profile in ("debug", "release"):
            for candidate in (root / profile / "deps").glob("upkit-*"):
                if not candidate.is_file() or not os.access(candidate, os.X_OK):
                    continue
                try:
                    listing = subprocess.run(
                        [str(candidate), "--list"],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    continue
                if listing.returncode == 0 and all(
                    f"tui::tests::terminal_session_restores_after_{case}_in_pty: test" in listing.stdout
                    for case in ("unwind", "initialization_error")
                ):
                    return candidate
    return None


def build_terminal_test_binary(target_dir):
    cargo = shutil.which("cargo")
    if not cargo:
        raise RuntimeError("terminal restoration PTY test requires Cargo when its Rust test binary is absent")
    repository = Path(__file__).resolve().parents[1]
    build_env = os.environ.copy()
    build_env["CARGO_TARGET_DIR"] = str(target_dir)
    build = subprocess.run(
        [cargo, "test", "--locked", "--offline", "--lib", "--no-run", "--message-format=json"],
        cwd=repository,
        env=build_env,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        raise RuntimeError(
            "could not build the terminal restoration test binary in its isolated target: "
            + build.stderr[-4000:]
        )
    binaries = []
    for line in build.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = event.get("target", {})
        if (
            event.get("reason") == "compiler-artifact"
            and target.get("name") == "upkit"
            and "lib" in target.get("kind", [])
            and event.get("profile", {}).get("test")
            and event.get("executable")
        ):
            binaries.append(Path(event["executable"]))
    if len(binaries) != 1:
        raise RuntimeError(f"expected one Rust library test binary, found {len(binaries)}")
    return binaries[0]


def terminal_restoration_pty_test():
    def run_cases(test_binary):
        for case in ("unwind", "initialization_error"):
            test_name = f"tui::tests::terminal_session_restores_after_{case}_in_pty"
            with tempfile.TemporaryDirectory(prefix="upkit-terminal-pty-home-") as home:
                master, slave = pty.openpty()
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
                before = termios.tcgetattr(slave)
                env = {
                    "HOME": home,
                    "TERM": "xterm",
                    "PATH": "",
                    "XDG_CONFIG_HOME": str(Path(home) / "config"),
                    "XDG_DATA_HOME": str(Path(home) / "data"),
                    "UPKIT_TEST_TERMINAL_UNWIND": "1",
                }
                child = subprocess.Popen(
                    [str(test_binary), test_name, "--exact", "--nocapture"],
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    env=env,
                    preexec_fn=controlling_pty_preexec(slave),
                )
                output = bytearray()
                try:
                    deadline = time.monotonic() + 20
                    while child.poll() is None and time.monotonic() < deadline:
                        if select.select([master], [], [], 0.2)[0]:
                            try:
                                output.extend(os.read(master, 65536))
                            except OSError:
                                break
                    if child.poll() is None:
                        child.kill()
                        child.wait()
                        raise AssertionError(f"{test_name} timed out")
                    while select.select([master], [], [], 0.1)[0]:
                        try:
                            output.extend(os.read(master, 65536))
                        except OSError:
                            break
                    result = terminal_text(output)
                    assert child.returncode == 0, result.decode(errors="replace")
                    assert test_name.encode() in result and b"1 passed" in result, (
                        f"Rust test did not run: {result.decode(errors='replace')}"
                    )
                    assert termios.tcgetattr(slave) == before, (
                        f"terminal state was not restored by {test_name}"
                    )
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait()
                    os.close(master)
                    os.close(slave)

    test_binary = existing_terminal_test_binary()
    if test_binary:
        run_cases(test_binary)
    else:
        with tempfile.TemporaryDirectory(prefix="upkit-terminal-pty-target-") as target:
            run_cases(build_terminal_test_binary(target))
    print("TUI panic and initialization-error restoration PTY tests passed")


def doctor_configuration_pty_test(binary):
    with tempfile.TemporaryDirectory(prefix="upkit-doctor-config-pty-") as temporary:
        root = Path(temporary)
        home = root / "home"
        bindir = root / "bin"
        home.mkdir(mode=0o700)
        bindir.mkdir(mode=0o700)
        missing_root = root / "configured-workspace-missing"
        config = root / "config.toml"
        config.write_text(
            "version = 1\n\n[profiles.ptyfixture]\nworkspace_roots = ["
            + json.dumps(str(missing_root))
            + "]\n"
        )
        env = {
            "HOME": str(home),
            "TERM": "xterm",
            "PATH": str(bindir),
            "XDG_CONFIG_HOME": str(root / "xdg-config"),
            "XDG_DATA_HOME": str(root / "xdg-data"),
            "XDG_CACHE_HOME": str(root / "xdg-cache"),
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "http_proxy": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
        }
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 180, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen(
            [
                binary,
                "--timeout",
                "1",
                "--retries",
                "0",
                "--home",
                str(home),
                "--bindir",
                str(bindir),
                "--config",
                str(config),
                "--profile",
                "ptyfixture",
                "doctor",
            ],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def read_until(marker, timeout=20):
            deadline = time.monotonic() + timeout
            while marker not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
            return marker in terminal_text(output)

        marker = f"workspace root {missing_root} cannot be inspected".encode()
        try:
            assert read_until(marker), (
                "Doctor did not report the selected profile's configured workspace root: "
                + terminal_text(output)[-5000:].decode(errors="replace")
            )
            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Doctor configuration TUI PTY test passed")


def build_managed_install_fixture_worker(target_dir):
    cargo = shutil.which("cargo")
    if not cargo:
        raise RuntimeError("managed cleanup PTY fixture requires Cargo to build its seal worker")
    repository = Path(__file__).resolve().parents[1]
    build_env = os.environ.copy()
    build_env["CARGO_TARGET_DIR"] = str(target_dir)
    build = subprocess.run(
        [
            cargo,
            "test",
            "--locked",
            "--offline",
            "--test",
            "managed_cleanup_tests",
            "--no-run",
            "--message-format=json",
        ],
        cwd=repository,
        env=build_env,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        raise RuntimeError(
            "could not build the managed cleanup fixture worker offline: "
            + build.stderr[-4000:]
        )
    binaries = []
    for line in build.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            event.get("reason") == "compiler-artifact"
            and event.get("target", {}).get("name") == "managed_cleanup_tests"
            and event.get("profile", {}).get("test")
            and event.get("executable")
        ):
            binaries.append(Path(event["executable"]))
    if len(binaries) != 1:
        raise RuntimeError(
            f"expected one managed cleanup fixture worker, found {len(binaries)}"
        )
    return binaries[0]


def create_managed_install_fixture(worker, fixture_root, tools, namespace_prefix=()):
    fixture_root = Path(fixture_root)
    bindir = fixture_root / "bin"
    env = {
        "UPKIT_PTY_FIXTURE_ROOT": str(fixture_root),
        "UPKIT_PTY_FIXTURE_BINDIR": str(bindir),
        "UPKIT_PTY_FIXTURE_TOOLS": ",".join(tools),
    }
    result = subprocess.run(
        [
            *namespace_prefix,
            str(worker),
            "tui_pty_managed_install_fixture_worker",
            "--exact",
            "--ignored",
            "--nocapture",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "managed cleanup fixture worker refused or failed to create its temporary fixture: "
            + result.stdout[-2000:]
            + result.stderr[-2000:]
        )
    managed = fixture_root / "managed"
    return managed, bindir


def trim_preview_read_only_pty_test(binary):
    if sys.platform != "linux":
        print("TRIM preview PTY test skipped: Linux-only preview")
        return

    root_mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split(" - ", 1)[0].split()
        if len(fields) >= 6 and fields[3] == "/":
            mount_point = (
                fields[4]
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\012", "\n")
                .replace("\\134", "\\")
            )
            if mount_point == "/":
                root_mounts.append(line)
    if len(root_mounts) != 1:
        print("TRIM preview PTY test skipped: root mount is ambiguous")
        return

    with tempfile.TemporaryDirectory(prefix="upkit-trim-preview-pty-") as temporary:
        root = Path(temporary)
        fake_home = root / "fake-home"
        fake_home.mkdir(mode=0o700)
        fake_bin = root / "bin"
        fake_bin.mkdir(mode=0o700)
        marker = root / "fstrim-called"
        fake_fstrim = fake_bin / "fstrim"
        fake_fstrim.write_text('#!/bin/sh\nprintf called > "$UPKIT_TRIM_MARKER"\n')
        fake_fstrim.chmod(0o700)

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        before = termios.tcgetattr(slave)
        env = {
            "HOME": str(fake_home),
            "TERM": "xterm",
            "PATH": str(fake_bin),
            "XDG_DATA_HOME": str(fake_home / "data"),
            "XDG_CACHE_HOME": str(fake_home / "cache"),
            "XDG_CONFIG_HOME": str(fake_home / "config"),
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "http_proxy": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "UPKIT_TRIM_MARKER": str(marker),
        }
        child = subprocess.Popen(
            [
                binary,
                "--timeout",
                "1",
                "--retries",
                "0",
                "--home",
                str(root / "upkit-data"),
                "maintenance",
                "trim",
                "--preview",
                "--mount",
                "/",
            ],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def read_until(marker_text, timeout=15):
            marker_bytes = marker_text if isinstance(marker_text, bytes) else marker_text.encode()
            deadline = time.monotonic() + timeout
            while marker_bytes not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            return marker_bytes in terminal_text(output)

        try:
            assert read_until("TRIM preview"), (
                "read-only TRIM preview did not open: "
                + terminal_text(output).decode(errors="replace")
            )
            assert read_until("Read-only preview; Esc/n closes."), (
                "preview did not disclose read-only behavior: "
                + terminal_text(output).decode(errors="replace")
            )

            output.clear()
            os.write(master, b"y")
            time.sleep(0.2)
            assert child.poll() is None, "y unexpectedly started a TRIM operation"
            assert not marker.exists(), "read-only preview invoked fstrim"

            os.write(master, b"nq")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before, "terminal attributes were not restored"
            assert not marker.exists(), "read-only preview invoked fstrim"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("TRIM preview PTY read-only and terminal-restoration test passed")


def go_test_preview_read_only_pty_test(binary):
    if sys.platform != "linux":
        print("Go test-cache preview PTY test skipped: Linux-only preview")
        return
    with tempfile.TemporaryDirectory(prefix="upkit-go-test-pty-") as temporary:
        root = Path(temporary)
        fake_home = root / "fake-home"
        fake_home.mkdir(mode=0o700)
        cache = root / "go-cache"
        cache.mkdir(mode=0o700)
        cache.chmod(0o700)
        marker = cache / "testexpire.txt"
        marker.write_text("123\n")
        marker.chmod(0o600)
        preserved = cache / "fixture"
        preserved.write_text("keep")
        preserved.chmod(0o600)

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        before = termios.tcgetattr(slave)
        env = {
            "HOME": str(fake_home),
            "TERM": "xterm",
            "PATH": "",
            "XDG_DATA_HOME": str(fake_home / "data"),
            "XDG_CACHE_HOME": str(fake_home / "cache"),
            "XDG_CONFIG_HOME": str(fake_home / "config"),
        }
        child = subprocess.Popen(
            [
                binary,
                "--timeout",
                "1",
                "--retries",
                "0",
                "--home",
                str(root / "upkit-data"),
                "cache",
                "go-test",
                "--path",
                str(cache),
                "--preview",
            ],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def read_until(marker_text, timeout=15):
            marker_bytes = marker_text if isinstance(marker_text, bytes) else marker_text.encode()
            deadline = time.monotonic() + timeout
            while marker_bytes not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            return marker_bytes in terminal_text(output)

        try:
            assert read_until("Go test cache preview"), (
                "read-only preview dialog did not open: "
                + terminal_text(output).decode(errors="replace")
            )
            assert read_until("Preview only; Esc/n closes."), (
                "preview did not disclose read-only behavior: "
                + terminal_text(output).decode(errors="replace")
            )
            rendered = terminal_text(output)
            assert str(cache).encode() in rendered, "preview did not show the requested cache path"
            assert b"Preview only; Esc/n closes." in rendered, "preview did not disclose read-only behavior"

            output.clear()
            os.write(master, b"y")
            time.sleep(0.2)
            assert child.poll() is None, "y unexpectedly started an expiration operation"
            assert marker.read_text() == "123\n", "read-only preview changed the Go test-cache marker"
            assert preserved.read_text() == "keep", "read-only preview changed another cache entry"

            output.clear()
            os.write(master, b"n")
            time.sleep(0.2)
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before, "terminal attributes were not restored"
            assert marker.read_text() == "123\n"
            assert preserved.read_text() == "keep"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Go test-cache preview PTY read-only and terminal-restoration test passed")


def artifact_preview_read_only_pty_test(binary):
    with tempfile.TemporaryDirectory(prefix="upkit-artifact-preview-pty-") as temporary:
        root = Path(temporary)
        fake_home = root / "fake-home"
        workspace = root / "workspace"
        target = workspace / "target"
        target.mkdir(parents=True, mode=0o700)
        fake_home.mkdir(mode=0o700)
        (workspace / "Cargo.toml").write_text("[workspace]\n")
        fixture_file = target / "fixture.o"
        fixture_file.write_text("keep this fixture")

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        before = termios.tcgetattr(slave)
        env = {
            "HOME": str(fake_home),
            "TERM": "xterm",
            "PATH": "",
            "XDG_DATA_HOME": str(fake_home / "data"),
            "XDG_CACHE_HOME": str(fake_home / "cache"),
            "XDG_CONFIG_HOME": str(fake_home / "config"),
        }
        child = subprocess.Popen(
            [
                binary,
                "--timeout",
                "1",
                "--retries",
                "0",
                "--home",
                str(root / "upkit-data"),
                "sweep",
                "preview",
                str(workspace),
                "--select",
                str(target),
            ],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def read_until(marker_text, timeout=15):
            marker_bytes = marker_text if isinstance(marker_text, bytes) else marker_text.encode()
            deadline = time.monotonic() + timeout
            while marker_bytes not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            return marker_bytes in terminal_text(output)

        try:
            assert read_until("Cleanup preview"), (
                "explicit sweep preview did not open its TUI: "
                + terminal_text(output).decode(errors="replace")
            )
            assert read_until("Read-only CLI preview"), (
                "explicit sweep preview did not disclose read-only behavior: "
                + terminal_text(output).decode(errors="replace")
            )

            output.clear()
            os.write(master, b"d")
            assert read_until("dashboard"), (
                "cleanup was not blocked in the explicit CLI preview: "
                + terminal_text(output).decode(errors="replace")
            )
            os.write(master, b"by\t")
            time.sleep(0.3)
            assert child.poll() is None, "read-only preview unexpectedly exited on a preview key"
            assert fixture_file.read_text() == "keep this fixture", "CLI preview changed its fixture"
            assert not (root / "upkit-data" / "history").exists(), "blocked cleanup wrote history"

            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before, "terminal attributes were not restored"
            assert fixture_file.read_text() == "keep this fixture"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Explicit artifact CLI preview read-only and terminal-restoration PTY test passed")


def go_output_preview_fails_closed_pty_test(binary):
    with tempfile.TemporaryDirectory(prefix="upkit-go-output-pty-") as temporary:
        root = Path(temporary)
        fake_home = root / "fake-home"
        workspace = root / "workspace"
        build = workspace / "build"
        build.mkdir(parents=True, mode=0o700)
        (workspace / "bin").mkdir(mode=0o700)
        fake_home.mkdir(mode=0o700)
        (workspace / "go.mod").write_text("module example.invalid/service\ngo 1.22\n")
        fixture_files = [build / "keep", workspace / "bin" / "keep"]
        for fixture_file in fixture_files:
            fixture_file.write_text("keep this Go fixture")

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
        before = termios.tcgetattr(slave)
        env = {
            "HOME": str(fake_home),
            "TERM": "xterm",
            "PATH": "/usr/bin:/bin",
            "XDG_DATA_HOME": str(fake_home / "data"),
            "XDG_CACHE_HOME": str(fake_home / "cache"),
            "XDG_CONFIG_HOME": str(fake_home / "config"),
        }
        child = subprocess.Popen(
            [
                binary,
                "--timeout",
                "1",
                "--retries",
                "0",
                "--home",
                str(root / "upkit-data"),
                "sweep",
                "run",
                "--scope",
                "artifacts",
                "--select",
                str(build),
                "--root",
                str(workspace),
            ],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def read_until(marker_text, timeout=15):
            marker_bytes = marker_text if isinstance(marker_text, bytes) else marker_text.encode()
            deadline = time.monotonic() + timeout
            while marker_bytes not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            return marker_bytes in terminal_text(output)

        try:
            assert read_until("Artifact preview failed"), (
                "Go output removal preview did not fail closed in the TUI: "
                + terminal_text(output).decode(errors="replace")
            )
            rendered = terminal_screen_text(output, 24, 160)
            assert (
                b"Go build and bin directories are inspection-only" in rendered
            ), rendered.decode(errors="replace")
            assert b"Confirm permanent removal" not in rendered, rendered.decode(errors="replace")
            assert all(path.read_text() == "keep this Go fixture" for path in fixture_files)
            assert not (root / "upkit-data" / "history").exists()

            output.clear()
            os.write(master, b"y")
            time.sleep(0.2)
            assert all(path.read_text() == "keep this Go fixture" for path in fixture_files)
            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
            assert all(path.read_text() == "keep this Go fixture" for path in fixture_files)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Go output TUI removal preview fails closed and restores the terminal")


def temp_cleanup_review_pty_test(binary):
    if sys.platform != "linux":
        print("Temporary link cleanup TUI PTY test skipped: Linux-only service")
        return
    unshare = shutil.which("unshare")
    namespace_args = ["--user", "--map-root-user", "--pid", "--fork", "--mount-proc"]
    if not unshare or subprocess.run(
        [unshare, *namespace_args, "/bin/true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        print("Temporary link cleanup TUI PTY test skipped: isolated user/PID namespace unavailable")
        return
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        managed_home = root / "upkit-home"
        bindir = root / "upkit-bin"
        user_home = root / "user-home"
        for directory in (managed_home, bindir, user_home):
            directory.mkdir(mode=0o700)
        staging = bindir / ".upkit-link-pty-fixture"
        staging.mkdir(mode=0o700)
        os.symlink(managed_home / "go/versions/1.2.3/bin/go", staging / "link")
        old_time = time.time() - 40 * 86400
        os.utime(staging, (old_time, old_time))

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 12, 110, 0, 0))
        before = termios.tcgetattr(slave)
        env = {
            "HOME": str(user_home),
            "TERM": "xterm",
            "PATH": "",
            "XDG_DATA_HOME": str(user_home / "data"),
            "XDG_CONFIG_HOME": str(user_home / "config"),
        }
        child = subprocess.Popen(
            [
                unshare,
                *namespace_args,
                binary,
                "--timeout",
                "1",
                "--retries",
                "0",
                "--home",
                str(managed_home),
                "--bindir",
                str(bindir),
                "maintenance",
                "temp",
                "--preview",
            ],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def read_until(marker, timeout=10):
            marker = marker if isinstance(marker, bytes) else marker.encode()
            deadline = time.monotonic() + timeout
            while marker not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            return marker in terminal_text(output)

        try:
            assert read_until(b"Upkit"), "Dashboard did not open: " + terminal_text(output).decode(errors="replace")
            assert read_until(".upkit-link-pty-fixture"), (
                "temporary staging candidate was not listed: "
                + terminal_text(output).decode(errors="replace")
            )
            output.clear()
            os.write(master, b" ")
            os.write(master, b"\x1b[6~")
            assert read_until(b"Selected: 1"), (
                "explicit candidate selection was not shown: "
                + terminal_text(output).decode(errors="replace")
            )

            output.clear()
            os.write(master, b"d")
            assert read_until("Review temporary staging inventory"), "selected preview did not open"
            output.clear()
            os.write(master, b"\r")
            review_rejected = b"continuing."
            assert read_until(review_rejected), (
                "review continued before all candidates were visible: "
                + terminal_text(output).decode(errors="replace")
            )
            os.write(master, b"\x1b[6~")
            output.clear()
            os.write(master, b"\r")
            assert read_until("days old"), (
                "confirmation was not opened after full review: "
                + terminal_text(output).decode(errors="replace")
            )
            output.clear()
            os.write(master, b"y")
            confirm_rejected = b"confirming."
            assert read_until(confirm_rejected), "cleanup confirmed before the full selection was visible"

            os.write(master, b"\x1b[6~\x1b")
            assert staging.is_dir() and (staging / "link").is_symlink(), (
                "cancelling confirmation removed the temporary fixture"
            )
            history = managed_home / "history"
            assert not history.exists() or not list(history.iterdir()), "cancelled preview wrote operation history"
            output.clear()
            os.write(master, b"\x1b")
            assert read_until(b"l: inspect Upkit temp links"), "temporary link subview did not close"
            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before, "terminal attributes were not restored"
        finally:
            if child.poll() is None:
                # unshare --fork may leave a namespaced child behind if only
                # the launcher PID is killed. Own a dedicated process group.
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
            os.close(master)
            os.close(slave)
    print("Temporary link cleanup selection, full review, cancellation, and terminal restoration PTY test passed")


def history_purge_pty_test(binary):
    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary) / "upkit"
        history = home / "history"
        history.mkdir(parents=True, mode=0o700)
        history.chmod(0o700)
        now = int(time.time())
        records = [
            {
                "id": 0,
                "started_unix": 1,
                "finished_unix": 1,
                "duration_ms": 1,
                "operation": "fixture_old_operation",
                "target": "fixture_old_target",
                "outcome": "completed",
                "detail": None,
                "estimated_bytes": None,
                "verified_reclaimed_bytes": None,
                "platform": "fixture",
            },
            {
                "id": 1,
                "started_unix": now - 60,
                "finished_unix": now - 60,
                "duration_ms": 1,
                "operation": "fixture_recent_operation",
                "target": "fixture_recent_target",
                "outcome": "completed",
                "detail": None,
                "estimated_bytes": None,
                "verified_reclaimed_bytes": None,
                "platform": "fixture",
            },
            {
                "id": 2,
                "started_unix": 1,
                "finished_unix": None,
                "duration_ms": 1,
                "operation": "fixture_unfinished_operation",
                "target": "fixture_unfinished_target",
                "outcome": "running",
                "detail": None,
                "estimated_bytes": None,
                "verified_reclaimed_bytes": None,
                "platform": "fixture",
            },
        ]
        for record in records:
            path = history / f"{record['id']:03}.json"
            path.write_text(json.dumps(record))
            path.chmod(0o600)

        original_history = {path.name: path.read_bytes() for path in history.iterdir()}
        preview_master, preview_slave = pty.openpty()
        fcntl.ioctl(preview_slave, termios.TIOCSWINSZ, struct.pack("HHHH", 18, 160, 0, 0))
        preview_before = termios.tcgetattr(preview_slave)
        env = {
            "HOME": temporary,
            "TERM": "xterm",
            "PATH": "",
            "XDG_DATA_HOME": str(Path(temporary) / "xdg-data"),
            "XDG_CONFIG_HOME": str(Path(temporary) / "xdg-config"),
        }
        preview_child = subprocess.Popen(
            [
                binary,
                "--timeout",
                "1",
                "--retries",
                "0",
                "--home",
                str(home),
                "report",
                "purge",
                "--older-than",
                "7d",
                "--preview",
            ],
            stdin=preview_slave,
            stdout=preview_slave,
            stderr=preview_slave,
            env=env,
            preexec_fn=controlling_pty_preexec(preview_slave),
        )
        preview_output = bytearray()

        def read_preview_until(marker, timeout=10):
            deadline = time.monotonic() + timeout
            while marker not in terminal_text(preview_output) and time.monotonic() < deadline:
                if select.select([preview_master], [], [], 0.2)[0]:
                    preview_output.extend(os.read(preview_master, 65536))
            return marker in terminal_text(preview_output)

        try:
            assert read_preview_until(b"History purge preview"), (
                "CLI history preview did not open Reports TUI: "
                + terminal_text(preview_output).decode(errors="replace")
            )
            assert read_preview_until(b"older than 7 days"), "requested retention age was lost"
            assert read_preview_until(b"Preview only; records will not be removed."), (
                "CLI preview did not disclose read-only behavior"
            )
            assert b"fixture_old_target" in terminal_text(preview_output)

            os.write(preview_master, b"y")
            time.sleep(0.2)
            assert preview_child.poll() is None, "y unexpectedly started a history purge"
            assert {path.name: path.read_bytes() for path in history.iterdir()} == original_history

            os.write(preview_master, b"nq")
            assert preview_child.wait(timeout=10) == 0
            assert termios.tcgetattr(preview_slave) == preview_before
            assert {path.name: path.read_bytes() for path in history.iterdir()} == original_history
        finally:
            if preview_child.poll() is None:
                preview_child.kill()
                preview_child.wait()
            os.close(preview_master)
            os.close(preview_slave)

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 9, 160, 0, 0))
        before = termios.tcgetattr(slave)
        env = {
            "HOME": temporary,
            "TERM": "xterm",
            "PATH": "",
            "XDG_DATA_HOME": str(Path(temporary) / "xdg-data"),
            "XDG_CONFIG_HOME": str(Path(temporary) / "xdg-config"),
        }
        child = subprocess.Popen(
            [binary, "--timeout", "1", "--retries", "0", "--home", str(home), "report"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def read_until(marker, timeout=10):
            deadline = time.monotonic() + timeout
            while marker not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            return marker in terminal_text(output)

        try:
            assert read_until(b"Order: newest first"), "Reports history did not load"
            os.write(master, b"7")
            assert read_until(b"Confirm history purge"), (
                "history purge preview did not render: "
                + terminal_text(output).decode(errors="replace")
            )
            assert read_until(b"Candidates (ID"), "purge candidates did not render"
            assert read_until(b"fixture_old_target"), "initial review omitted the old candidate"
            review_prompt = b"Press y after r"
            assert review_prompt not in terminal_text(output), "short terminal did not require scrolling"

            time.sleep(0.2)
            os.write(master, b"y")
            # In a nine-row terminal the modal covers the status message,
            # so verify the actual safety property rather than text that
            # cannot be rendered: early approval must not delete anything.
            time.sleep(0.3)
            assert child.poll() is None, "short terminal exited during review"
            assert {path.name: path.read_bytes() for path in history.iterdir()} == original_history, (
                "unreviewed history purge removed data"
            )
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 18, 160, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            assert json.loads((history / "000.json").read_text()) == records[0]
            assert json.loads((history / "001.json").read_text()) == records[1]
            assert json.loads((history / "002.json").read_text()) == records[2]

            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 9, 160, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.2)
            assert child.poll() is None
            assert {path.name: path.read_bytes() for path in history.iterdir()} == original_history
            # Ratatui sends incremental redraws; do not wait for an unchanged
            # title to be sent again after the resize.
            output.clear()
            os.write(master, b"\x1b[6~")
            # Paging down may scroll the already-reviewed candidate offscreen;
            # the required warning and approval line must instead appear.
            assert read_until(b"Warning:"), (
                "scrolling did not reveal the purge warning: "
                + terminal_text(output).decode(errors="replace")
            )
            assert read_until(review_prompt), (
                "scrolling did not reveal the final review line: "
                + terminal_text(output).decode(errors="replace")
            )
            os.write(master, b"y")
            assert read_until(b"History purge: completed", timeout=15), (
                "history purge did not complete: "
                + terminal_text(output).decode(errors="replace")
            )

            # The purge summary reuses the first free slot after deleting the old record.
            summary = json.loads((history / "000.json").read_text())
            assert summary["operation"] == "history_purge"
            assert summary["target"].startswith("history records older than ")
            assert summary["target"] != "fixture_old_target"
            assert summary["outcome"] == "completed"
            assert json.loads((history / "001.json").read_text()) == records[1]
            assert json.loads((history / "002.json").read_text()) == records[2]

            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before, "terminal attributes were not restored"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("History purge confirmation and terminal restoration PTY test passed")


def structured_settings_form_pty_test(binary):
    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        config = home / "config.toml"
        original = (
            "version = 1\n"
            "# keep global marker\n"
            'artifact_retention = "30d" # keep global retention comment\n'
            "\n"
            "# keep alpha marker\n"
            "[profiles.alpha]\n"
            'artifact_retention = "14d" # keep alpha retention\n'
            "\n"
            "# keep beta marker\n"
            "[profiles.beta]\n"
            'artifact_retention = "7d" # keep beta retention\n'
        )
        config.write_text(original)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
        before = termios.tcgetattr(slave)
        env = {
            "HOME": temporary,
            "TERM": "xterm",
            "PATH": "",
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CONFIG_HOME": str(home / "config"),
        }
        child = subprocess.Popen(
            [binary, "--timeout", "1", "--retries", "0", "--config", str(config), "config", "show"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()
        transcript = bytearray()

        def read_until(marker, timeout=10):
            deadline = time.monotonic() + timeout
            while marker not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    data = os.read(master, 65536)
                    output.extend(data)
                    transcript.extend(data)
            return marker in terminal_text(output)

        def read_screen_until(marker, timeout=10):
            deadline = time.monotonic() + timeout
            while marker not in terminal_screen_text(transcript, 10, 160) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    data = os.read(master, 65536)
                    output.extend(data)
                    transcript.extend(data)
            return marker in terminal_screen_text(transcript, 10, 160)

        def drain_output():
            deadline = time.monotonic() + 1
            quiet_deadline = time.monotonic() + 0.1
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.05)[0]:
                    transcript.extend(os.read(master, 65536))
                    quiet_deadline = time.monotonic() + 0.1
                elif time.monotonic() >= quiet_deadline:
                    break
            assert not select.select([master], [], [], 0)[0], "TUI output did not become quiescent"

        try:
            assert read_until(b"Press e for structured fields, t for TOML"), (
                "Settings page did not load: "
                + terminal_text(output).decode(errors="replace")
            )
            output.clear()
            os.write(master, b"e")
            assert read_until(b"Profile scope"), (
                "structured Settings form did not open: "
                + terminal_text(output).decode(errors="replace")
            )
            os.write(master, b"\x1b[B" * 3 + b"\r")
            assert read_until(b"Edit setting"), "retention field editor did not open"
            output.clear()
            os.write(master, b"\x7f\x7f\x7f45d\r")
            deadline = time.monotonic() + 10
            rows = 24
            while b"Artifact retention: 45d" not in terminal_text(output) and time.monotonic() < deadline:
                rows = 25 if rows == 24 else 24
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, 160, 0, 0))
                os.kill(child.pid, signal.SIGWINCH)
                if select.select([master], [], [], 0.3)[0]:
                    data = os.read(master, 65536)
                    output.extend(data)
                    transcript.extend(data)
            assert b"Artifact retention: 45d" in terminal_text(output), (
                "retention edit was not applied in the form: "
                + terminal_text(output).decode(errors="replace")
            )
            output.clear()
            transcript.clear()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 10, 160, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            assert read_until(b"Ctrl+S: save"), (
                "small Settings form did not redraw: "
                + terminal_text(output).decode(errors="replace")
            )
            deadline = time.monotonic() + 10
            while b"Confirm settings" not in terminal_text(output) and time.monotonic() < deadline:
                os.write(master, b"\x13")
                read_until(b"Confirm settings", timeout=0.5)
            assert b"Confirm settings" in terminal_text(output), (
                "save preview did not render: "
                + terminal_text(output).decode(errors="replace")
            )
            assert read_until(b"Changed scope fields"), (
                "save preview contents did not finish rendering: "
                + terminal_text(output).decode(errors="replace")
            )
            drain_output()
            before_after = 'global defaults.artifact_retention: "30d" → "45d"'.encode()
            assert config.read_text() == original, "Ctrl+S saved before confirmation"

            output.clear()
            os.write(master, b"y")
            assert read_screen_until(b"Review every settings impact"), (
                "unreviewed Settings confirmation was not rejected: "
                + terminal_screen_text(transcript, 10, 160).decode(errors="replace")
            )
            assert config.read_text() == original, "premature confirmation changed the config"
            output.clear()
            os.write(master, b"\x1b[B\x1b[B")
            review_prompt = b"Press y after the end to save"
            assert read_until(before_after), (
                "save preview omitted the retention before/after values: "
                + terminal_text(output).decode(errors="replace")
            )
            assert read_until(review_prompt), "scrolling did not reveal the final save review line"
            os.write(master, b"y")
            assert read_until(b"Backup:", timeout=15), "reviewed Settings save did not finish"

            expected = original.replace(
                'artifact_retention = "30d"', 'artifact_retention = "45d"', 1
            )
            assert config.read_text() == expected, "save changed comments or another profile"
            backups = list(home.glob(".upkit-config-backup-*.toml"))
            assert len(backups) == 1 and backups[0].read_text() == original

            drain_output()
            output.clear()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            assert read_until(b"Profile scope"), (
                "Settings form did not redraw after resize: "
                + terminal_text(output).decode(errors="replace")
            )
            drain_output()
            output.clear()
            os.write(master, b"\x1b")
            assert read_until(b"Press e for structured fields, t for TOML"), (
                "Settings form did not close after save: "
                + terminal_text(output).decode(errors="replace")
            )
            os.write(master, b"q")
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
            returncode = child.poll()
            assert returncode is not None, (
                "TUI did not exit after q; "
                + terminal_text(output).decode(errors="replace")
            )
            assert child.wait(timeout=2) == 0, (
                f"TUI exited with status {returncode}; "
                + terminal_text(output).decode(errors="replace")
            )
            assert termios.tcgetattr(slave) == before, "terminal attributes were not restored"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Structured Settings form review, save, and terminal restoration PTY test passed")


def managed_cleanup_pty_test(binary):
    if sys.platform != "linux":
        print("Managed cleanup PTY test skipped: Linux-only workflow")
        return
    unshare = shutil.which("unshare")
    namespace_args = ["--user", "--map-root-user", "--pid", "--fork", "--mount-proc"]
    isolated = bool(
        unshare
        and subprocess.run(
            [unshare, *namespace_args, "/bin/true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )
    fixture_namespace = [unshare, *namespace_args] if isolated else []
    worker_target_override = os.environ.get("UPKIT_PTY_WORKER_TARGET_DIR") or None
    cleanup_worker_target = worker_target_override is None
    worker_target = (
        Path(worker_target_override)
        if worker_target_override
        else Path(tempfile.mkdtemp(prefix="upkit-managed-pty-worker-target-"))
    )
    try:
        worker = build_managed_install_fixture_worker(worker_target)
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            managed, bindir = create_managed_install_fixture(
                worker, home, ["go"], fixture_namespace
            )
            root = managed / "go"
            install = next(root.glob("install-*"))
            (root / "user-data").write_text("keep root fixture")
            shell = home / ".bashrc"
            shell.write_text("# upkit (go GOBIN)\nexport PATH=\"/fixture:$PATH\"\n")
            unrelated = home / "unrelated"
            unrelated.write_text("keep")
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 12, 55, 0, 0))
            before = termios.tcgetattr(slave)
            env = {"HOME": temporary, "SHELL": "/bin/bash", "TERM": "xterm", "PATH": "", "XDG_DATA_HOME": str(home / "data"), "XDG_CONFIG_HOME": str(home / "config"), "HTTPS_PROXY": "http://127.0.0.1:1", "https_proxy": "http://127.0.0.1:1"}
            command = [binary, "--timeout", "1", "--retries", "0", "--home", str(managed), "--bindir", str(bindir), "clean", "go"]
            if isolated:
                command = [unshare, *namespace_args, *command]
            child = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
            output = bytearray()
            try:
                deadline = time.monotonic() + 15
                while b"Confirm managed cleanup" not in terminal_text(output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Confirm managed cleanup" in terminal_text(output), terminal_text(output).decode(errors="replace")
                os.write(master, b"y")
                time.sleep(0.4)
                assert install.exists(), "small terminal allowed managed cleanup"
                output.clear()
                os.write(master, b"i")
                deadline = time.monotonic() + 10
                while b"Top-level contents" not in terminal_text(output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Top-level contents" in terminal_text(output), terminal_text(output).decode(errors="replace")
                os.write(master, b"\x1b")
                time.sleep(0.2)
                output.clear()
                # A long disclosure needs enough room for its complete review.
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 240, 0, 0))
                resize_target = child.pid
                if isolated:
                    children = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text().split()
                    assert children, "isolated dashboard process did not start"
                    resize_target = int(children[0])
                os.kill(resize_target, signal.SIGWINCH)
                complete_review = b"Press y to remove; Esc/n cancels. i shows top-level contents."
                activity_statuses = (
                    b"Process activity: no_open_handles_or_cwd_observed",
                    b"Process activity: open_handles_or_cwd_observed",
                    b"Process activity: executable_observed",
                    b"Process activity: inspection_incomplete",
                    b"Process activity: unavailable",
                )

                def read_activity_status(timeout=10):
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        screen = terminal_text(output)
                        if complete_review in screen:
                            for status in activity_statuses:
                                if status in screen:
                                    return status
                        if select.select([master], [], [], 0.2)[0]:
                            output.extend(os.read(master, 65536))
                    return None

                activity_status = read_activity_status()
                for _ in range(8):
                    if activity_status == activity_statuses[0]:
                        break
                    output.clear()
                    os.write(master, b"\x1b")
                    time.sleep(0.2)
                    os.write(master, b"d")
                    activity_status = read_activity_status()
                if activity_status in (activity_statuses[3], activity_statuses[4]):
                    # A hosted runner may hide other processes or deny complete
                    # /proc inspection. In that environment cleanup must fail
                    # closed; it would be unsafe to demand a successful delete.
                    os.write(master, b"y")
                    time.sleep(0.3)
                    assert install.exists(), "incomplete process inspection allowed deletion"
                    assert (root / "user-data").read_text() == "keep root fixture"
                    assert (bindir / "go").is_symlink(), "recorded link changed on rejected cleanup"
                    os.write(master, b"nq")
                    assert child.wait(timeout=10) == 0
                    assert termios.tcgetattr(slave) == before
                    print("Managed cleanup PTY fail-closed check passed: process inspection unavailable")
                    return
                assert activity_status == activity_statuses[0], (
                    "managed cleanup never reached a no-activity preview: "
                    + terminal_text(output).decode(errors="replace")
                )
                # Wait for a full redraw at the enlarged PTY dimensions. A
                # stale 12x55 frame can safely reject the first confirmation.
                time.sleep(0.4)
                for _ in range(3):
                    os.write(master, b"y")
                    deadline = time.monotonic() + 3
                    while install.exists() and time.monotonic() < deadline:
                        if select.select([master], [], [], 0.2)[0]:
                            output.extend(os.read(master, 65536))
                    if not install.exists():
                        break
                assert not install.exists(), terminal_text(output).decode(errors="replace")
                assert root.exists(), "cleanup removed the tool root and its receipt"
                assert (root / "user-data").read_text() == "keep root fixture"
                assert {entry.name for entry in root.iterdir()} == {".upkit-managed-links", "user-data"}
                deadline = time.monotonic() + 10
                while child.poll() is None and time.monotonic() < deadline:
                    os.write(master, b"q")
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert child.wait(timeout=2) == 0
                assert termios.tcgetattr(slave) == before
                assert not (bindir / "go").is_symlink()
                assert shell.read_text() == "# upkit (go GOBIN)\nexport PATH=\"/fixture:$PATH\"\n"
                assert unrelated.read_text() == "keep"
                history = subprocess.run([binary, "--non-interactive", "--json", "--home", str(managed), "report"], env=env, capture_output=True, check=True)
                assert any(record["operation"] == "managed_tool_cleanup" for record in json.loads(history.stdout)["records"])
            finally:
                if child.poll() is None:
                    # unshare --fork may outlive its launcher on test failure.
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
                os.close(master)
                os.close(slave)
        print("Managed cleanup confirmation and removal PTY test passed with temporary fixtures")

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            managed, bindir = create_managed_install_fixture(worker, home, ["go", "node"])
            roots = {tool: managed / tool for tool in ("go", "node")}
            installs = {tool: next(root.glob("install-*")) for tool, root in roots.items()}
            unrelated = home / "unrelated"
            unrelated.write_text("keep")
            env = {
                "HOME": temporary,
                "TERM": "xterm",
                "PATH": "",
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "https_proxy": "http://127.0.0.1:1",
                "XDG_DATA_HOME": str(home / "data"),
                "XDG_CONFIG_HOME": str(home / "config"),
            }
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
            before = termios.tcgetattr(slave)
            child = subprocess.Popen(
                [binary, "--timeout", "1", "--retries", "0", "--home", str(managed),
                 "--bindir", str(bindir), "tui"],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env=env,
                preexec_fn=controlling_pty_preexec(slave),
            )
            output = bytearray()

            def read_until(marker, timeout=15, start=0):
                deadline = time.monotonic() + timeout
                while marker not in terminal_text(output[start:]) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                return marker in terminal_text(output[start:])

            try:
                assert read_until(b"Recent activity"), "dashboard cards did not render"
                output.clear()
                os.write(master, b"\t")
                assert read_until(b"installed:"), "Toolchains screen did not render"

                # Search notes with a unique Go phrase; offline Flutter errors include googleapis.com.
                os.write(master, b"/bindir\r")
                assert read_until(b"Filter: bindir (1/8 toolchains)"), (
                    "Go filter did not apply: "
                    + terminal_text(output)[-4000:].decode(errors="replace")
                )
                os.write(master, b" ")
                os.write(master, b"/" + b"\x7f" * len("bindir") + b"node\r")
                # The PTY receives incremental screen differences; the unchanged `Filter:` label may not be resent.
                assert read_until(b"node (1/8 toolchains)"), (
                    "Node filter did not apply: "
                    + terminal_text(output)[-4000:].decode(errors="replace")
                )
                marked_at = len(output)
                os.write(master, b" ")
                # Only the changed count digit is resent after the first target is marked.
                assert read_until(b"2", start=marked_at), (
                    "both cleanup targets were not marked: "
                    + terminal_text(output[marked_at:])[-4000:].decode(errors="replace")
                )
                os.write(master, b"D")
                assert read_until(b"Review all 2 managed cleanup targets"), "combined managed cleanup preview did not render"
                assert read_until(b"Selected tool 2/2: node"), "combined preview omitted a selected tool"
                assert all(root.exists() for root in roots.values()), "preview changed managed fixtures"

                output.clear()
                os.write(master, b"y")
                time.sleep(0.2)
                assert all(root.exists() for root in roots.values()), "early confirmation bypassed full review"
                os.write(master, b"j" * 40 + b"y")
                assert read_until(b"Managed cleanup batch result", timeout=20), "batch result summary did not render"
                assert all(root.exists() for root in roots.values()), "cleanup removed a tool root"
                assert all(not install.exists() for install in installs.values()), "sealed installations remain"
                assert all(
                    {entry.name for entry in root.iterdir()} == {".upkit-managed-links"}
                    for root in roots.values()
                ), "cleanup changed data outside sealed installations and recorded links"
                assert all(not (bindir / tool).is_symlink() for tool in roots), "matching binary links remain"
                assert unrelated.read_text() == "keep"

                os.write(master, b"\x1b")
                time.sleep(0.2)
                os.write(master, b"q")
                assert child.wait(timeout=10) == 0
                assert termios.tcgetattr(slave) == before
                history = subprocess.run(
                    [binary, "--non-interactive", "--json", "--home", str(managed), "report"],
                    env=env,
                    capture_output=True,
                    check=True,
                )
                records = [
                    record for record in json.loads(history.stdout)["records"]
                    if record["operation"] == "managed_tool_cleanup"
                ]
                assert len(records) == 2 and all(record["outcome"] == "completed" for record in records)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)
                os.close(slave)
        print("Marked multi-tool managed cleanup PTY test passed with temporary fixtures")
    finally:
        if cleanup_worker_target:
            shutil.rmtree(worker_target, ignore_errors=True)


def cache_tui_pty_smoke_test(binary, unshare, mount, namespace_args):
    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        etc_opt = Path(temporary) / "etc" / "opt"
        etc_opt.mkdir(parents=True, mode=0o700)
        cache = home / ".cargo" / "registry"
        cache.mkdir(parents=True)
        (home / ".cargo").chmod(0o700)
        cache.chmod(0o700)
        (cache / "keep").write_text("fixture")
        (cache / "keep").chmod(0o600)
        git_cache = home / ".cargo" / "git"
        git_cache.mkdir()
        (git_cache / "fixture").write_text("larger than registry")
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        before = termios.tcgetattr(slave)
        go_cache = home / "go-build"
        go_env = home / "config" / "go" / "env"
        go_env.parent.mkdir(parents=True)
        go_env.write_text(
            f"GOCACHE={go_cache}\nGOPATH={home / 'go'}\nGOMODCACHE={home / 'go' / 'pkg' / 'mod'}\nGOCACHEPROG=\n"
        )
        global_config = home / "npm-global.npmrc"
        global_config.write_text("")
        env = {
            "HOME": str(home),
            "TERM": "xterm",
            "PATH": "",
            "GOENV": str(go_env),
            "GOCACHE": str(go_cache),
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CACHE_HOME": str(home / "cache"),
            "XDG_CONFIG_HOME": str(home / "config"),
            "NPM_CONFIG_GLOBALCONFIG": str(global_config),
        }
        child = subprocess.Popen(
            private_etc_opt_namespace_command(
                unshare,
                mount,
                namespace_args,
                etc_opt,
                [binary, "--timeout", "1", "--retries", "0", "cache", "status"],
            ),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            cwd=home,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def resize_child():
            children = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text().split()
            if children:
                os.kill(int(children[0]), signal.SIGWINCH)

        try:
            deadline = time.monotonic() + 10
            size = 24
            redraw_at = 0
            while b"Cargo registry:" not in terminal_text(output) and time.monotonic() < deadline:
                if time.monotonic() >= redraw_at:
                    size = 25 if size == 24 else 24
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", size, 100, 0, 0))
                    resize_child()
                    redraw_at = time.monotonic() + 0.25
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Cargo registry:" in terminal_text(output), "cache inventory did not render"
            output.clear()
            os.write(master, b"/registry")
            deadline = time.monotonic() + 10
            size = 24
            redraw_at = 0
            while (b"Filter: registry" not in terminal_text(output)
                   or b"Enter: apply" not in terminal_text(output)) and time.monotonic() < deadline:
                if time.monotonic() >= redraw_at:
                    size = 25 if size == 24 else 24
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", size, 100, 0, 0))
                    resize_child()
                    redraw_at = time.monotonic() + 0.25
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Filter: registry" in terminal_text(output), terminal_text(output).decode(errors="replace")
            assert b"Enter: apply" in terminal_text(output), terminal_text(output).decode(errors="replace")
            output.clear()
            os.write(master, b"\r")
            deadline = time.monotonic() + 10
            redraw_at = 0
            while (b"1 of 2 caches" not in terminal_text(output)
                   or b"d: removal" not in terminal_text(output)) and time.monotonic() < deadline:
                if time.monotonic() >= redraw_at:
                    size = 25 if size == 24 else 24
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", size, 100, 0, 0))
                    resize_child()
                    redraw_at = time.monotonic() + 0.25
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"d: removal" in terminal_text(output), terminal_text(output).decode(errors="replace")
            assert b"1 of 2 caches" in terminal_text(output), terminal_text(output).decode(errors="replace")
            output.clear()
            os.write(master, b"d")
            deadline = time.monotonic() + 10
            while b"Enter: review" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Enter: review" in terminal_text(output), terminal_text(output).decode(errors="replace")
            output.clear()
            os.write(master, b"sj")
            deadline = time.monotonic() + 10
            redraw_at = 0
            while (b"Sort: logical size" not in terminal_text(output)
                   or b"Enter: review" not in terminal_text(output)
                   or b"\xe2\x80\xba Cargo registry" not in terminal_text(output)
                   or str(cache).encode() not in terminal_text(output)) and time.monotonic() < deadline:
                if time.monotonic() >= redraw_at:
                    size = 25 if size == 24 else 24
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", size, 100, 0, 0))
                    resize_child()
                    redraw_at = time.monotonic() + 0.25
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            chooser = terminal_text(output)
            assert b"Sort: logical size" in chooser, chooser.decode(errors="replace")
            assert b"Enter: review" in chooser, chooser.decode(errors="replace")
            assert b"\xe2\x80\xba Cargo registry" in chooser and str(cache).encode() in chooser, f"sorting changed the selected cache: {chooser[-3000:]}"
            output.clear()
            os.write(master, b"\r")
            deadline = time.monotonic() + 10
            redraw_at = 0
            activity_error = b"Shared-cache preview failed: cache process activity"
            while (b"Review shared-cache entries" not in terminal_text(output)
                   and activity_error not in terminal_text(output)
                   and time.monotonic() < deadline):
                if time.monotonic() >= redraw_at:
                    size = 25 if size == 24 else 24
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", size, 100, 0, 0))
                    resize_child()
                    redraw_at = time.monotonic() + 0.25
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            preview = terminal_text(output)
            if activity_error in preview:
                assert b"Shared-cache preview failed: cache process activity was observed" in preview, preview.decode(errors="replace")
                response = b"q"
            else:
                assert b"Review shared-cache entries" in preview, preview.decode(errors="replace")
                time.sleep(0.2)
                output.clear()
                os.write(master, b"\r")
                deadline = time.monotonic() + 10
                redraw_at = 0
                while (b"Confirm permanent shared-cache removal" not in terminal_text(output)
                       or str(cache).encode() not in terminal_text(output)
                       or b"reclaimed space is unknown" not in terminal_text(output)) and time.monotonic() < deadline:
                    if time.monotonic() >= redraw_at:
                        size = 25 if size == 24 else 24
                        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", size, 100, 0, 0))
                        resize_child()
                        redraw_at = time.monotonic() + 0.25
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                preview = terminal_text(output)
                assert b"Confirm permanent shared-cache removal" in preview, terminal_text(output).decode(errors="replace")
                assert str(cache).encode() in preview, "sorted selection previewed the wrong cache path"
                assert b"reclaimed space is unknown" in preview, "cache estimate was presented as reclaimed space"
                response = b"n"
            assert (cache / "keep").read_text() == "fixture"
            assert (git_cache / "fixture").read_text() == "larger than registry"
            os.write(master, response)
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before
            assert (cache / "keep").read_text() == "fixture"
            assert (git_cache / "fixture").read_text() == "larger than registry"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Cache TUI PTY smoke test passed")


def shared_cache_review_removal_pty_test(binary, unshare, mount, namespace_args):
    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        parent = home / "caches"
        etc_opt = home / "etc" / "opt"
        etc_opt.mkdir(parents=True, mode=0o700)
        target = parent / "go-build"
        target.mkdir(parents=True)
        parent.chmod(0o700)
        target.chmod(0o700)
        for i in range(25):
            file = target / f"file-{i:02}"
            file.write_text("fixture")
            file.chmod(0o600)
        last = target / "zz-LAST-COMPLETE"
        last.write_text("fixture")
        last.chmod(0o600)
        go_env = home / "config" / "go" / "env"
        go_env.parent.mkdir(parents=True)
        go_env.write_text(
            f"GOCACHE={target}\nGOPATH={home / 'go'}\nGOMODCACHE={home / 'go' / 'pkg' / 'mod'}\nGOCACHEPROG=\n"
        )
        global_config = home / "npm-global.npmrc"
        global_config.write_text("")
        env = {
            "HOME": temporary,
            "PATH": "/usr/bin:/bin",
            "TERM": "xterm",
            "GOENV": str(go_env),
            "GOCACHE": str(target),
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_CACHE_HOME": str(parent),
            "NPM_CONFIG_GLOBALCONFIG": str(global_config),
        }
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen(
            private_etc_opt_namespace_command(
                unshare,
                mount,
                namespace_args,
                etc_opt,
                [binary, "--timeout", "1", "--retries", "0", "cache", "status"],
            ),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            cwd=home,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()
        try:
            deadline = time.monotonic() + 15
            redraw_at = 0
            while str(target).encode() not in terminal_text(output) and time.monotonic() < deadline:
                if time.monotonic() >= redraw_at:
                    children = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text().split()
                    if children:
                        os.kill(int(children[0]), signal.SIGWINCH)
                    redraw_at = time.monotonic() + 0.25
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert str(target).encode() in terminal_text(output), terminal_text(output).decode(errors="replace")
            output.clear()
            os.write(master, b"d")
            deadline = time.monotonic() + 10
            while b"Select shared cache" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Select shared cache" in output, terminal_text(output).decode(errors="replace")
            output.clear()
            os.write(master, b"\r")
            deadline = time.monotonic() + 20
            while b"file-00" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"file-00" in output, terminal_text(output).decode(errors="replace")
            os.write(master, b"\ry")
            time.sleep(0.4)
            assert target.exists(), "shared-cache review was bypassed"
            output.clear()
            os.write(master, b"j" * 10)
            deadline = time.monotonic() + 10
            while b"LAST-COMPLETE" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"LAST-COMPLETE" in output, terminal_text(output).decode(errors="replace")
            output.clear()
            os.write(master, b"\r")
            time.sleep(0.3)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 25, 161, 0, 0))
            children = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text().split()
            assert children
            os.kill(int(children[0]), signal.SIGWINCH)
            deadline = time.monotonic() + 10
            while b"Confirm permanent shared-cache removal" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm permanent shared-cache removal" in output, terminal_text(output).decode(errors="replace")
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 12, 50, 0, 0))
            os.kill(int(children[0]), signal.SIGWINCH)
            time.sleep(0.3)
            os.write(master, b"y")
            time.sleep(0.4)
            assert target.exists(), "small terminal allowed shared-cache confirmation"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 25, 161, 0, 0))
            os.kill(int(children[0]), signal.SIGWINCH)
            time.sleep(0.3)
            os.write(master, b"y")
            deadline = time.monotonic() + 15
            while target.exists() and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert not target.exists(), terminal_text(output).decode(errors="replace")
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
        target.mkdir(mode=0o700)
        (target / "keep").write_text("fixture")
        (target / "keep").chmod(0o600)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen(
            private_etc_opt_namespace_command(
                unshare,
                mount,
                namespace_args,
                etc_opt,
                [
                    binary,
                    "--timeout",
                    "1",
                    "--retries",
                    "0",
                    "sweep",
                    "run",
                    "--scope",
                    "cache",
                    "--select",
                    str(target),
                ],
            ),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            cwd=home,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()
        try:
            deadline = time.monotonic() + 20
            while b"Review shared-cache entries" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Review shared-cache entries" in output, terminal_text(output).decode(errors="replace")
            os.write(master, b"\x1b")
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before
            assert (target / "keep").read_text() == "fixture"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Shared-cache review and removal TUI PTY test passed in an isolated namespace")


def queued_container_confirmation_pty_test(binary):
    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        bindir = home / "bin"
        bindir.mkdir()
        container_id = "a" * 64
        docker = bindir / "docker"
        docker.write_text('''#!/bin/sh
case "$*" in
  'info --format json') printf '%s\\n' '{"ID":"fixture-daemon"}' ;;
  'container ls --all --size --no-trunc --format json') printf '{"ID":"%s","State":"exited","Names":"fixture"}\\n' "$EXPECTED_ID" ;;
  'container inspect --size '*) /bin/sleep 0.4; printf '[{"Id":"%s","Name":"fixture","RestartCount":0,"SizeRw":1,"State":{"Status":"exited","Running":false,"Restarting":false,"StartedAt":"a","FinishedAt":"b"}}]\\n' "$4" ;;
  'container rm -- '*) printf removed > "$HOME/removed" ;;
  *) printf '[]\\n' ;;
esac
''')
        docker.chmod(0o700)
        env = {"HOME": temporary, "TERM": "xterm", "PATH": str(bindir),
               "EXPECTED_ID": container_id, "XDG_DATA_HOME": str(home / "data"),
               "XDG_CONFIG_HOME": str(home / "config")}
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen(
            [binary, "--timeout", "2", "--retries", "0", "containers", "preview-remove",
             "--engine", "docker", "--id", container_id],
            cwd=home, env=env, stdin=slave, stdout=slave, stderr=slave,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while b"\x1b[?1049h" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"\x1b[?1049h" in output, "TUI did not enter its alternate screen"
            os.write(master, b"y" * 64)
            deadline = time.monotonic() + 10
            while b"Confirm container removal" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm container removal" in output, terminal_text(output).decode(errors="replace")
            time.sleep(0.3)
            assert child.poll() is None
            assert not (home / "removed").exists(), "queued input confirmed an unseen plan"
            os.write(master, b"nq")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
            assert not (home / "removed").exists()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Queued container confirmation is discarded before preview")


def self_update_pty_test(binary):
    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        bindir = home / "bin"
        bindir.mkdir()
        cargo = bindir / "cargo"
        cargo.write_text(
            '#!/bin/sh\nif [ "$1" = install ]; then printf "%s\\n" "$@" > "$HOME/update-args"; '
            'exit "${UPKIT_FIXTURE_STATUS:-0}"; fi\nprintf probe >> "$HOME/unrelated-probes"\n'
        )
        cargo.chmod(0o700)
        for name in ("go", "rustc", "node", "python3", "flutter", "mojo", "java", "dotnet"):
            probe = bindir / name
            probe.write_text('#!/bin/sh\nprintf probe >> "$HOME/unrelated-probes"\n')
            probe.chmod(0o700)
        env = {
            "HOME": temporary,
            "PATH": str(bindir),
            "TERM": "xterm",
            "UPKIT_INSTALLER": "cargo",
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_DATA_HOME": str(home / "data"),
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "https_proxy": "http://127.0.0.1:1",
        }
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 140, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen(
            [binary, "--timeout", "1", "--retries", "0", "self-update"],
            cwd=home, env=env, stdin=slave, stdout=slave, stderr=slave,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def read_until(marker, timeout=15):
            deadline = time.monotonic() + timeout
            while marker not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
            return marker in terminal_text(output)

        try:
            os.write(master, b"y")
            assert read_until(b"Confirm Upkit self-update"), terminal_text(output).decode(errors="replace")
            assert read_until(str(cargo).encode()), terminal_text(output).decode(errors="replace")
            time.sleep(0.2)
            assert not (home / "update-args").exists()
            assert not (home / "unrelated-probes").exists(), "preview started unrelated checks"
            output.clear()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 10, 45, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.3)
            os.write(master, b"y")
            time.sleep(0.4)
            assert child.poll() is None
            assert not (home / "update-args").exists(), "small terminal allowed self-update"
            output.clear()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 140, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            assert read_until(b"Confirm Upkit self-update"), terminal_text(output).decode(errors="replace")
            assert read_until(b"Enter/y: confirm"), terminal_text(output).decode(errors="replace")
            time.sleep(0.2)
            os.write(master, b"y")
            deadline = time.monotonic() + 10
            while not (home / "update-args").exists() and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert (home / "update-args").read_text().splitlines() == ["install", "--force", "upkit"]
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
        (home / "update-args").unlink()
        env["UPKIT_FIXTURE_STATUS"] = "7"
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 140, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen(
            [binary, "--timeout", "1", "--retries", "0", "self-update"],
            cwd=home, env=env, stdin=slave, stdout=slave, stderr=slave,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()
        try:
            assert read_until(b"Confirm Upkit self-update"), terminal_text(output).decode(errors="replace")
            assert read_until(str(cargo).encode()), terminal_text(output).decode(errors="replace")
            assert read_until(b"Enter/y: confirm"), terminal_text(output).decode(errors="replace")
            time.sleep(0.2)
            os.write(master, b"y")
            deadline = time.monotonic() + 10
            while not (home / "update-args").exists() and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert (home / "update-args").exists()
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
            assert child.wait(timeout=2) != 0
            assert termios.tcgetattr(slave) == before
            assert (home / "update-args").exists()
            assert not (home / "unrelated-probes").exists()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
        (home / "update-args").unlink()
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 140, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen(
            [binary, "--timeout", "1", "--retries", "0", "self-update"],
            cwd=home, env=env, stdin=slave, stdout=slave, stderr=slave,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()
        try:
            assert read_until(b"Confirm Upkit self-update"), terminal_text(output).decode(errors="replace")
            assert read_until(str(cargo).encode()), terminal_text(output).decode(errors="replace")
            assert read_until(b"Enter/y: confirm"), terminal_text(output).decode(errors="replace")
            time.sleep(0.2)
            os.write(master, b"n")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
            assert not (home / "update-args").exists()
            assert not (home / "unrelated-probes").exists()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
        shell = bindir / "sh"
        shell.write_text('#!/bin/sh\nprintf "%s" "$UPKIT_RELEASE_BASE_URL" > "$HOME/release-source"\n')
        shell.chmod(0o700)
        env["UPKIT_INSTALLER"] = "standalone"
        env["UPKIT_RELEASE_BASE_URL"] = "https://user:secret@example.invalid/releases?token=hidden"
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 140, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen(
            [binary, "--timeout", "1", "--retries", "0", "self-update"],
            cwd=home, env=env, stdin=slave, stdout=slave, stderr=slave,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()
        try:
            assert read_until(b"Confirm Upkit self-update"), terminal_text(output).decode(errors="replace")
            assert read_until(b"https://example.invalid/releases"), terminal_text(output).decode(errors="replace")
            assert b"secret" not in terminal_text(output)
            assert b"token=hidden" not in terminal_text(output)
            assert not (home / "release-source").exists()
            assert read_until(b"Enter/y: confirm"), terminal_text(output).decode(errors="replace")
            time.sleep(0.2)
            os.write(master, b"y")
            deadline = time.monotonic() + 10
            while not (home / "release-source").exists() and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert (home / "release-source").read_text() == env["UPKIT_RELEASE_BASE_URL"]
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Self-update preview and fake installer TUI PTY test passed")


def dashboard_recent_activity_pty_test(binary):
    with tempfile.TemporaryDirectory(prefix="upkit-dashboard-history-pty-") as temporary:
        root = Path(temporary)
        home = root / "upkit"
        history = home / "history"
        history.mkdir(parents=True, mode=0o700)
        history.chmod(0o700)
        home.chmod(0o700)
        records = [
            (0, "oldest_operation", "completed", "/private/oldest"),
            (1, "older_operation", "failed", "/private/older"),
            (2, "middle_operation", "partial", "/private/middle"),
            (3, "newest_operation", "completed", "/private/newest"),
        ]
        for record_id, operation, outcome, target in records:
            record = {
                "id": record_id,
                "started_unix": record_id,
                "finished_unix": None,
                "duration_ms": 0,
                "operation": operation,
                "target": target,
                "outcome": outcome,
                "detail": None,
                "estimated_bytes": None,
                "verified_reclaimed_bytes": None,
                "platform": "fixture",
            }
            path = history / f"{record_id:03}.json"
            path.write_text(json.dumps(record))
            path.chmod(0o600)

        cargo_home = root / ".cargo"
        cargo_registry = cargo_home / "registry"
        cargo_registry.mkdir(parents=True, mode=0o700)
        cargo_home.chmod(0o700)
        (cargo_registry / "fixture").write_text("cache fixture")
        (cargo_registry / "fixture").chmod(0o600)

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
        before = termios.tcgetattr(slave)
        env = {
            "HOME": str(root),
            "TERM": "xterm",
            "PATH": "",
            "XDG_DATA_HOME": str(root / "xdg-data"),
            "XDG_CACHE_HOME": str(root / "xdg-cache"),
            "XDG_CONFIG_HOME": str(root / "xdg-config"),
        }
        child = subprocess.Popen(
            [binary, "--timeout", "1", "--retries", "0", "--home", str(home)],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            rendered = b""
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                rendered = terminal_screen_text(output, 30, 120)
                if all(
                    marker in rendered
                    for marker in (b"newest_operation", b"middle_operation", b"older_operation")
                ):
                    break
            assert all(
                marker in rendered
                for marker in (b"newest_operation", b"middle_operation", b"older_operation")
            ), rendered.decode(errors="replace")
            positions = [
                rendered.index(marker)
                for marker in (b"newest_operation", b"middle_operation", b"older_operation")
            ]
            assert positions == sorted(positions), "recent operations are not newest-first"
            assert b"oldest_operation" not in rendered
            assert b"/private/" not in rendered
            output.clear()
            os.write(master, b"c")
            deadline = time.monotonic() + 15
            rendered = b""
            while b"Cargo registry: logical snapshot 13 bytes" not in rendered and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                rendered = terminal_screen_text(output, 30, 120)
            assert b"Cargo registry: logical snapshot 13 bytes" in rendered, (
                "Dashboard c shortcut did not start cache inventory: "
                + rendered.decode(errors="replace")
            )
            assert b"(1 of 1 caches)" in rendered
            assert b"Shared caches" in rendered
            assert b"Recent activity" not in rendered
            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Dashboard shows recent outcomes without target paths and opens cache inventory")


def main():
    binary = os.path.abspath(os.environ.get("UPKIT_TUI_TEST_BINARY", "target/debug/upkit"))
    dashboard_only = sys.argv[1:] == ["dashboard"]
    if sys.argv[1:] and not dashboard_only:
        if sys.argv[1:] == ["history-purge"]:
            history_purge_pty_test(binary)
        elif sys.argv[1:] == ["temp-cleanup"]:
            temp_cleanup_review_pty_test(binary)
        elif sys.argv[1:] == ["go-test-preview"]:
            go_test_preview_read_only_pty_test(binary)
        elif sys.argv[1:] == ["artifact-preview"]:
            artifact_preview_read_only_pty_test(binary)
        elif sys.argv[1:] == ["go-artifact-preview"]:
            go_output_preview_fails_closed_pty_test(binary)
        elif sys.argv[1:] == ["trim-preview"]:
            trim_preview_read_only_pty_test(binary)
        elif sys.argv[1:] == ["settings-form"] and sys.platform == "linux":
            structured_settings_form_pty_test(binary)
        elif sys.argv[1:] == ["managed-clean"]:
            managed_cleanup_pty_test(binary)
        elif sys.argv[1:] == ["terminal-restoration"]:
            terminal_restoration_pty_test()
        elif sys.argv[1:] == ["doctor-config"]:
            doctor_configuration_pty_test(binary)
        elif sys.argv[1:] == ["self-update"]:
            self_update_pty_test(binary)
        elif sys.argv[1:] == ["queued-container"]:
            queued_container_confirmation_pty_test(binary)
        elif sys.argv[1:] == ["dashboard-recent-activity"]:
            dashboard_recent_activity_pty_test(binary)
        else:
            raise SystemExit(f"unknown PTY test selector: {' '.join(sys.argv[1:])}")
        return
    if not dashboard_only:
        terminal_restoration_pty_test()
        doctor_configuration_pty_test(binary)
        self_update_pty_test(binary)
        queued_container_confirmation_pty_test(binary)
    if not dashboard_only and sys.platform == "linux":
        history_purge_pty_test(binary)
        temp_cleanup_review_pty_test(binary)
        trim_preview_read_only_pty_test(binary)
        go_test_preview_read_only_pty_test(binary)
        artifact_preview_read_only_pty_test(binary)
        go_output_preview_fails_closed_pty_test(binary)
    dashboard_recent_activity_pty_test(binary)
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
    before = termios.tcgetattr(slave)
    with tempfile.TemporaryDirectory() as home:
        env = os.environ.copy()
        env.update(HOME=home, TERM="xterm", PATH="", XDG_DATA_HOME=home, XDG_CONFIG_HOME=home)
        env.pop("CI", None)
        child = subprocess.Popen(
            [binary, "--timeout", "1", "--retries", "0"],
            stdin=slave, stdout=slave, stderr=slave, env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()
        transcript = bytearray()

        def read_output():
            data = os.read(master, 65536)
            output.extend(data)
            transcript.extend(data)

        try:
            deadline = time.monotonic() + 10
            while (
                b"Upkit" not in output
                or b"Recent activity" not in terminal_text(output)
            ) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    read_output()
            assert b"Upkit" in output, "dashboard did not render"
            assert b"Storage & maintenance" in terminal_text(output)
            assert b"Recent activity" in terminal_text(output)
            os.write(master, b"?")
            deadline = time.monotonic() + 10
            while b"Keyboard help" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    read_output()
            assert b"Keyboard help" in output, "keyboard help did not render"
            help_closed_at = len(output)
            help_closed_text = b"Recent activity"
            os.write(master, b"?")
            deadline = time.monotonic() + 10
            while (
                help_closed_text not in terminal_text(output[help_closed_at:])
                and time.monotonic() < deadline
            ):
                if select.select([master], [], [], 0.2)[0]:
                    read_output()
            assert help_closed_text in terminal_text(output[help_closed_at:]), "dashboard did not redraw after closing help"
            resized_at = len(output)
            dashboard_page = b"Dashboard"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 18, 59, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            deadline = time.monotonic() + 10
            while (
                dashboard_page not in terminal_text(output[resized_at:])
                and time.monotonic() < deadline
            ):
                if select.select([master], [], [], 0.2)[0]:
                    read_output()
            assert dashboard_page in terminal_text(output[resized_at:]), "dashboard did not redraw after resize"
            navigated_at = len(output)
            toolchains_markers = (
                b"Checking toolchains in the background",
                b"installed:",
                b"Toolchain check failed; results are unavailable.",
            )
            os.write(master, b"\t")
            deadline = time.monotonic() + 10
            while (
                not any(
                    marker in terminal_text(output[navigated_at:])
                    for marker in toolchains_markers
                )
                and time.monotonic() < deadline
            ):
                if select.select([master], [], [], 0.2)[0]:
                    read_output()
            navigated_output = terminal_text(output[navigated_at:])
            assert any(marker in navigated_output for marker in toolchains_markers), (
                "Tab navigation did not render the Toolchains screen; output after Tab: "
                f"{navigated_output.decode(errors='replace')!r}"
            )
            assert b"r: refresh" in navigated_output and b"Enter: update" in navigated_output, (
                "narrow Toolchains footer hid refresh or update controls: "
                + navigated_output.decode(errors="replace")
            )
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            ready_deadline = time.monotonic() + 15
            while (
                b"installed:" not in terminal_text(output)
                and b"Toolchain check failed" not in terminal_text(output)
                and time.monotonic() < ready_deadline
            ):
                if select.select([master], [], [], 0.2)[0]:
                    read_output()
            assert b"installed:" in terminal_text(output), (
                "toolchain inventory did not finish before refresh: "
                + terminal_text(output).decode(errors="replace")
            )
            output.clear()
            os.write(master, b"/go\r")
            filter_deadline = time.monotonic() + 10
            while b"Filter: go" not in terminal_text(output) and time.monotonic() < filter_deadline:
                if select.select([master], [], [], 0.2)[0]:
                    read_output()
            assert b"Filter: go" in terminal_text(output), (
                "toolchain filter did not apply: "
                + terminal_text(output).decode(errors="replace")
            )
            output.clear()
            os.write(master, b"r")
            refresh_deadline = time.monotonic() + 15
            while (
                b"Toolchain inventory refreshed." not in terminal_screen_text(transcript, 30, 120)
                and time.monotonic() < refresh_deadline
            ):
                if select.select([master], [], [], 0.2)[0]:
                    read_output()
            refreshed_screen = terminal_screen_text(transcript, 30, 120)
            assert b"Toolchain inventory refreshed." in refreshed_screen, (
                "r did not refresh the toolchain inventory: "
                + refreshed_screen.decode(errors="replace")
            )
            assert b"Filter: go" in refreshed_screen, (
                "toolchain refresh lost the active filter: "
                + refreshed_screen.decode(errors="replace")
            )
            os.write(master, b"\x03")
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    read_output()
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before, "terminal attributes were not restored"
            assert not os.listdir(home), "opening the dashboard changed its isolated home"
            while select.select([master], [], [], 0)[0]:
                read_output()
            assert b"\x1b[?1049h" in transcript and b"\x1b[?1049l" in transcript
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("TUI PTY smoke test passed")
    if dashboard_only:
        return

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        project = home / "project"
        target = project / "target"
        target.mkdir(parents=True)
        (project / "Cargo.toml").write_text("[workspace]\n")
        (target / "fixture").write_text("keep")
        config = home / "config.toml"
        config.write_text(f"version = 1\nworkspace_roots = [{json.dumps(str(project))}]\n")
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 140, 0, 0))
        before = termios.tcgetattr(slave)
        env = {"HOME": temporary, "TERM": "xterm", "PATH": "", "XDG_DATA_HOME": str(home / "data"), "XDG_CONFIG_HOME": str(home / "config")}
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "--config", str(config)], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while b"Dashboard" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Dashboard" in terminal_text(output)
            output.clear()
            os.write(master, b"s")
            deadline = time.monotonic() + 10
            while str(target).encode() not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert str(target).encode() in terminal_text(output), terminal_text(output).decode(errors="replace")
            config.write_text(f"version = 1\nworkspace_roots = [{json.dumps(str(project))}]\nexclusions = ['target']\n")
            output.clear()
            os.write(master, b"r")
            deadline = time.monotonic() + 10
            while b"No artifacts found" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"No artifacts found" in terminal_text(output), terminal_text(output).decode(errors="replace")
            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
            assert (target / "fixture").read_text() == "keep"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Configured dashboard scan and rescan PTY test passed")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        config = home / "config.toml"
        original = "version = 1\n# original\n"
        config.write_text(original)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
        before = termios.tcgetattr(slave)
        env = {"HOME": temporary, "TERM": "xterm", "PATH": "", "XDG_DATA_HOME": str(home / "data"), "XDG_CONFIG_HOME": str(home / "config")}
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "--config", str(config), "config", "show"], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while b"Press e for structured fields, t for TOML" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Press e for structured fields, t for TOML" in terminal_text(output), terminal_text(output).decode(errors="replace")
            output.clear()
            os.write(master, b"t\x1b[F #edited")
            time.sleep(0.3)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 10, 45, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.2)
            os.write(master, b"\x13")
            deadline = time.monotonic() + 10
            while b"Confirm settings" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm settings" in terminal_text(output), terminal_text(output).decode(errors="replace")
            os.write(master, b"y")
            time.sleep(0.4)
            assert config.read_text() == original, "small terminal allowed configuration save"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.4)
            os.write(master, b"y")
            deadline = time.monotonic() + 10
            while config.read_text() == original and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert config.read_text() == "version = 1 #edited\n# original\n", terminal_text(output).decode(errors="replace")
            backups = list(home.glob(".upkit-config-backup-*.toml"))
            assert len(backups) == 1 and backups[0].read_text() == original
            deadline = time.monotonic() + 10
            while b"Backup:" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Backup:" in terminal_text(output), terminal_text(output).decode(errors="replace")
            os.write(master, b"\x1b")
            time.sleep(0.2)
            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Settings editor confirmation, save, and backup PTY test passed")
    if sys.platform == "linux":
        structured_settings_form_pty_test(binary)

    managed_cleanup_pty_test(binary)


    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        trash = home / "Trash"
        (trash / "files").mkdir(parents=True)
        (trash / "info").mkdir()
        (trash / "files" / "fixture").write_text("keep")
        metadata = trash / "info" / "fixture.trashinfo"
        metadata.write_text("[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n")
        for path in (trash, trash / "files", trash / "info"):
            path.chmod(0o700)
        for path in (trash / "files" / "fixture", metadata):
            path.chmod(0o600)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 110, 0, 0))
        before = termios.tcgetattr(slave)
        env = {"HOME": str(home), "TERM": "xterm", "PATH": "", "TZ": "UTC", "XDG_DATA_HOME": str(home), "XDG_CONFIG_HOME": str(home / "config")}
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "trash", "preview", "--older-than", "30d"], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while b"older_than_threshold" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"older_than_threshold" in output, "Trash retention preview did not render"
            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
            assert (trash / "files" / "fixture").read_text() == "keep"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Trash retention TUI PTY test passed")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        trash = home / "Trash"
        (trash / "files").mkdir(parents=True)
        (trash / "info").mkdir()
        (trash / "files" / "fixture").write_text("keep")
        (trash / "info" / "fixture.trashinfo").write_text("[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n")
        for path in (trash, trash / "files", trash / "info"):
            path.chmod(0o700)
        for path in (trash / "files" / "fixture", trash / "info" / "fixture.trashinfo"):
            path.chmod(0o600)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
        before = termios.tcgetattr(slave)
        env = {"HOME": str(home), "TERM": "xterm", "PATH": "", "TZ": "UTC", "XDG_DATA_HOME": str(home), "XDG_CONFIG_HOME": str(home / "config")}
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "trash", "preview-retention", "--location", str(trash), "--older-than", "30d"], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while (b"Confirm permanent Trash deletion" not in output or b"Eligible:" not in output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm permanent Trash deletion" in output, "direct retention preview did not render"
            assert b"Eligible:" in output, "retention summary was not shown"
            os.write(master, b"nq")
            assert child.wait(timeout=10) == 0
            assert (trash / "files" / "fixture").read_text() == "keep"
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Direct Trash retention preview TUI PTY test passed")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        trash = home / "Trash"
        (trash / "files").mkdir(parents=True)
        (trash / "info").mkdir()
        for path in (trash, trash / "files", trash / "info"):
            path.chmod(0o700)
        def add_trash_file(name):
            item = trash / "files" / name
            metadata = trash / "info" / (name + ".trashinfo")
            item.write_text(name)
            metadata.write_text("[Trash Info]\nDeletionDate=not-a-date\n")
            item.chmod(0o600)
            metadata.chmod(0o600)
        add_trash_file("fixture")
        directory = trash / "files" / "folder"
        directory.mkdir(mode=0o700)
        (directory / "nested").write_text("nested")
        (directory / "nested").chmod(0o600)
        directory_info = trash / "info" / "folder.trashinfo"
        directory_info.write_text("[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n")
        directory_info.chmod(0o600)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
        before = termios.tcgetattr(slave)
        env = {"HOME": str(home), "TERM": "xterm", "PATH": "", "TZ": "UTC", "XDG_DATA_HOME": str(home), "XDG_CONFIG_HOME": str(home / "config")}
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "trash", "empty", "--location", str(trash)], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while (b"Confirm permanent Trash deletion" not in terminal_text(output) or b"fixture" not in terminal_text(output) or b"folder" not in terminal_text(output) or b"descendants=1" not in terminal_text(output)) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm permanent Trash deletion" in terminal_text(output), terminal_text(output).decode(errors="replace")
            assert b"regardless of age" in terminal_text(output)
            assert b"fixture" in terminal_text(output)
            assert b"folder" in terminal_text(output) and b"descendants=1" in terminal_text(output)
            add_trash_file("new")
            output.clear()
            os.write(master, b"y")
            deadline = time.monotonic() + 10
            while b"review the complete selection again" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"review the complete selection again" in terminal_text(output), terminal_text(output).decode(errors="replace")
            assert (trash / "files" / "fixture").read_text() == "fixture"
            assert (trash / "files" / "new").read_text() == "new"
            assert (directory / "nested").read_text() == "nested"
            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Trash empty TUI stale-selection test passed using temporary fixtures")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        trash = home / "Trash"
        directory = trash / "files" / "folder"
        directory.mkdir(parents=True)
        (trash / "info").mkdir()
        for path in (trash, trash / "files", trash / "info", directory):
            path.chmod(0o700)
        (directory / "nested").write_text("fixture")
        (directory / "nested").chmod(0o600)
        metadata = trash / "info" / "folder.trashinfo"
        metadata.write_text("[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n")
        metadata.chmod(0o600)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
        before = termios.tcgetattr(slave)
        env = {"HOME": str(home), "TERM": "xterm", "PATH": "", "TZ": "UTC", "XDG_DATA_HOME": str(home), "XDG_CONFIG_HOME": str(home / "config")}
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "trash", "empty", "--location", str(trash)], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while (b"Confirm permanent Trash deletion" not in terminal_text(output) or b"descendants=1" not in terminal_text(output)) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm permanent Trash deletion" in terminal_text(output), terminal_text(output).decode(errors="replace")
            assert b"descendants=1" in terminal_text(output)
            time.sleep(0.2)
            os.write(master, b"y")
            deadline = time.monotonic() + 10
            while (directory.exists() or metadata.exists()) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert not directory.exists() and not metadata.exists()
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Trash directory removal TUI test passed using temporary fixtures")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        trash = home / "Trash"
        (trash / "files").mkdir(parents=True)
        (trash / "info").mkdir()
        (trash / "files" / "fixture").write_text("fixture")
        (trash / "info" / "fixture.trashinfo").write_text("[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n")
        (trash / "files" / "second").write_text("second")
        (trash / "info" / "second.trashinfo").write_text("[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n")
        (trash / "files" / "untouched").write_text("untouched")
        (trash / "info" / "untouched.trashinfo").write_text("[Trash Info]\nDeletionDate=2999-01-01T00:00:00\n")
        for path in (trash, trash / "files", trash / "info"):
            path.chmod(0o700)
        for path in (trash / "files" / "fixture", trash / "info" / "fixture.trashinfo", trash / "files" / "second", trash / "info" / "second.trashinfo", trash / "files" / "untouched", trash / "info" / "untouched.trashinfo"):
            path.chmod(0o600)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
        before = termios.tcgetattr(slave)
        env = {"HOME": str(home), "TERM": "xterm", "PATH": "", "TZ": "UTC", "XDG_DATA_HOME": str(home), "XDG_CONFIG_HOME": str(home / "config")}
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "trash", "preview", "--older-than", "30d"], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while b"older_than_threshold" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"older_than_threshold" in output, "Trash preview did not render"
            os.write(master, b"A")
            deadline = time.monotonic() + 10
            size = 24
            redraw_at = 0
            while b"2 eligible; 1 newer/unknown; 0 unsupported" not in terminal_text(output) and time.monotonic() < deadline:
                # Ratatui emits screen differences; force a redraw while the worker finishes.
                if time.monotonic() >= redraw_at:
                    size = 25 if size == 24 else 24
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", size, 120, 0, 0))
                    os.kill(child.pid, signal.SIGWINCH)
                    redraw_at = time.monotonic() + 0.25
                if select.select([master], [], [], 0.1)[0]:
                    output.extend(os.read(master, 65536))
            assert b"2 eligible; 1 newer/unknown; 0 unsupported" in terminal_text(output), f"age-based selection did not finish: {terminal_text(output)[-3000:].decode(errors='replace')}"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            # The selected-count message is asynchronous. Let the resized
            # frame settle before attempting Enter: continuous SIGWINCH and an
            # immediate Enter can be consumed before the review is ready.
            time.sleep(0.2)
            for attempt in range(4):
                if b"Review marked Trash" in terminal_text(output):
                    break
                os.write(master, b"\r")
                deadline = time.monotonic() + 2.5
                while b"Review marked Trash" not in terminal_text(output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
            reviewed = terminal_text(output)
            assert b"Review marked Trash" in reviewed, (
                "Trash review did not render: "
                f"{reviewed[-3000:].decode(errors='replace')!r}"
            )
            output.clear()
            os.write(master, b"d")
            deadline = time.monotonic() + 10
            size = 24
            redraw_at = 0
            retry_at = time.monotonic() + 0.5
            while (b"Confirm permanent Trash deletion" not in terminal_text(output) or b"second" not in terminal_text(output)) and time.monotonic() < deadline:
                if time.monotonic() >= retry_at:
                    os.write(master, b"d")
                    retry_at = time.monotonic() + 0.5
                if time.monotonic() >= redraw_at:
                    size = 25 if size == 24 else 24
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", size, 120, 0, 0))
                    os.kill(child.pid, signal.SIGWINCH)
                    redraw_at = time.monotonic() + 0.25
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm permanent Trash deletion" in terminal_text(output), terminal_text(output)[-3000:].decode(errors="replace")
            assert b"second" in terminal_text(output), "second selected file was not shown"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 12, 50, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.3)
            os.write(master, b"y")
            time.sleep(0.5)
            assert (trash / "files" / "fixture").exists(), "small terminal allowed permanent deletion"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.3)
            os.write(master, b"y")
            deadline = time.monotonic() + 10
            while (trash / "files" / "fixture").exists() and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert not (trash / "files" / "fixture").exists(), "fixture Trash item was not deleted"
            deadline = time.monotonic() + 10
            while b"verified_absent" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"verified_absent" in output, "per-item deletion result was not shown"
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert child.wait(timeout=2) == 0
            assert not (trash / "info" / "fixture.trashinfo").exists()
            assert not (trash / "files" / "second").exists()
            assert not (trash / "info" / "second.trashinfo").exists()
            assert (trash / "files" / "untouched").read_text() == "untouched"
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Trash retention and batch removal TUI PTY test passed using temporary fixture")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary) / "home"
        workspace = Path(temporary) / "workspace"
        home.mkdir()
        (workspace / "target").mkdir(parents=True)
        (workspace / "Cargo.toml").write_text("[workspace]\n")
        artifact = workspace / "target" / "keep"
        artifact.write_text("fixture")
        (workspace / "python" / "__pycache__").mkdir(parents=True)
        (workspace / "python" / "pyproject.toml").write_text("[project]\n")
        (workspace / "python" / "__pycache__" / "keep").write_text("fixture")
        config = Path(temporary) / "config.toml"
        config.write_text(f"version = 1\n[profiles.work]\nworkspace_roots = ['{workspace}']\nenabled_ecosystems = ['cargo']\n")
        for command in ("scan", "preview"):
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 220, 0, 0))
            before = termios.tcgetattr(slave)
            env = os.environ.copy()
            env.update(HOME=str(home), TERM="xterm", PATH="", XDG_DATA_HOME=str(home), XDG_CONFIG_HOME=str(home))
            env.pop("CI", None)
            child = subprocess.Popen(
                [binary, "--timeout", "1", "--retries", "0", "--config", str(config), "--profile", "work", "sweep", command],
                stdin=slave, stdout=slave, stderr=slave, env=env,
                preexec_fn=controlling_pty_preexec(slave),
            )
            output = bytearray()
            try:
                deadline = time.monotonic() + 10
                marker = b"Selected (including hidden):" if command == "preview" else b"cargo"
                warning = (
                    os.fsencode(workspace / "python" / "__pycache__")
                    + b": subtree skipped because python artifacts are disabled; "
                    + b"nested projects may not be detected"
                )
                while time.monotonic() < deadline:
                    rendered = terminal_text(output)
                    if marker in rendered and warning in rendered:
                        break
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                rendered = terminal_text(output)
                assert marker in rendered, (
                    f"{command} results did not render; output: {rendered.decode(errors='replace')!r}"
                )
                assert warning in rendered, (
                    f"{command} did not render the disabled-subtree warning; "
                    f"output: {rendered.decode(errors='replace')!r}"
                )
                if command == "preview":
                    os.write(master, b" \rqq")
                else:
                    os.write(master, b"q")
                assert child.wait(timeout=10) == 0
                assert termios.tcgetattr(slave) == before
                assert artifact.read_text() == "fixture"
                assert not re.search(rb"\[[ x]\]\s*python(?:\s|$)", rendered), (
                    f"{command} showed a Python candidate; output: "
                    f"{rendered.decode(errors='replace')!r}"
                )
                assert not list(home.iterdir())
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)
                os.close(slave)
    print("Artifact scan and preview TUI PTY smoke tests passed")

    unshare = shutil.which("unshare")
    mount = shutil.which("mount")
    namespace_args = ["--user", "--map-root-user", "--pid", "--fork", "--mount", "--mount-proc"]
    private_etc_opt_namespace = private_etc_opt_namespace_available(
        unshare, mount, namespace_args
    )
    if private_etc_opt_namespace:
        cache_tui_pty_smoke_test(binary, unshare, mount, namespace_args)
    else:
        print("Cache TUI PTY smoke test skipped: private mount namespace with /etc/opt bind is unavailable")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        bin_dir = home / "bin"
        bin_dir.mkdir()
        image_id = "f" * 64
        docker = bin_dir / "docker"
        docker.write_text(f'''#!/bin/sh
case "$*" in
  'system df --format json') printf '%s\\n' '{{"Type":"Images","Total":"2","Size":"12MB"}}' ;;
  'container ls --all --size --no-trunc --format json') printf '%s\\n' '{{"Names":"test-container","State":"exited"}}' ;;
  'image ls --all --format json') printf '[]\\n' ;;
  'image ls --all --filter dangling=true --no-trunc --format json') printf '[{{"ID":"sha256:{image_id}","Size":"8MB"}}]\\n' ;;
  'image rm '*) printf attempted > "$HOME/image-rm-called" ;;
  'buildx inspect --timeout=2s') printf 'Name: fixture\\nNodes:\\n' ;;
  'buildx --builder fixture du --timeout=2s --format=json') printf '%s\\n' '{{"ID":"cache-fixture","Size":"1MB","Mutable":false,"Shared":false,"Reclaimable":true}}' ;;
  *) printf '[]\\n' ;;
esac
''')
        docker.chmod(0o755)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        before = termios.tcgetattr(slave)
        env = {"HOME": str(home), "TERM": "xterm", "PATH": str(bin_dir), "IMAGE_ID": image_id, "XDG_DATA_HOME": str(home / "data"), "XDG_CONFIG_HOME": str(home / "config")}
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "containers", "status"], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while (b"12MB" not in output or b"test-container" not in output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"12MB" in output, "container inventory did not render"
            assert b"test-container" in output, "container listing did not render"
            deadline = time.monotonic() + 10
            while b"read-only; removal unsupported" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"read-only; removal unsupported" in terminal_text(output), "dangling images were not marked read-only"
            assert image_id[:12].encode() in terminal_text(output), "read-only image inventory did not render its ID"
            os.write(master, b"d")
            time.sleep(0.5)
            while select.select([master], [], [], 0.1)[0]:
                output.extend(os.read(master, 65536))
            assert b"Confirm image removal" not in terminal_text(output), "TUI offered image removal"
            assert not (home / "image-rm-called").exists(), "TUI invoked image rm"
            deadline = time.monotonic() + 10
            while b"cache-fixture" not in output and time.monotonic() < deadline:
                os.write(master, b"\x1b[6~")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"cache-fixture" in output, "build-cache inventory did not render"
            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
            assert sorted(path.name for path in home.iterdir()) == ["bin"]
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Container and read-only image TUI PTY smoke test passed")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        bin_dir = home / "bin"
        bin_dir.mkdir()
        container_id = "a" * 64
        network_id = "d" * 64
        docker = bin_dir / "docker"
        docker.write_text(f'''#!/bin/sh
case "$*" in
  'system df --format json') printf '%s\\n' '{{"Type":"Images","Total":"1","Size":"12MB"}}' ;;
  'info --format json') printf '%s\\n' '{{"ID":"fixture-daemon"}}' ;;
  'container ls --all --size --no-trunc --format json') printf '%s\\n' '{{"ID":"{container_id}","State":"exited","Names":"other-container"}}' ;;
  'image ls --all --format json'|'image ls --all --filter dangling=true --no-trunc --format json'|'volume ls --format json') printf '[]\\n' ;;
  'network ls --format json'|'network ls --filter dangling=true --filter type=custom --no-trunc --format json') printf '{{"ID":"%s","Name":"temporary-net","Driver":"bridge"}}\\n' "$NETWORK_ID" ;;
  'network inspect '*) printf '[{{"Id":"%s","Name":"temporary-net","Driver":"bridge","Scope":"local","Containers":{{}}}}]\\n' "$NETWORK_ID" ;;
  'network rm '*) printf removed > "$HOME/removed" ;;
  'container rm -- '*) printf removed > "$HOME/removed" ;;
  'buildx inspect --timeout=2s') printf 'Name: fixture\\nNodes:\\n' ;;
  'buildx --builder fixture du --timeout=2s --format=json') printf '[]\\n' ;;
  *) printf '[]\\n' ;;
esac
''')
        docker.chmod(0o755)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
        before = termios.tcgetattr(slave)
        env = {
            "HOME": str(home),
            "TERM": "xterm",
            "PATH": str(bin_dir),
            "NETWORK_ID": network_id,
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CONFIG_HOME": str(home / "config"),
        }
        child = subprocess.Popen(
            [binary, "--timeout", "1", "--retries", "0", "containers", "status"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while b"temporary-net" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"temporary-net" in terminal_text(output), "fake network inventory did not render"

            # Terminal key events are FIFO, so Enter applies the filter before d selects its result.
            while select.select([master], [], [], 0)[0]:
                os.read(master, 65536)
            output.clear()
            os.write(master, b"/temporary-net\rd")
            deadline = time.monotonic() + 10
            while (b"Confirm network removal" not in terminal_text(output)
                   or network_id.encode() not in terminal_text(output)) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            preview = terminal_text(output)
            assert b"Confirm network removal" in preview, "filtered target opened the wrong preview"
            assert network_id.encode() in preview, "network preview did not show the selected full ID"
            assert not (home / "removed").exists(), "preview executed a removal"
            os.write(master, b"nq")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
            assert not (home / "removed").exists(), "canceled preview invoked a removal command"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Container filter and exact-target preview TUI PTY test passed with fake engine")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        bin_dir = home / "bin"
        bin_dir.mkdir()
        docker = bin_dir / "docker"
        container_id = "a" * 64
        docker.write_text("""#!/bin/sh
case "$*" in
  'system df --format json') printf '%s\\n' '{"Type":"Containers","Size":"123B"}' ;;
  'info --format json') printf '%s\\n' '{"ID":"fixture-daemon"}' ;;
  'container ls --all --size --no-trunc --format json')
    if [ -f "$HOME/removed" ]; then printf '[]\\n'; else printf '{"ID":"%s","State":"exited","Names":"fixture"}\\n' "$EXPECTED_ID"; fi ;;
  'container inspect --size '*) printf '[{"Id":"%s","Name":"fixture","RestartCount":0,"SizeRw":123,"State":{"Status":"exited","Running":false,"Restarting":false,"StartedAt":"a","FinishedAt":"b"}}]\\n' "$4" ;;
  'container rm -- '*) [ "$4" = "$EXPECTED_ID" ] && [ "$#" = 4 ] || exit 2; printf removed > "$HOME/removed" ;;
  'container ls --all --no-trunc --filter '*) [ -f "$HOME/removed" ] || exit 3; printf '[]\\n' ;;
  *) printf '[]\\n' ;;
esac
""")
        docker.chmod(0o755)
        direct_master, direct_slave = pty.openpty()
        fcntl.ioctl(direct_slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 110, 0, 0))
        direct_before = termios.tcgetattr(direct_slave)
        direct_env = {"HOME": str(home), "TERM": "xterm", "PATH": str(bin_dir), "EXPECTED_ID": container_id, "XDG_DATA_HOME": str(home / "data"), "XDG_CONFIG_HOME": str(home / "config")}
        direct = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "containers", "preview-remove", "--engine", "docker", "--id", container_id], stdin=direct_slave, stdout=direct_slave, stderr=direct_slave, env=direct_env, preexec_fn=controlling_pty_preexec(direct_slave))
        direct_output = bytearray()
        try:
            os.write(direct_master, b"y" * 64)
            deadline = time.monotonic() + 10
            while b"Confirm container removal" not in direct_output and time.monotonic() < deadline:
                if select.select([direct_master], [], [], 0.2)[0]:
                    direct_output.extend(os.read(direct_master, 65536))
            assert b"Confirm container removal" in direct_output, "direct container preview did not render"
            time.sleep(0.3)
            assert direct.poll() is None
            assert not (home / "removed").exists(), "queued input confirmed an unseen plan"
            os.write(direct_master, b"nq")
            assert direct.wait(timeout=10) == 0
            assert not (home / "removed").exists()
            assert termios.tcgetattr(direct_slave) == direct_before
        finally:
            if direct.poll() is None:
                direct.kill()
                direct.wait()
            os.close(direct_master)
            os.close(direct_slave)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 110, 0, 0))
        before = termios.tcgetattr(slave)
        env = {"HOME": str(home), "TERM": "xterm", "PATH": str(bin_dir), "EXPECTED_ID": container_id, "XDG_DATA_HOME": str(home / "data"), "XDG_CONFIG_HOME": str(home / "config")}
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "containers", "status"], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while b"fixture" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"fixture" in output, "stopped container did not render"
            os.write(master, b"d")
            deadline = time.monotonic() + 10
            while b"Confirm container removal" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm container removal" in output, "container preview did not render"
            assert not (home / "removed").exists(), "preview executed removal"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 60, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            os.write(master, b"y")
            time.sleep(0.3)
            assert not (home / "removed").exists(), "small terminal allowed confirmation"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 110, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.3)
            os.write(master, b"y")
            deadline = time.monotonic() + 10
            while b"removed; absence verif" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"removed; absence verif" in output, "fake removal was not verified"
            assert (home / "removed").read_text() == "removed"
            os.write(master, b"\t\t")
            deadline = time.monotonic() + 10
            while b"verified_absent" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"verified_absent" in output, "operation history did not render"
            os.write(master, b"q")
            assert child.wait(timeout=10) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Stopped-container removal TUI PTY test passed with fake engine")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        workspace = home / "workspace"
        workspace.mkdir()
        unit_dir = home / "config/systemd/user"
        unit_dir.mkdir(parents=True, mode=0o700)
        unit_dir.chmod(0o700)
        settings_dir = home / "config/upkit"
        settings_dir.mkdir()
        (settings_dir / "config.toml").write_text(f"version = 1\nworkspace_roots = ['{workspace}']\n")
        bin_dir = home / "bin"
        bin_dir.mkdir()
        systemctl = bin_dir / "systemctl"
        systemctl.write_text(r'''#!/bin/sh
[ "$1" = --user ] || exit 8
case "$2" in
  show)
    case "$5" in
      --property=FragmentPath) [ ! -e "$XDG_CONFIG_HOME/systemd/user/$3" ] || printf '%s\n' "$XDG_CONFIG_HOME/systemd/user/$3" ;;
      --property=LoadState) if [ -e "$XDG_CONFIG_HOME/systemd/user/$3" ]; then printf 'loaded\n'; else printf 'not-found\n'; fi ;;
      --property=NeedDaemonReload) printf 'no\n' ;;
      --property=ActiveState) printf 'inactive\n' ;;
      --property=DropInPaths) : ;;
      --property=LoadState,ActiveState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime)
        if [ ! -e "$XDG_CONFIG_HOME/systemd/user/upkit-scan.timer" ]; then printf 'LoadState=not-found\n'; elif [ -s "$HOME/timer_inactive" ]; then printf 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n'; elif [ -f "$HOME/installed" ]; then printf 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'; else printf 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n'; fi ;;
      *) exit 9 ;;
    esac ;;
  daemon-reload) if [ -f "$HOME/change_during_reload" ]; then printf "version = 1\nworkspace_roots = ['$HOME/workspace']\nexclusions = ['private']\n" > "$XDG_CONFIG_HOME/upkit/config.toml"; fi ;;
  disable) [ "$3" = --now ] && [ "$4" = upkit-scan.timer ] || exit 7; printf disabled > "$HOME/disabled"; printf inactive > "$HOME/timer_inactive" ;;
  enable) [ "$3" = --now ] && [ "$4" = upkit-scan.timer ] || exit 7; if [ -f "$HOME/disabled" ]; then printf enabled > "$HOME/enabled_again"; else printf enabled > "$HOME/installed"; fi; if [ -f "$HOME/timer_inactive" ]; then : > "$HOME/timer_inactive"; fi ;;
  *) exit 6 ;;
esac
''')
        systemctl.chmod(0o755)
        env = {"HOME": str(home), "TERM": "xterm", "PATH": str(bin_dir), "XDG_DATA_HOME": str(home / "data"), "XDG_CONFIG_HOME": str(home / "config")}
        preview = subprocess.run([binary, "--json", "--non-interactive", "schedule", "preview", "--frequency", "daily", str(workspace)], env=env, capture_output=True, check=True)
        plan = json.loads(preview.stdout)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 240, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "schedule", "list"], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()

        def wait_for_schedule_review(marker):
            deadline = time.monotonic() + 10
            while marker not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert marker in terminal_text(output), "complete schedule review did not render"
            settle = time.monotonic() + 0.2
            while time.monotonic() < settle:
                if select.select([master], [], [], 0.05)[0]:
                    output.extend(os.read(master, 65536))

        try:
            deadline = time.monotonic() + 10
            while b"not_found" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"not_found" in output, "missing timer status did not render"
            os.write(master, b"a")
            deadline = time.monotonic() + 15
            while b"Confirm timer installation" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer installation" in output, "timer install preview did not render"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 60, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            os.write(master, b"y")
            time.sleep(0.3)
            assert not (unit_dir / "upkit-scan.service").exists(), "small terminal allowed installation"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 240, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.3)
            (home / "change_during_reload").write_text("fixture")
            output.clear()
            os.write(master, b"y")
            deadline = time.monotonic() + 15
            failed = False
            while not failed and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    failed |= entry.get("operation") == "schedule_install" and entry.get("outcome") == "failed_or_unknown"
            assert failed, "configuration change during reload was not reported"
            assert not (home / "installed").exists(), "changed configuration allowed timer installation"
            assert (unit_dir / "upkit-scan.service").exists() and (unit_dir / "upkit-scan.timer").exists()
            expected_service = (unit_dir / "upkit-scan.service").read_text()
            assert "--scope-token v2." in expected_service
            (unit_dir / "upkit-scan.service").unlink()
            (unit_dir / "upkit-scan.timer").unlink()
            (home / "change_during_reload").unlink()
            (settings_dir / "config.toml").write_text(f"version = 1\nworkspace_roots = ['{workspace}']\n")
            output.clear()
            deadline = time.monotonic() + 15
            while b"Confirm timer installation" not in output and time.monotonic() < deadline:
                os.write(master, b"a")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer installation" in output, "fresh timer install preview did not render"
            wait_for_schedule_review(b"Press y to install; Esc/n cancels.")
            output.clear()
            os.write(master, b"y")
            deadline = time.monotonic() + 15
            installed = False
            while not installed and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    installed |= entry.get("operation") == "schedule_install" and entry.get("outcome") == "completed"
            assert installed, "timer installation was not verified and recorded"
            assert (home / "installed").read_text() == "enabled"
            assert (unit_dir / "upkit-scan.service").read_text() == expected_service
            assert (unit_dir / "upkit-scan.timer").read_text() == plan["timer_unit"]
            output.clear()
            deadline = time.monotonic() + 15
            while b"Confirm timer disable" not in output and time.monotonic() < deadline:
                os.write(master, b"d")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer disable" in output, "timer disable preview did not render"
            deadline = time.monotonic() + 15
            while b"Confirm timer disable" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer disable" in output, "timer preview did not render"
            assert not (home / "disabled").exists()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 60, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            os.write(master, b"y")
            time.sleep(0.3)
            assert not (home / "disabled").exists(), "small terminal allowed timer confirmation"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 240, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.3)
            output.clear()
            os.write(master, b"y")
            deadline = time.monotonic() + 15
            while (b"inactive" not in output or not (home / "disabled").exists()) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"inactive" in output, "updated timer state did not render"
            assert (home / "disabled").read_text() == "disabled"
            assert (unit_dir / "upkit-scan.service").read_text() == expected_service
            assert (unit_dir / "upkit-scan.timer").read_text() == plan["timer_unit"]
            deadline = time.monotonic() + 15
            disabled_recorded = False
            while not disabled_recorded and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    disabled_recorded |= entry.get("operation") == "schedule_disable" and entry.get("outcome") == "completed"
            assert disabled_recorded, "timer disable was not verified and recorded"
            output.clear()
            deadline = time.monotonic() + 15
            while b"Confirm timer enable" not in output and time.monotonic() < deadline:
                os.write(master, b"1")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer enable" in output, f"timer enable preview did not render: {terminal_text(output)[-1200:]}"
            assert not (home / "enabled_again").exists()
            output.clear()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 41, 240, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            deadline = time.monotonic() + 10
            while b"Confirm timer enable" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer enable" in terminal_text(output), "timer enable review did not redraw after resize"
            for _ in range(30):
                os.write(master, b"\x1b[6~")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                if b"cancels." in terminal_text(output):
                    break
            assert b"cancels." in terminal_text(output), "timer enable review did not reach the end"
            (settings_dir / "config.toml").write_text(f"version = 1\nworkspace_roots = ['{workspace}']\nexclusions = ['private']\n")
            output.clear()
            os.write(master, b"y")
            deadline = time.monotonic() + 15
            while b"inactive" not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            refreshed_status = terminal_text(output)
            assert b"inactive" in refreshed_status, (
                "timer status did not refresh after configuration changed: "
                f"{refreshed_status[-3000:].decode(errors='replace')!r}"
            )
            assert not (home / "enabled_again").exists(), "changed configuration allowed enabling"
            (settings_dir / "config.toml").write_text(f"version = 1\nworkspace_roots = ['{workspace}']\n")
            output.clear()
            deadline = time.monotonic() + 15
            while b"Confirm timer enable" not in output and time.monotonic() < deadline:
                os.write(master, b"1")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer enable" in output, "fresh timer enable preview did not render"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 60, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            os.write(master, b"y")
            time.sleep(0.3)
            assert not (home / "enabled_again").exists(), "small terminal allowed timer enable confirmation"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 240, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.3)
            output.clear()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 41, 240, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            for _ in range(30):
                os.write(master, b"\x1b[6~")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                if b"cancels." in terminal_text(output):
                    break
            assert b"cancels." in terminal_text(output), "timer enable review after resize did not reach the end"
            # On a slower ARM64 runner the final resize and page events may
            # still be queued. Wait for the fully drawn review before approval.
            time.sleep(0.3)
            output.clear()
            os.write(master, b"y")
            deadline = time.monotonic() + 25
            verified = False
            while not verified and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    verified |= entry.get("operation") == "schedule_enable" and entry.get("outcome") == "completed"
            assert verified, (
                "timer enable was not verified and recorded: "
                + terminal_text(output)[-1600:]
                    .decode(errors="replace")
                    .replace(str(home), "<fixture-home>")
            )
            assert (home / "enabled_again").read_text() == "enabled"
            assert (unit_dir / "upkit-scan.service").read_text() == expected_service
            assert (unit_dir / "upkit-scan.timer").read_text() == plan["timer_unit"]
            output.clear()
            deadline = time.monotonic() + 15
            while b"Confirm timer disable" not in output and time.monotonic() < deadline:
                os.write(master, b"d")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer disable" in output, "second timer disable preview did not render"
            wait_for_schedule_review(b"Press y to disable; Esc/n cancels.")
            output.clear()
            os.write(master, b"y")
            deadline = time.monotonic() + 15
            disables = 0
            while disables < 2 and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                disables = 0
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    disables += entry.get("operation") == "schedule_disable" and entry.get("outcome") == "completed"
            assert disables >= 2, "second disable was not verified and recorded"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 70, 300, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            output.clear()
            deadline = time.monotonic() + 15
            while b"Confirm timer replacement" not in output and time.monotonic() < deadline:
                os.write(master, b"E")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer replacement" in output, "timer edit preview did not render"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 60, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            os.write(master, b"y")
            time.sleep(0.3)
            assert (unit_dir / "upkit-scan.timer").read_text() == plan["timer_unit"], "small terminal allowed schedule replacement"
            output.clear()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 70, 300, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            deadline = time.monotonic() + 10
            review_start = b"Review all lines"
            review_end = b"Press y to replace; Esc/n cancels."
            while (
                (review_start not in terminal_text(output) or review_end not in terminal_text(output))
                and time.monotonic() < deadline
            ):
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert review_start in terminal_text(output) and review_end in terminal_text(output), (
                "replacement review did not redraw completely after resize: "
                + terminal_text(output).decode(errors="replace")
            )
            (home / "change_during_reload").write_text("fixture")
            os.write(master, b"y")
            deadline = time.monotonic() + 20
            failed_edit = False
            while not failed_edit and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    failed_edit |= entry.get("operation") == "schedule_edit" and entry.get("outcome") == "failed_or_unknown"
            assert failed_edit, "configuration change during replacement was not recorded"
            assert not (unit_dir / "upkit-scan.service").exists() and not (unit_dir / "upkit-scan.timer").exists()
            assert (home / "timer_inactive").read_text() == "inactive"
            (home / "change_during_reload").unlink()
            (settings_dir / "config.toml").write_text(f"version = 1\nworkspace_roots = ['{workspace}']\n")
            for name, key in [("upkit-scan.service", "service_unit"), ("upkit-scan.timer", "timer_unit")]:
                path = unit_dir / name
                path.write_text(plan[key])
                path.chmod(0o600)
            output.clear()
            deadline = time.monotonic() + 15
            while b"Confirm timer replacement" not in output and time.monotonic() < deadline:
                os.write(master, b"E")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer replacement" in output, "fresh timer edit preview did not render"
            wait_for_schedule_review(b"Press y to replace; Esc/n cancels.")
            output.clear()
            os.write(master, b"y")
            deadline = time.monotonic() + 20
            edited = False
            while not edited and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    edited |= entry.get("operation") == "schedule_edit" and entry.get("outcome") == "completed"
            assert edited, "schedule replacement was not verified and recorded"
            assert "OnCalendar=weekly" in (unit_dir / "upkit-scan.timer").read_text()
            assert (home / "timer_inactive").read_text() == ""
            output.clear()
            deadline = time.monotonic() + 15
            while b"Confirm timer disable" not in output and time.monotonic() < deadline:
                os.write(master, b"d")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer disable" in output, "edited timer disable preview did not render"
            wait_for_schedule_review(b"Press y to disable; Esc/n cancels.")
            output.clear()
            os.write(master, b"y")
            deadline = time.monotonic() + 15
            disables = 0
            while disables < 3 and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                disables = 0
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    disables += entry.get("operation") == "schedule_disable" and entry.get("outcome") == "completed"
            assert disables >= 3, "edited timer disable was not verified"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 240, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            output.clear()
            deadline = time.monotonic() + 15
            while b"Confirm timer unit removal" not in output and time.monotonic() < deadline:
                os.write(master, b"x")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm timer unit removal" in output, "timer removal preview did not render"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 60, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            os.write(master, b"y")
            time.sleep(0.3)
            assert (unit_dir / "upkit-scan.service").exists() and (unit_dir / "upkit-scan.timer").exists(), "small terminal allowed unit removal"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 240, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.3)
            output.clear()
            os.write(master, b"y")
            deadline = time.monotonic() + 15
            removed = False
            while not removed and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    removed |= entry.get("operation") == "schedule_remove" and entry.get("outcome") == "completed"
            if not removed:
                removal_records = []
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    if entry.get("operation") == "schedule_remove":
                        removal_records.append(
                            {key: entry.get(key) for key in ("operation", "outcome", "detail")}
                        )
                diagnostic = terminal_text(output)[-5000:].decode(errors="replace")
                diagnostic = diagnostic.replace(str(home), "<fixture-home>")
                diagnostic = diagnostic.replace(str(Path(binary).resolve()), "<binary>")
                raise AssertionError(
                    "unit removal was not verified and recorded; "
                    f"records={removal_records!r}; UI={diagnostic!r}"
                )
            assert not (unit_dir / "upkit-scan.service").exists() and not (unit_dir / "upkit-scan.timer").exists()
            assert not list(unit_dir.glob(".upkit-remove-*"))
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
        direct_workspace = home / "direct-workspace"
        direct_workspace.mkdir()
        expected = subprocess.run([binary, "--json", "--non-interactive", "schedule", "preview", "--frequency", "weekly", "--exclude", "private", str(direct_workspace)], env=env, capture_output=True, check=True)
        expected_plan = json.loads(expected.stdout)
        dry = subprocess.run([binary, "--dry-run", "--json", "schedule", "add", "--frequency", "weekly", "--exclude", "private", str(direct_workspace)], env=env, capture_output=True, check=True)
        assert json.loads(dry.stdout)["dry_run"]
        assert not (unit_dir / "upkit-scan.timer").exists()
        input_master, input_slave = pty.openpty()
        try:
            redirected = subprocess.run([binary, "schedule", "preview", "--frequency", "weekly", str(direct_workspace)], stdin=input_slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=10, check=True)
            assert b"Preview token:" in redirected.stdout and b"\x1b[?1049h" not in redirected.stdout
        finally:
            os.close(input_master)
            os.close(input_slave)

        def direct_schedule(command, title, finished=None, readonly=False):
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 70, 300, 0, 0))
            before = termios.tcgetattr(slave)
            child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "schedule", *command], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
            output = bytearray()
            try:
                deadline = time.monotonic() + 15
                while title not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert title in output, terminal_text(output).decode(errors="replace")[-2500:]
                if not readonly:
                    while b"Esc/n cancels." not in terminal_text(output) and time.monotonic() < deadline:
                        if select.select([master], [], [], 0.2)[0]:
                            output.extend(os.read(master, 65536))
                    assert b"Esc/n cancels." in terminal_text(output), "complete schedule review did not render"
                settle = time.monotonic() + 0.3
                while time.monotonic() < settle:
                    if select.select([master], [], [], 0.05)[0]:
                        output.extend(os.read(master, 65536))
                os.write(master, b"y")
                if readonly:
                    time.sleep(0.4)
                    assert not (unit_dir / "upkit-scan.timer").exists(), "preview command changed the schedule"
                    os.write(master, b"\x1b")
                else:
                    deadline = time.monotonic() + 15
                    while not finished() and time.monotonic() < deadline:
                        if select.select([master], [], [], 0.2)[0]:
                            output.extend(os.read(master, 65536))
                    assert finished(), terminal_text(output).decode(errors="replace")[-2500:]
                deadline = time.monotonic() + 10
                while child.poll() is None and time.monotonic() < deadline:
                    os.write(master, b"q")
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert child.wait(timeout=2) == 0
                assert termios.tcgetattr(slave) == before
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)
                os.close(slave)

        direct_args = ["--frequency", "weekly", "--exclude", "private", str(direct_workspace)]
        direct_schedule(["preview", *direct_args], b"Preview timer installation", readonly=True)
        direct_schedule(["add", *direct_args], b"Confirm timer installation", lambda: (unit_dir / "upkit-scan.timer").exists())
        assert (unit_dir / "upkit-scan.service").read_text() == expected_plan["service_unit"]
        assert (unit_dir / "upkit-scan.timer").read_text() == expected_plan["timer_unit"]
        direct_schedule(["disable"], b"Confirm timer disable", lambda: (home / "timer_inactive").read_text() == "inactive")
        direct_schedule(["enable", *direct_args], b"Confirm timer enable", lambda: (home / "timer_inactive").read_text() == "")
        direct_schedule(["disable"], b"Confirm timer disable", lambda: (home / "timer_inactive").read_text() == "inactive")
        edit_args = ["--frequency", "daily", "--exclude", "private", str(direct_workspace)]
        direct_schedule(["edit", *edit_args], b"Confirm timer replacement", lambda: (unit_dir / "upkit-scan.timer").exists() and "OnCalendar=daily" in (unit_dir / "upkit-scan.timer").read_text())
        direct_schedule(["disable"], b"Confirm timer disable", lambda: (home / "timer_inactive").read_text() == "inactive")
        direct_schedule(["remove"], b"Confirm timer unit removal", lambda: not (unit_dir / "upkit-scan.timer").exists())
        assert not (unit_dir / "upkit-scan.service").exists()
    print("Direct schedule commands TUI PTY test passed with fake manager")
    print("Schedule lifecycle TUI PTY test passed with fake manager")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        workspace = home / "workspace"
        workspace.mkdir()
        config_parts = [f"settings-{index:02d}-" + "x" * 180 for index in range(14)]
        config = home.joinpath(*config_parts, "config.toml")
        config.parent.mkdir(parents=True)
        config.write_text(
            "version = 1\n"
            "[profiles.work]\n"
            f"workspace_roots = [{json.dumps(str(workspace))}]\n"
            "artifact_retention = '30d'\n"
            "enabled_ecosystems = ['cargo']\n"
        )
        unit_dir = home / "config-home/systemd/user"
        unit_dir.mkdir(parents=True, mode=0o700)
        unit_dir.chmod(0o700)
        bin_dir = home / "bin"
        bin_dir.mkdir()
        systemctl = bin_dir / "systemctl"
        systemctl.write_text(r'''#!/bin/sh
[ "$1" = --user ] || exit 8
case "$2" in
  show)
    case "$5" in
      --property=FragmentPath) [ ! -e "$XDG_CONFIG_HOME/systemd/user/$3" ] || printf '%s\n' "$XDG_CONFIG_HOME/systemd/user/$3" ;;
      --property=LoadState) if [ -e "$XDG_CONFIG_HOME/systemd/user/$3" ]; then printf 'loaded\n'; else printf 'not-found\n'; fi ;;
      --property=NeedDaemonReload) printf 'no\n' ;;
      --property=ActiveState) printf 'inactive\n' ;;
      --property=DropInPaths) : ;;
      --property=LoadState,ActiveState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime)
        if [ ! -e "$XDG_CONFIG_HOME/systemd/user/upkit-scan.timer" ]; then printf 'LoadState=not-found\n'; elif [ -f "$HOME/installed" ]; then printf 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'; else printf 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n'; fi ;;
      *) exit 9 ;;
    esac ;;
  daemon-reload) printf 'reload\n' >> "$HOME/manager-actions" ;;
  enable) [ "$3" = --now ] && [ "$4" = upkit-scan.timer ] || exit 7; printf 'enable\n' >> "$HOME/manager-actions"; printf enabled > "$HOME/installed" ;;
  *) exit 6 ;;
esac
''')
        systemctl.chmod(0o755)
        env = {
            "HOME": str(home),
            "TERM": "xterm",
            "PATH": str(bin_dir),
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CONFIG_HOME": str(home / "config-home"),
        }
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen(
            [binary, "--config", str(config), "--profile", "work", "--timeout", "1", "--retries", "0", "schedule", "list"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def read_until(marker, timeout=15):
            deadline = time.monotonic() + timeout
            while marker not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            return marker in terminal_text(output)

        try:
            assert read_until(b"not_found"), "missing timer status did not render"
            os.write(master, b"a")
            assert read_until(b"Confirm timer installation"), "configured timer install preview did not render"

            os.write(master, b"y")
            time.sleep(0.3)
            assert not (unit_dir / "upkit-scan.service").exists(), "early y installed the v2 unit"
            assert not (home / "manager-actions").exists(), "early y changed the fake manager"

            for _ in range(30):
                os.write(master, b"\x1b[6~")
                time.sleep(0.12)
                if select.select([master], [], [], 0)[0]:
                    output.extend(os.read(master, 65536))
                if b"cancels." in terminal_text(output):
                    break
            assert b"cancels." in terminal_text(output), "PageDown review did not reach the end"

            output.clear()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 82, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            assert read_until(b"Review all lines"), "resized schedule review did not redraw"
            os.write(master, b"y")
            time.sleep(0.3)
            assert not (unit_dir / "upkit-scan.service").exists(), "resize preserved the previous review progress"
            assert not (home / "manager-actions").exists(), "y after resize changed the fake manager"

            output.clear()
            for _ in range(30):
                os.write(master, b"\x1b[6~")
                time.sleep(0.12)
                if select.select([master], [], [], 0)[0]:
                    output.extend(os.read(master, 65536))
                if b"cancels." in terminal_text(output):
                    break
            assert b"cancels." in terminal_text(output), "resized PageDown review did not reach the end"
            os.write(master, b"y")
            deadline = time.monotonic() + 20
            while not (home / "installed").exists() and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert (home / "installed").exists(), "reviewed v2 timer was not enabled"
            assert (unit_dir / "upkit-scan.service").exists(), "reviewed v2 timer was not installed"
            assert (home / "installed").read_text() == "enabled"
            assert "reload" in (home / "manager-actions").read_text()
            assert "enable" in (home / "manager-actions").read_text()
            service_unit = (unit_dir / "upkit-scan.service").read_text()
            assert "--scope-token v2." in service_unit
            scope_token = service_unit.split("--scope-token ", 1)[1].split()[0]
            assert len(scope_token) > 5000, f"configured v2 token was not long: {len(scope_token)}"

            deadline = time.monotonic() + 15
            completed = False
            while not completed and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    completed |= entry.get("operation") == "schedule_install" and entry.get("outcome") == "completed"
            assert completed, "reviewed v2 installation was not recorded"
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Long configured v2 schedule review TUI PTY test passed with fake manager")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        workspace = home / "workspace"
        workspace.mkdir()
        config = home / "config.toml"
        config.write_text(
            "version = 1\n"
            "[profiles.work]\n"
            f"workspace_roots = [{json.dumps(str(workspace))}]\n"
            "artifact_retention = '30d'\n"
            "enabled_ecosystems = ['cargo']\n"
        )
        unit_dir = home / "config/systemd/user"
        unit_dir.mkdir(parents=True, mode=0o700)
        unit_dir.chmod(0o700)
        bin_dir = home / "bin"
        bin_dir.mkdir()
        systemctl = bin_dir / "systemctl"
        systemctl.write_text(r'''#!/bin/sh
[ "$1" = --user ] || exit 8
case "$2" in
  show)
    case "$5" in
      --property=FragmentPath) [ ! -e "$XDG_CONFIG_HOME/systemd/user/$3" ] || printf '%s\n' "$XDG_CONFIG_HOME/systemd/user/$3" ;;
      --property=LoadState) if [ -e "$XDG_CONFIG_HOME/systemd/user/$3" ]; then printf 'loaded\n'; else printf 'not-found\n'; fi ;;
      --property=NeedDaemonReload) printf 'no\n' ;;
      --property=ActiveState) printf 'inactive\n' ;;
      --property=DropInPaths) : ;;
      --property=LoadState,ActiveState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime)
        if [ ! -e "$XDG_CONFIG_HOME/systemd/user/upkit-scan.timer" ]; then printf 'LoadState=not-found\n'; elif [ -f "$HOME/installed" ]; then printf 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'; else printf 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n'; fi ;;
      *) exit 9 ;;
    esac ;;
  daemon-reload)
    printf 'reload\n' >> "$HOME/manager-actions"
    if [ -f "$HOME/change_during_reload" ]; then
      printf "version = 1\n[profiles.work]\nworkspace_roots = ['$HOME/workspace']\nartifact_retention = '7d'\nenabled_ecosystems = ['cargo', 'python']\nscheduled_bytecode_cleanup = true\n" > "$CONFIG_FILE"
    fi ;;
  enable) [ "$3" = --now ] && [ "$4" = upkit-scan.timer ] || exit 7; printf 'enable\n' >> "$HOME/manager-actions"; printf enabled > "$HOME/installed" ;;
  *) exit 6 ;;
esac
''')
        systemctl.chmod(0o755)
        env = {
            "HOME": str(home),
            "TERM": "xterm",
            "PATH": str(bin_dir),
            "CONFIG_FILE": str(config),
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CONFIG_HOME": str(home / "config"),
        }
        preview = subprocess.run(
            [binary, "--json", "--non-interactive", "--config", str(config), "--profile", "work",
             "schedule", "preview", "--frequency", "daily"],
            env=env,
            capture_output=True,
            check=True,
        )
        plan = json.loads(preview.stdout)
        assert plan["roots"] == [str(workspace)]
        assert plan["scheduled_scope_token"].startswith("v2."), "configured preview omitted its policy token"

        config.write_text(
            "version = 1\n"
            "[profiles.work]\n"
            f"workspace_roots = [{json.dumps(str(workspace))}]\n"
            "artifact_retention = '30d'\n"
            "enabled_ecosystems = ['cargo', 'python']\n"
            "scheduled_bytecode_cleanup = true\n"
        )
        cleanup_preview = subprocess.run(
            [binary, "--json", "--non-interactive", "--config", str(config), "--profile", "work",
             "schedule", "preview", "--frequency", "daily"],
            env=env,
            capture_output=True,
            check=True,
        )
        cleanup_plan = json.loads(cleanup_preview.stdout)
        assert cleanup_plan["scheduled_scope_token"].startswith("v3.")
        assert "automatically and permanently removes eligible Python bytecode" in cleanup_plan["warning"]
        assert "at most 32 files per run" in cleanup_plan["warning"]

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen(
            [binary, "--config", str(config), "--profile", "work", "--timeout", "1", "--retries", "0",
             "schedule", "add", "--frequency", "daily"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=controlling_pty_preexec(slave),
        )
        output = bytearray()

        def read_until(marker, timeout=15):
            deadline = time.monotonic() + timeout
            while marker not in terminal_text(output) and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            return marker in terminal_text(output)

        try:
            assert read_until(b"Confirm timer installation"), "configured CLI request did not render its preview"
            for _ in range(30):
                os.write(master, b"\x1b[6~")
                time.sleep(0.12)
                if select.select([master], [], [], 0)[0]:
                    output.extend(os.read(master, 65536))
                if b"cancels." in terminal_text(output):
                    break
            assert b"cancels." in terminal_text(output), "configured schedule review did not reach the end"
            reviewed = terminal_screen_text(output, 24, 120)
            assert b"automatically and permanently removes eligible Python bytecode" in reviewed
            assert b"at most 32 files are removed per run" in reviewed
            assert b"revalidated against" in reviewed
            assert b"No files are cleaned" not in reviewed
            assert b"no workspace files are cleaned" not in reviewed

            (home / "change_during_reload").write_text("fixture")
            os.write(master, b"y")
            deadline = time.monotonic() + 20
            failed = False
            while not failed and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
                for record in (home / "data/upkit/history").glob("*.json"):
                    try:
                        entry = json.loads(record.read_text())
                    except (OSError, ValueError):
                        continue
                    failed |= entry.get("operation") == "schedule_install" and entry.get("outcome") == "failed_or_unknown"
            assert failed, "changed configured policy was not rejected and recorded"
            assert not (home / "installed").exists(), "configuration drift still enabled the timer"
            assert (unit_dir / "upkit-scan.service").exists() and (unit_dir / "upkit-scan.timer").exists()
            service_unit = (unit_dir / "upkit-scan.service").read_text()
            assert "--scope-token v3." in service_unit
            assert "scheduled-bytecode-cleanup --authorize-scheduled-cleanup" in service_unit
            actions = (home / "manager-actions").read_text()
            assert "reload" in actions and "enable" not in actions

            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Configured schedule CLI preview and TUI PTY test passed with fake manager")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        cache_id = "a" * 25
        engine = home / "docker"
        engine.write_text('''#!/bin/sh
case "$*" in
  'info --format json') printf '%s\\n' '{"ID":"fixture-server"}' ;;
  'system df --format json') printf '[]\\n' ;;
  'buildx inspect --timeout=2s'|'buildx inspect fixture --timeout=2s') printf 'Name: fixture\\nDriver: docker-container\\nNodes:\\nName: node0\\nEndpoint: fixture\\nStatus: running\\n' ;;
  'buildx --builder fixture du --timeout=2s --format=json')
    if [ -f "$HOME/removed" ]; then printf '[]\\n'; else printf '{"ID":"%s","Size":"1MB","Type":"regular","CreatedAt":"2025-01-01","Reclaimable":true,"Shared":false,"Mutable":false}\\n' "$CACHE_ID"; fi ;;
  "buildx --builder fixture prune --timeout=2s --force --filter id=^${CACHE_ID}$ --filter immutable=\\"\\" --filter private=\\"\\"") printf removed > "$HOME/removed" ;;
  *) printf '[]\\n' ;;
esac
''')
        engine.chmod(0o755)
        env = os.environ.copy()
        env.update(HOME=temporary, PATH=temporary, TERM="xterm", CACHE_ID=cache_id,
                   XDG_DATA_HOME=str(home / "data"), XDG_CONFIG_HOME=str(home / "config"))
        env.pop("CI", None)
        def build_cache_dialog(command, readonly):
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 12 if not readonly else 24, 50 if not readonly else 120, 0, 0))
            before = termios.tcgetattr(slave)
            child = subprocess.Popen([binary, "containers", command, "--builder", "fixture", "--id", cache_id],
                                     stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
            output = bytearray()
            try:
                title = b"Build cache preview" if readonly else b"Confirm build cache removal"
                deadline = time.monotonic() + 10
                while title not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert title in output, f"{command} did not render"
                os.write(master, b"y")
                time.sleep(0.5)
                assert not (home / "removed").exists(), "read-only or small-terminal preview removed cache"
                if not readonly:
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
                    os.kill(child.pid, signal.SIGWINCH)
                    time.sleep(0.3)
                    os.write(master, b"y")
                    deadline = time.monotonic() + 10
                    while not (home / "removed").exists() and time.monotonic() < deadline:
                        if select.select([master], [], [], 0.2)[0]:
                            output.extend(os.read(master, 65536))
                    assert (home / "removed").exists(), "confirmed cache removal did not run"
                else:
                    os.write(master, b"\x1b")
                deadline = time.monotonic() + 10
                while child.poll() is None and time.monotonic() < deadline:
                    os.write(master, b"q")
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert child.wait(timeout=2) == 0
                assert termios.tcgetattr(slave) == before
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)
                os.close(slave)
        build_cache_dialog("preview-build-cache", True)
        build_cache_dialog("remove-build-cache", False)
    print("Build-cache preview and removal TUI PTY tests passed with fake engine")

    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        network_id = "b" * 64
        engine = home / "docker"
        engine.write_text('''#!/bin/sh
case "$1 $2" in
  'info --format') printf '%s\\n' '{"ID":"fixture-server"}' ;;
  'network inspect') printf '[{"Id":"%s","Name":"fixture","Driver":"bridge","Scope":"local","Containers":{}}]\\n' "$NETWORK_ID" ;;
  'network ls') if [ -f "$HOME/removed" ]; then printf '[]\\n'; else printf '[{"ID":"%s"}]\\n' "$NETWORK_ID"; fi ;;
  'network rm') [ "$3" = -- ] && [ "$4" = "$NETWORK_ID" ] && [ "$#" = 4 ] || exit 1; printf removed > "$HOME/removed" ;;
  *) printf '[]\\n' ;;
esac
''')
        engine.chmod(0o755)
        env = os.environ.copy()
        env.update(HOME=temporary, PATH=temporary, TERM="xterm", NETWORK_ID=network_id,
                   XDG_DATA_HOME=str(home / "data"), XDG_CONFIG_HOME=str(home / "config"))
        env.pop("CI", None)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 12, 50, 0, 0))
        before = termios.tcgetattr(slave)
        child = subprocess.Popen([binary, "--timeout", "1", "--retries", "0", "containers",
                                  "preview-network", "--engine", "docker", "--id", network_id],
                                 stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=controlling_pty_preexec(slave))
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while b"Confirm network removal" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert b"Confirm network removal" in output, "network preview did not render"
            os.write(master, b"y")
            time.sleep(0.5)
            assert not (home / "removed").exists(), "small terminal allowed network removal"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            time.sleep(0.3)
            os.write(master, b"y")
            deadline = time.monotonic() + 10
            while not (home / "removed").exists() and time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert (home / "removed").exists(), "network removal did not run"
            deadline = time.monotonic() + 10
            while child.poll() is None and time.monotonic() < deadline:
                os.write(master, b"q")
                if select.select([master], [], [], 0.2)[0]:
                    output.extend(os.read(master, 65536))
            assert child.wait(timeout=2) == 0
            assert termios.tcgetattr(slave) == before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)
            os.close(slave)
    print("Unused-network removal TUI PTY test passed with fake engine")

    unshare = shutil.which("unshare")
    mount = shutil.which("mount")
    git = fixture_git()
    namespace_args = ["--user", "--map-root-user", "--pid", "--fork", "--mount", "--mount-proc"]
    if (
        unshare
        and git
        and subprocess.run(
            [unshare, *namespace_args, "/bin/true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0
    ):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            project = home / "project"
            cache = project / "__pycache__"
            cache.mkdir(parents=True)
            project.chmod(0o700)
            cache.chmod(0o700)
            manifest = project / "pyproject.toml"
            manifest.write_text("[project]\nname='fixture'\n")
            manifest.chmod(0o600)
            source = project / "example.py"
            source.write_text("value = 1\n")
            source.chmod(0o600)
            metadata = source.stat()
            bytecode = cache / "example.cpython-311.pyc"
            bytecode.write_bytes(struct.pack("<H2sIII", 3495, b"\r\n", 0, int(metadata.st_mtime), metadata.st_size) + b"\0")
            bytecode.chmod(0o600)
            real_git = git
            git_env = {"HOME": temporary, "PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
            git_args = [real_git, "-C", str(project), "-c", "core.hooksPath=/dev/null", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgSign=false"]
            for args in (["init", "-q"], ["add", "pyproject.toml", "example.py"], ["commit", "-qm", "fixture"]):
                subprocess.run([*git_args, *args], env=git_env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            bindir = home / "bin"
            bindir.mkdir(mode=0o700)
            wrapper = bindir / "git"
            shutil.copy(real_git, wrapper)
            config = home / "config.toml"
            config.write_text("version = 1\n")
            env = os.environ.copy()
            env.update(HOME=temporary, PATH="bin:/usr/bin:/bin", TERM="xterm", XDG_DATA_HOME=str(home / "data"), XDG_CONFIG_HOME=str(home / "config"))
            env.pop("CI", None)
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 12, 50, 0, 0))
            before = termios.tcgetattr(slave)
            child = subprocess.Popen([unshare, *namespace_args, binary, "--timeout", "1", "--retries", "0", "--config", str(config), "sweep", "bytecode", str(bytecode), "--root", str(project)], stdin=slave, stdout=slave, stderr=slave, env=env, cwd=temporary, preexec_fn=controlling_pty_preexec(slave))
            output = bytearray()
            try:
                deadline = time.monotonic() + 15
                while b"Confirm bytecode removal" not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Confirm bytecode removal" in output, terminal_text(output).decode(errors="replace")
                time.sleep(0.2)
                os.write(master, b"y")
                time.sleep(0.4)
                assert bytecode.exists(), "small terminal allowed bytecode deletion"
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
                children = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text().split()
                assert children, "could not find the namespaced Upkit process"
                os.kill(int(children[0]), signal.SIGWINCH)
                time.sleep(0.4)
                config.write_text("version = 1\nexclusions = ['__pycache__']\n")
                os.write(master, b"y")
                deadline = time.monotonic() + 10
                while b"configuration changed" not in terminal_text(output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"configuration changed" in terminal_text(output), terminal_text(output).decode(errors="replace")
                assert bytecode.exists(), "changed exclusions allowed bytecode deletion"
                os.write(master, b"q")
                assert child.wait(timeout=10) == 0
                assert termios.tcgetattr(slave) == before
                assert source.read_text() == "value = 1\n"
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)
                os.close(slave)
            config.write_text("version = 1\n")
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
            before = termios.tcgetattr(slave)
            child = subprocess.Popen([unshare, *namespace_args, binary, "--timeout", "1", "--retries", "0", "--config", str(config), "sweep", "bytecode", str(bytecode), "--root", str(project)], stdin=slave, stdout=slave, stderr=slave, env=env, cwd=temporary, preexec_fn=controlling_pty_preexec(slave))
            output = bytearray()
            try:
                deadline = time.monotonic() + 15
                while b"Confirm bytecode removal" not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Confirm bytecode removal" in output, terminal_text(output).decode(errors="replace")
                while b"Press y to remove this file" not in terminal_text(output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Press y to remove this file" in terminal_text(output), "complete bytecode review did not render"
                time.sleep(0.2)
                os.write(master, b"y")
                deadline = time.monotonic() + 10
                while bytecode.exists() and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert not bytecode.exists(), terminal_text(output).decode(errors="replace")
                deadline = time.monotonic() + 10
                while child.poll() is None and time.monotonic() < deadline:
                    os.write(master, b"q")
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert child.wait(timeout=2) == 0
                assert termios.tcgetattr(slave) == before
                assert source.read_text() == "value = 1\n"
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)
                os.close(slave)
            contents = struct.pack("<H2sIII", 3495, b"\r\n", 0, int(metadata.st_mtime), metadata.st_size) + b"\0"
            bytecode.write_bytes(contents)
            bytecode.chmod(0o600)
            other_bytecode = cache / "example.cpython-311.opt-1.pyc"
            other_bytecode.write_bytes(contents)
            other_bytecode.chmod(0o600)
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
            before = termios.tcgetattr(slave)
            child = subprocess.Popen([unshare, *namespace_args, binary, "--timeout", "1", "--retries", "0", "--config", str(config), "sweep", "scan", str(project)], stdin=slave, stdout=slave, stderr=slave, env=env, cwd=temporary, preexec_fn=controlling_pty_preexec(slave))
            output = bytearray()
            try:
                deadline = time.monotonic() + 15
                while (b"__pycache__" not in terminal_text(output) or b"Read-only scan" not in terminal_text(output)) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"__pycache__" in terminal_text(output) and b"Read-only scan" in terminal_text(output), terminal_text(output).decode(errors="replace")
                output.clear()
                os.write(master, b"b")
                deadline = time.monotonic() + 10
                while b"Choose bytecode file" not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Choose bytecode file" in output, terminal_text(output).decode(errors="replace")
                output.clear()
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 25, 161, 0, 0))
                children = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text().split()
                assert children
                os.kill(int(children[0]), signal.SIGWINCH)
                deadline = time.monotonic() + 10
                while (b"example.cpython-311.opt-1.pyc" not in output or b"example.cpython-311.pyc" not in output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"example.cpython-311.opt-1.pyc" in output and b"example.cpython-311.pyc" in output, terminal_text(output).decode(errors="replace")
                output.clear()
                os.write(master, b"j\r")
                deadline = time.monotonic() + 15
                while b"Confirm bytecode removal" not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Confirm bytecode removal" in output, terminal_text(output).decode(errors="replace")
                while b"Press y to remove this file" not in terminal_text(output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Press y to remove this file" in terminal_text(output), "complete bytecode review did not render"
                time.sleep(0.2)
                os.write(master, b"y")
                deadline = time.monotonic() + 10
                while bytecode.exists() and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert not bytecode.exists(), terminal_text(output).decode(errors="replace")
                assert other_bytecode.read_bytes() == contents
                deadline = time.monotonic() + 10
                while child.poll() is None and time.monotonic() < deadline:
                    os.write(master, b"q")
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert child.wait(timeout=2) == 0
                assert termios.tcgetattr(slave) == before
                assert source.read_text() == "value = 1\n"
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)
                os.close(slave)
            bytecode.write_bytes(contents)
            bytecode.chmod(0o600)
            third_bytecode = cache / "example.cpython-311.opt-2.pyc"
            third_bytecode.write_bytes(contents)
            third_bytecode.chmod(0o600)
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
            before = termios.tcgetattr(slave)
            child = subprocess.Popen([unshare, *namespace_args, binary, "--timeout", "1", "--retries", "0", "--config", str(config), "sweep", "scan", str(project)], stdin=slave, stdout=slave, stderr=slave, env=env, cwd=temporary, preexec_fn=controlling_pty_preexec(slave))
            output = bytearray()
            try:
                deadline = time.monotonic() + 15
                while (b"__pycache__" not in terminal_text(output) or b"Read-only scan" not in terminal_text(output)) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"__pycache__" in terminal_text(output), terminal_text(output).decode(errors="replace")
                output.clear()
                os.write(master, b"b")
                deadline = time.monotonic() + 10
                while b"Choose bytecode file" not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Choose bytecode file" in output, terminal_text(output).decode(errors="replace")
                output.clear()
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 25, 161, 0, 0))
                children = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text().split()
                assert children
                os.kill(int(children[0]), signal.SIGWINCH)
                deadline = time.monotonic() + 10
                while (b"example.cpython-311.opt-1.pyc" not in output or b"example.cpython-311.opt-2.pyc" not in output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"example.cpython-311.opt-1.pyc" in output and b"example.cpython-311.opt-2.pyc" in output, terminal_text(output).decode(errors="replace")
                output.clear()
                os.write(master, b" j \r")
                deadline = time.monotonic() + 15
                while (b"Confirm bytecode batch removal" not in output or b"opt-1.pyc" not in output or b"opt-2.pyc" not in output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Confirm bytecode batch removal" in output, terminal_text(output).decode(errors="replace")
                assert b"opt-1.pyc" in output and b"opt-2.pyc" in output
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 12, 50, 0, 0))
                children = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text().split()
                assert children
                os.kill(int(children[0]), signal.SIGWINCH)
                os.write(master, b"y")
                time.sleep(0.4)
                assert other_bytecode.exists() and third_bytecode.exists(), "small terminal allowed batch deletion"
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
                os.kill(int(children[0]), signal.SIGWINCH)
                time.sleep(0.4)
                os.write(master, b"y")
                deadline = time.monotonic() + 15
                while (other_bytecode.exists() or third_bytecode.exists()) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert not other_bytecode.exists() and not third_bytecode.exists(), terminal_text(output).decode(errors="replace")
                assert bytecode.read_bytes() == contents
                deadline = time.monotonic() + 10
                while b"Cleanup result" not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"Cleanup result" in output, terminal_text(output).decode(errors="replace")
                deadline = time.monotonic() + 10
                while child.poll() is None and time.monotonic() < deadline:
                    os.write(master, b"q")
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert child.wait(timeout=2) == 0
                assert termios.tcgetattr(slave) == before
                assert source.read_text() == "value = 1\n"
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)
                os.close(slave)
        print("Bytecode TUI confirmation, config recheck, and removal PTY tests passed in an isolated namespace")
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            project = home / os.fsdecode(b"project-\xff%")
            target = project / "target"
            target.mkdir(parents=True)
            project.chmod(0o700)
            target.chmod(0o700)
            manifest = project / "Cargo.toml"
            manifest.write_text("[package]\nname='fixture'\nversion='0.1.0'\n[workspace]\n")
            manifest.chmod(0o600)
            for i in range(25):
                file = target / f"file-{i:02}"
                file.write_text("fixture")
                file.chmod(0o600)
            nested = target / ("nested-" + "a" * 100)
            nested.mkdir(mode=0o700)
            long_file = nested / ("tail-" + "b" * 100)
            long_file.write_text("fixture")
            long_file.chmod(0o600)
            last = target / "zz-LAST-COMPLETE"
            last.write_text("fixture")
            last.chmod(0o600)
            real_git = git
            git_env = {"HOME": temporary, "PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
            git_args = [real_git, "-C", str(project), "-c", "core.hooksPath=/dev/null", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgSign=false"]
            for args in (["init", "-q"], ["add", "Cargo.toml"], ["commit", "-qm", "fixture"]):
                subprocess.run([*git_args, *args], env=git_env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            bindir = home / "bin"
            bindir.mkdir(mode=0o700)
            shutil.copy(real_git, bindir / "git")
            config = home / "settings.toml"
            config.write_text("version = 1\n")
            env = os.environ.copy()
            env.update(HOME=temporary, PATH="bin:/usr/bin:/bin", TERM="xterm", XDG_DATA_HOME=str(home / "data"), XDG_CONFIG_HOME=str(home / "config"))
            env.pop("CI", None)
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 160, 0, 0))
            before = termios.tcgetattr(slave)
            child = subprocess.Popen([unshare, *namespace_args, binary, "--timeout", "1", "--retries", "0", "--config", str(config), "sweep", "run", "--scope", "artifacts", "--select", str(target), "--root", str(project)], stdin=slave, stdout=slave, stderr=slave, env=env, cwd=temporary, preexec_fn=controlling_pty_preexec(slave))
            output = bytearray()
            try:
                deadline = time.monotonic() + 20
                while b"file-00" not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"file-00" in output, terminal_text(output).decode(errors="replace")
                output.clear()
                os.write(master, b"\ry")
                time.sleep(0.4)
                assert target.exists(), "confirmation bypassed unread entries"
                os.write(master, b"j" * 8)
                time.sleep(0.5)
                output.clear()
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 25, 161, 0, 0))
                children = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text().split()
                assert children
                os.kill(int(children[0]), signal.SIGWINCH)
                deadline = time.monotonic() + 10
                while b"file-00" not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"file-00" in output, terminal_text(output).decode(errors="replace")
                os.write(master, b"\ry")
                time.sleep(0.4)
                assert target.exists(), "resize bypassed the full review"
                output.clear()
                os.write(master, b"j" * 12)
                deadline = time.monotonic() + 10
                while b"LAST-COMPLETE" not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"LAST-COMPLETE" in output, terminal_text(output).decode(errors="replace")
                output.clear()
                os.write(master, b"\r")
                time.sleep(0.3)
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 26, 162, 0, 0))
                os.kill(int(children[0]), signal.SIGWINCH)
                deadline = time.monotonic() + 10
                while b"including user data" not in terminal_text(output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert b"including user data" in terminal_text(output), terminal_text(output).decode(errors="replace")
                assert b"project-%FF%25/target" in terminal_text(output), terminal_text(output).decode(errors="replace")
                os.write(master, b"y")
                deadline = time.monotonic() + 15
                while target.exists() and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert not target.exists(), terminal_text(output).decode(errors="replace")
                deadline = time.monotonic() + 10
                while child.poll() is None and time.monotonic() < deadline:
                    os.write(master, b"q")
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert child.wait(timeout=2) == 0
                assert termios.tcgetattr(slave) == before
                assert manifest.exists()
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)
                os.close(slave)
        print("Non-Unicode artifact review and removal TUI PTY test passed in an isolated namespace")
        if private_etc_opt_namespace:
            shared_cache_review_removal_pty_test(binary, unshare, mount, namespace_args)
        else:
            print("Shared-cache review and removal TUI PTY test skipped: private mount namespace with /etc/opt bind is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            projects = [home / "project-a", home / "project-b"]
            for index, project in enumerate(projects):
                target = project / "target"
                target.mkdir(parents=True)
                project.chmod(0o700)
                target.chmod(0o700)
                manifest = project / "Cargo.toml"
                manifest.write_text("[workspace]\n")
                manifest.chmod(0o600)
                fixture = target / f"fixture-{index}"
                fixture.write_text(f"artifact-{index}")
                fixture.chmod(0o600)
                real_git = git
                git_env = {"HOME": temporary, "PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
                git_args = [real_git, "-C", str(project), "-c", "core.hooksPath=/dev/null", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgSign=false"]
                for args in (["init", "-q"], ["add", "Cargo.toml"], ["commit", "-qm", "fixture"]):
                    subprocess.run([*git_args, *args], env=git_env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            bindir = home / "bin"
            bindir.mkdir(mode=0o700)
            shutil.copy(real_git, bindir / "git")
            config = home / "config.toml"
            config.write_text("version = 1\nworkspace_roots = " + json.dumps([str(project) for project in projects]) + "\n")
            env = os.environ.copy()
            env.update(HOME=temporary, PATH="bin:/usr/bin:/bin", TERM="xterm", XDG_DATA_HOME=str(home / "data"), XDG_CONFIG_HOME=str(home / "config"))
            env.pop("CI", None)
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 12, 160, 0, 0))
            before = termios.tcgetattr(slave)
            child = subprocess.Popen([unshare, *namespace_args, binary, "--timeout", "1", "--retries", "0", "--config", str(config)], stdin=slave, stdout=slave, stderr=slave, env=env, cwd=temporary, preexec_fn=controlling_pty_preexec(slave))
            output = bytearray()

            def wait_for(marker, timeout=15):
                deadline = time.monotonic() + timeout
                while marker not in terminal_text(output) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert marker in terminal_text(output), terminal_text(output).decode(errors="replace")

            def wait_for_page(markers, timeout=15):
                deadline = time.monotonic() + timeout
                while not any(marker in terminal_text(output) for marker in markers) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                rendered = terminal_text(output)
                assert any(marker in rendered for marker in markers), rendered.decode(errors="replace")

            try:
                wait_for(b"Developer environment overview")
                for page_markers in (
                    (b"Checking toolchains in the background", b"installed:"),
                    (b"Running diagnostics in the background", b"Home filesystem available bytes:"),
                    (b"Press r",),
                ):
                    output.clear()
                    os.write(master, b"\t")
                    wait_for_page(page_markers)
                output.clear()
                os.write(master, b"r")
                wait_for(b"project-a/target")
                wait_for(b"project-b/target")
                os.write(master, b" ")
                time.sleep(0.2)
                os.write(master, b"j")
                time.sleep(0.2)
                os.write(master, b" ")
                time.sleep(0.2)

                output.clear()
                os.write(master, b"d")
                wait_for(b"Review all 2 entries across 2 selected targets")
                os.write(master, b"\x1b")
                time.sleep(0.3)
                assert all((project / "target").exists() for project in projects), "cancelling the batch preview removed a target"

                output.clear()
                os.write(master, b"d")
                wait_for(b"Review all 2 entries across 2 selected targets")
                os.write(master, b"j" * 40)
                wait_for(b"Batch warning:")
                output.clear()
                os.write(master, b"\r")
                wait_for(b"Exact reviewed targets:")
                os.write(master, b"y")
                time.sleep(0.3)
                assert all((project / "target").exists() for project in projects), "confirmation skipped unseen batch targets"
                os.write(master, b"j" * 20)
                output.clear()
                os.write(master, b"y")
                deadline = time.monotonic() + 15
                while any((project / "target").exists() for project in projects) and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        output.extend(os.read(master, 65536))
                assert all(not (project / "target").exists() for project in projects), terminal_text(output).decode(errors="replace")
                wait_for(b"Complete: true")
                children = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text().split()
                assert children, "could not find the namespaced Upkit process"
                output.clear()
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 13, 161, 0, 0))
                os.kill(int(children[0]), signal.SIGWINCH)
                wait_for(b"Complete: true")
                result_text = terminal_text(output)
                assert result_text.count(b"verified_absent") == 2 and b"project-a/target" in result_text and b"project-b/target" in result_text, result_text.decode(errors="replace")
                os.write(master, b"\x1b")
                time.sleep(0.2)
                os.write(master, b"q")
                assert child.wait(timeout=10) == 0
                assert termios.tcgetattr(slave) == before
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)
                os.close(slave)
        print("Artifact batch selection, cancellation, full review, and per-target removal PTY test passed")
    else:
        print("Bytecode, artifact removal, and shared-cache removal TUI PTY tests skipped: Git or isolated user/PID namespaces are unavailable")


if __name__ == "__main__":
    main()
