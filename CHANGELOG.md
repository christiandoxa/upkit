# Changelog

## Unreleased

This work is in progress and has not been published as a standalone release.

### Added

- A Ratatui dashboard for interactive toolchain, artifact, cache, maintenance,
  schedule, report, and settings workflows. Non-interactive commands and JSON
  remain available.
- Combined managed tool cleanup previews for marked tools on the Linux
  Toolchains screen, with full scroll review, all-target preflight, an active
  process veto, and stop-on-failure or cancellation behavior.
- Workspace artifact inventory and preview, with guarded Linux removal for
  selected directories and CPython bytecode. `upkit clean` continues to remove
  Upkit-managed toolchains; `upkit sweep` handles project artifacts.
- Local operation history, configurable workspace profiles, and read-only scan
  schedules for Linux, macOS, and Windows. Scheduled bytecode cleanup is Linux-only
  and requires explicit opt-in, an approved scope, and at least seven days' retention.
- A structured settings form for existing profiles and global scan policies,
  plus an explicit preview-and-confirm workflow for removing old history records
  on Linux.
- Cache inventory, Linux Trash and TRIM workflows, and selected Docker/Podman
  resource previews and removals. Available actions depend on the platform and
  the resource; shared caches are not cleaned automatically, and Trash
  retention has a separate Linux-only opt-in.
- Scheduled Linux Trash retention with an explicit location, a minimum 30-day
  age, and a reviewed token before installing or re-enabling a persistent daily
  systemd user timer. It defaults off, permanently deletes matching items, and
  processes at most 32 eligible items per run.
- Eclipse Temurin JDK and .NET SDK providers, subject to platform availability.
- Windows Python archive installation for x64 and ARM64. It links `python.exe`;
  use `python -m pip` because the upstream archive has no `pip.exe` launcher.
  Native Windows installation and execution remain unverified.
- Zig project artifacts and shared global-cache discovery, with explicit review
  before removal; Maven user settings inform the inferred local repository path.
- Root `target/` inventory for sbt projects as a review-only artifact, with
  ecosystem filtering and ambiguity safeguards for mixed build manifests.

### Changed

- Go cache inventory uses nonempty process values and the user `GOENV` file
  without invoking Go. Because `GOTOOLCHAIN` can select a toolchain whose
  `GOROOT/go.env` cannot be identified safely, missing Go settings remain
  unknown and affected paths are omitted; Linux shared-cache removal is blocked
  when its overlap scope is unknown. An empty GOPATH default is also unresolved
  when it may equal the active GOROOT, so GOPATH-derived module paths require an
  explicit GOPATH together with `GOMODCACHE=`, or an absolute GOMODCACHE.
- The bounded Windows reader loads Go's persistent `%APPDATA%\go\env` file or
  absolute `GOENV` override with bounded, no-reparse checks and rejects
  multiply linked files. Its 64-bit file-index identity may collide on ReFS.
  Unsafe or unavailable settings no longer cause default Go cache paths to be
  guessed.
- Windows workspace scans skip reparse points and directories whose volume
  differs from the scan root or cannot be verified. Path replacement can still
  race these checks. Windows CI is configured to test reparse-point and
  volume-boundary fixtures, but has not yet run on a Windows host.
- Esc on the Doctor screen requests cancellation. An active filesystem call may
  finish first; capability and diagnostic checks not yet started are skipped
  after cancellation is observed.
- Removed the Zig toolchain provider while retaining Zig project artifact scanning,
  ecosystem configuration, and shared-cache discovery. Existing Zig installations
  are left untouched.

### Migration and limitations

- In an interactive terminal, running `upkit` opens the dashboard. Use
  `--non-interactive` and `--json` for automation where needed.
- Destructive actions require a preview and confirmation, and some Linux
  operations require additional authorization flags. Paths and processes can
  change between checks; partial operations may leave data in quarantine.
- Artifact and cache removal and scheduled cleanup are not available on every
  platform. Native macOS and Windows behavior and the six release builds remain
  to be verified. See the README for current limits.
- Standalone installers compare the binary with `SHA256SUMS` from the same
  release base URL; Node compares its archive with `SHASUMS256.txt` from
  nodejs.org. These checksum comparisons are not independent signature checks.
- Image removal is disabled until it can preserve tags added after preview;
  Docker and Podman image inventories remain read-only.
- No telemetry is added.
