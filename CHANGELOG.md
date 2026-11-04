# Changelog

## 0.5.1 (2026-11-04) — stable UX polish update

- Highlight the currently selected navigation page and label `←/→` and `Tab`
  as ways to change sections, without occupying additional content height.
- Preserve page-specific hotkeys after toolchain refresh or other actions by
  showing status separately in the footer border. Brief successful refresh
  notices dismiss automatically; error messages remain visible.
- Simplify shared-cache inventory into readable sizes, names, and statuses;
  press `w` to inspect the full warnings, ownership, and diagnostic details.
  Removal still requires a separate review and confirmation. Clarify toolchain
  statuses and action wording to avoid suggesting immediate deletion.
- Strengthen interactive PTY regression tests and cleanup of orphaned test
  subprocesses without changing user-facing cleanup safety controls.
- **Known quality limitations:** most recent line coverage is **83.45%**
  (below the existing 90% target); interactive macOS dashboard PTY smoke
  remains unverified. Native macOS CI passed. Coverage enforcement is unchanged.

## 0.5.0 (2026-11-03) — stable release

This release is being published as the stable channel by project-owner
request after all six native cross-platform CI jobs and the six-platform
prerelease release pipeline succeeded. **The 90% line-coverage target remains
unmet:** the last measured coverage was **83.42%**. The coverage workflow
keeps its 90% threshold and will remain red until further tests are added.
The interactive dashboard PTY smoke on macOS release runners also remains
unverified because its fixture stalled; other native macOS tests and binary
smoke checks passed. Treat destructive maintenance features cautiously:
review previews, authorization tokens, and backups before use.

## 0.5.0-rc.2 (2026-11-03) — prerelease

- Release candidate replacing the unpublished `rc.1` attempt, whose build
  matrix did not finish successfully.
- Make the Windows ARM64 Task Scheduler PowerShell lookup test tolerant of
  slow hosted-runner cold starts; production utility timeout remains 10 seconds.
- Do not run the interactive dashboard PTY smoke on macOS release runners
  because it stalled there; native macOS tests, binary verification, standalone
  linkage checks and binary smoke tests remain required. Interactive macOS TUI
  smoke remains a known limitation of this prerelease.
- Line coverage remains below the 90% stable-release gate; this is **not a
  stable release** and must not replace the current stable `Latest` release.

## 0.5.0-rc.1 (2026-11-03) — tagged, not published

Release candidate for cross-platform evaluation. All six primary CI jobs
passed on 2026-11-03, but line coverage was **83.42%**, short of the 90%
stable-release target. High-risk maintenance commands remain opt-in and
fail-closed; validate backups and review target paths before using them.
This prerelease is **not** the latest stable release.

### Added

- Read-only macOS volume Trash inventory for direct `/Volumes` mounts with a
  verified user-owned `.Trashes/<effective UID>` directory. This undocumented
  layout is a bounded heuristic and has not been tested on native macOS.
- A Ratatui dashboard for interactive toolchain, artifact, cache, maintenance,
  schedule, report, and settings workflows. Non-interactive commands and JSON
  remain available.
- Interactive self-update uses a Ratatui confirmation of the selected installer
  and runs it in a background worker after the plan is reviewed.
- Combined managed tool cleanup previews for marked tools on the Linux
  Toolchains screen, with full scroll review, all-target preflight, an active
  process veto, and stop-on-failure or cancellation behavior.
- Workspace artifact inventory and preview, with guarded Linux removal for
  selected directories and CPython bytecode. `upkit clean` continues to remove
  Upkit-managed toolchains; `upkit sweep` handles project artifacts.
- Local operation history, configurable workspace profiles, and read-only scan
  schedules for Linux, macOS, and Windows. Scheduled bytecode cleanup is Linux-only
  and requires explicit opt-in, an approved scope, and at least seven days' retention.
- Opt-in scheduled Linux artifact cleanup can remove at most eight explicitly
  scoped rebuildable directories per run after at least 30 days. Each attempt
  reserves local history before removal; interrupted writes may leave records
  needing manual recovery.
- A structured settings form for existing profiles and global scan policies,
  plus an explicit preview-and-confirm workflow for removing old history records
  on Linux and macOS. The macOS history workflow has not yet been tested natively.
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
- Inspection-only Ninja build-state discovery when a standalone project's
  `build.ninja` and root `build/.ninja_log` are present; custom paths are not
  inferred and this does not authorize removal.

### Changed

- Toolchain archive downloads stop at 8 GiB, including when a server omits or
  understates the content length.
- Stale-link cleanup fails closed if process-activity results are incomplete;
  malformed container inventory rows are reported as per-list errors.
- Windows TRIM notification status rejects malformed or conflicting policy
  output rather than inferring a setting from a similar-looking key.
- A failed `javac` version probe reports an unknown JDK version instead of
  treating the detected executable as absent.
- .NET SDK detection checks for a nonempty SDK `dotnet.dll` and reports an
  incomplete layout as unknown when no valid SDK is found; this does not
  verify installation integrity.
- Overlapping cache inventories warn that their size estimates may overlap.
- Linux user-manager calls bound pipe reads even if a descendant holds the
  output open; a timed-out schedule change can still have an unknown outcome.
- macOS maintenance status also inspects direct mounted children of `/Volumes`;
  the inventory remains partial and has not been tested on native macOS.
- Rust reports an unavailable version probe as unknown and notes when no
  `rustc` executable is found on PATH.
- Offline tool checks do not run Go, Rust or Flutter version commands that
  can trigger toolchain downloads; affected installed versions may be unknown.
- Container engine queries limit concurrent output readers. If descendants
  keep output pipes open, further queries report an error until a slot is free.
- Held `j` and `k` navigation keys repeat where the terminal reports repeats;
  confirmation keys still require a fresh press.
- Artifact scan progress keeps the latest snapshot instead of queuing every
  update, so large scans do not delay completion behind progress messages.
- A newly opened confirmation discards early approval input after drawing as
  well as pending input before drawing; navigation and cancellation remain
  available, and delayed terminal input can still arrive afterward.
- Windows maintenance inventories fixed drive-letter volumes and available
  space without claiming TRIM support; dry-run skips the volume queries.
- Windows schedule inspection reports a task as absent only when task lookup
  itself reports that it is missing; other query failures remain unavailable.
- Shared-cache removal fails closed when recognized Maven or Java options and
  observed Maven configuration may redirect a local repository.
- The PowerShell installer preserves unrelated legacy backup files and uses a
  unique, non-overwriting backup when replacing an existing executable.
- macOS artifact scans report unavailable mount identities and cancelled mount
  checks as incomplete. Path-based mount checks can still race remounts.
- Linux shared-cache removal now fails closed on empty or relative recognized
  cache-directory settings and `XDG_CACHE_HOME`. npm cache and log settings are
  matched case-insensitively, and possible log locations are protected.
- npm inventory reads the user `.npmrc`, bounded ancestor project configs,
  explicit absolute user/global config paths, and their redirects to identify
  possible cache roots and protect logs. Unresolved, unreadable, or over-limit
  sources block removal. Since Upkit cannot reliably infer npm's default global
  prefix, shared-cache removal also requires an absolute `NPM_CONFIG_GLOBALCONFIG`.
  Config-only cache locations remain inspection-only; builtin config and CLI
  overrides remain uninspected.
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
