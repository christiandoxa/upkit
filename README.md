# upkit

![Coverage](https://github.com/christiandoxa/upkit/actions/workflows/coverage.yml/badge.svg)

Upkit is a standalone developer environment manager with a keyboard-first
terminal dashboard, toolchain management, workspace artifact discovery, and
selected maintenance operations.

The stable `v0.5.0` standalone release includes the developer-environment
manager and Ratatui dashboard. Known quality limitations are documented in
[CHANGELOG.md](CHANGELOG.md): measured line coverage is still **83.42%**
against the 90% target, and interactive macOS dashboard PTY smoke remains
unverified. Review every maintenance action before approving deletion.

## Features

- Check, install, update, and review removal of Go, Rust, Node, Python, Flutter,
  Mojo, Eclipse Temurin JDK, and .NET SDK toolchains, subject to the platform limits below.
- Browse detected project artifacts and shared caches, including Zig; review supported cleanup
  operations before confirming them.
- Zig remains supported for project artifact scanning, ecosystem configuration, and
  shared-cache discovery. Upkit no longer installs, updates, or removes Zig toolchains;
  existing installations are left in place.
- Inspect maintenance status, Trash, containers, schedules, and local history.
- Hybrid model: uses native installers when available and direct downloads when needed.
- JSON output for scripting and integrations.
- Offline and dry-run modes for safe previews.

## Install

### Linux and macOS

Install the standalone binary without Rust or Node.js:

```bash
curl -fsSL https://github.com/christiandoxa/upkit/releases/latest/download/install.sh | sh
```

The installer detects x86_64 or ARM64, verifies the download against
`SHA256SUMS`, and installs to `~/.local/bin`. If that directory is missing from
your `PATH`, add this line to your shell profile (`~/.bashrc` or `~/.zshrc`), then
open a new terminal:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

The installer replaces an existing regular `upkit` file, but refuses a
directory, symbolic link, or other non-regular destination. The destination
can still change between this check and the final move; use a trusted install
directory.

In Fish, run this once to add the directory for current and future sessions:

```fish
fish_add_path ~/.local/bin
```

To install a specific release or choose a different directory:

```bash
curl -fsSL https://github.com/christiandoxa/upkit/releases/latest/download/install.sh |
  sh -s -- --release v0.5.0 --install-dir "$HOME/.local/bin"
```

### Windows

Run in PowerShell:

```powershell
irm https://github.com/christiandoxa/upkit/releases/latest/download/install.ps1 | iex
```

The installer detects x64 or ARM64, verifies `SHA256SUMS`, and installs to
`%LOCALAPPDATA%\upkit\bin`. It adds that directory to your user `PATH`; open a new
terminal if an existing terminal does not find `upkit`. Administrator access is
not required for the standalone installer. Some toolchain operations create
symbolic links and can fail if the Windows account lacks permission to create
them; Windows toolchain installation support also varies by provider.

To choose a release or install directory, set these variables before running
the installer:

```powershell
$env:UPKIT_RELEASE = 'v0.4.15'
$env:UPKIT_INSTALL_DIR = "$env:LOCALAPPDATA\upkit\bin"
irm https://github.com/christiandoxa/upkit/releases/latest/download/install.ps1 | iex
```

Both standalone installers download `SHA256SUMS` from the same release base URL
as the binary. This detects a mismatch with that manifest, but does not
independently authenticate the release with a signature.

Standalone binaries for Linux, macOS, and Windows, each on x86_64 and ARM64, are
also available from [GitHub Releases](https://github.com/christiandoxa/upkit/releases).
Linux binaries target glibc-based distributions.

### GitHub Actions

```yaml
- uses: christiandoxa/upkit@v0.4.15
  with:
    version: latest

- run: upkit check --json
```

The action downloads the binary and checks it against `SHA256SUMS` from the
same release URL; this does not independently authenticate the release. It
then adds the CLI to `PATH`.

### Cargo

```bash
cargo install upkit --locked
```

### From source

```bash
git clone https://github.com/christiandoxa/upkit.git
cd upkit
cargo install --path .
```

New standalone releases are published to GitHub instead of npm. If you previously
installed with npm, remove the old package with
`npm uninstall -g @christiandoxa/upkit`, then run the standalone installer so the
old npm launcher does not take precedence on `PATH`.

## Usage

View local maintenance history with `upkit report`, `upkit sweep report`, or
`upkit --json report`. The dashboard has a Reports screen; press `/` there to
filter records by operation, target, outcome, or detail, and submit an empty
filter to show all records. Press `s` to switch between newest-first and
oldest-first order. Subtotals always cover all readable records.
Selected cleanup, schedule, TRIM, and container operations are recorded with
their target, time, duration, result and any verification outcome. Estimated
bytes are not reported as verified reclaimed space. Reports show a subtotal of
verified bytes from readable records and count records without a measurement;
some operations do not measure reclaimed space, and not every operation is
recorded.

History is stored under the Upkit data directory in up to 100 individual
records. When all slots are occupied, Upkit reports that later operations could
not be recorded. On Linux, reports skip records that are not private,
user-owned, single-link regular files on the history directory's device and
show a warning. macOS also rejects non-private and hard-linked records and opens
the final record without following links. Windows rejects reparse points and
hard-linked records and holds each record against concurrent writes or renames
while reading. On macOS and Windows, parent path replacement can still race a
read; Windows ownership and ACLs are not verified. Private read-only records
remain readable. History purge is implemented for Linux and macOS; the macOS
path has not received native runtime verification yet. Inspect an age-based
selection and its token before permanently removing old records:

```sh
upkit --non-interactive --json report purge --older-than 30d --preview
upkit --non-interactive --yes report purge --older-than 30d --run \
  --authorize-history-purge --preview-token TOKEN
```

Linux purge uses `openat2`; macOS uses no-follow descriptor-relative opens and
exclusive quarantine renames. Both require private, user-owned history,
revalidate the preview, and lock the directory during removal. macOS also
requires directory sync support: a sync failure during staging leaves a
recoverable staged record, while a failure after unlink can leave the outcome
unknown. The APIs compile for the Apple target, but this backend has not been
run on a Mac. Windows history purge is not supported; existing records remain
readable there.

On a TTY, `upkit report purge --older-than 30d --preview` opens a read-only Reports preview using the requested age.

In Reports, `7`, `3`, and `9` preview records older than 7, 30, and 90 days.
Review every listed record and warning before confirming; Esc cancels the
preview or requests cancellation during removal. Results appear per record.

The token binds the selected records and their identities; changes require a
new preview. Records without a finish timestamp are skipped. Linked, invalid,
or unexpected history entries stop the operation. A purge records a summary
after execution when there is room; a history-write failure is reported.
`--dry-run` performs no deletion or history write. A valid record left staged
by an interrupted purge is shown with a warning and can be reviewed again for
removal. Invalid files or conflicting slots are preserved and can require
manual recovery. Same-user changes and older writers that do not use the lock
can still race. On Unix the history directory must not be accessible to group
or other users. Reporting does not send data over the network.

Inspect Docker and Podman storage summaries without pruning resources:

```bash
upkit containers status
upkit --json containers status
```

The command reports each engine separately, including unavailable or failed
queries, and lists containers, images, volumes, and networks. It also asks each
engine for dangling images, unattached volumes, and networks without attached
containers (Docker reports custom networks only); these are snapshots and do
not authorize removal.
With `--dry-run`, Upkit skips both engine executables entirely and marks each
engine as skipped. Podman may initialize local runtime state on first use. An
executable found on `PATH` can also be a wrapper with side effects. Dry-run
container or network previews and removal commands also skip engine inspection
and report that no plan was generated or verified.
Container listings request the engine's per-container size when available.
Docker engines that reject the network filter report a per-list error. Storage and reclaimable figures are engine estimates, not guaranteed
reclaimed space. Offline mode skips these queries because an engine may use a
remote endpoint. In an interactive terminal the command opens the container
storage screen; Enter or `r` refreshes it. Resource lists can be incomplete when
an engine rejects a query; errors are shown per list. `/` filters the selectable
stopped containers, unused networks, and eligible Buildx cache entries.
Dangling image and unattached volume snapshots remain visible as read-only
references and are not selectable for removal. Full engine details remain
visible as a non-selectable reference.

Docker also lists `unused images (snapshot)` by combining
[`docker image ls --all --no-trunc --format json`](https://docs.docker.com/reference/cli/docker/image/ls/)
with [`docker system df --verbose`](https://docs.docker.com/reference/cli/docker/system/df/).
Multiple tags for one image ID are combined, and only images reported with zero
containers are listed. These separate inventory queries can observe different
engine states; images and container attachments can change during or after the
snapshot. This list is reference-only and does not authorize removal. If either
inventory is incomplete, an ID is ambiguous, or the detailed image section is
missing or truncated, Upkit reports an error without classifying images. The
verbose output also contains container details; Upkit parses its image section
and does not emit container commands or labels from that output.

Podman also lists `unused images (snapshot)`. It combines
[`podman image ls --all --no-trunc --format json`](https://docs.podman.io/en/stable/markdown/podman-images.1.html)
with a second query,
`podman image ls --all --no-trunc --format '{{.Id}} {{.Containers}}'`, using
Podman's documented full-ID and container-count template fields. Only images
reported with zero containers appear. These inventory queries are separate
snapshots and may see different image or container state; the result is
reference-only and does not authorize removal. Missing IDs, counts, or images
produce an error instead of a partial classification. The custom query emits
only IDs and counts, not container commands or image labels. Older Podman
versions that do not support these template fields report the inventory as
unavailable.

Docker inventory also requests individual build-cache records from the selected
[Buildx builder](https://docs.docker.com/reference/cli/docker/buildx/du/). It omits build descriptions and parent IDs, limits output to
1 MiB, and reports query errors separately. Buildx may connect to a remote
builder and execute `buildctl` inside a running builder container. Its reported
reclaimable and shared values are snapshots, not guaranteed reclaimed space or
permission to remove anything. Detailed Podman build-cache inventory is not yet supported. Buildx may create
or update local configuration files and directories, which is another reason
`--dry-run` skips all Docker and Podman inventory queries.

In the Containers screen, select a listed private, immutable and reclaimable
Buildx cache and press `d` to review removal. Confirm with `y` only after the
entire plan is visible. Direct interactive `preview-build-cache` opens a
read-only preview; `remove-build-cache` opens the confirmation. For the
non-interactive CLI, supply a builder name and its complete 25-character cache
ID from that builder's inventory:

```sh
upkit --non-interactive --json containers preview-build-cache --builder BUILDER --id CACHE_ID
upkit --non-interactive --yes containers remove-build-cache --builder BUILDER --id CACHE_ID \
  --preview-token TOKEN_FROM_PREVIEW --authorize-build-cache-removal
```

The builder must have one identifiable running node and the cache must be
reclaimable, private, immutable, and of a supported type. The token binds the
builder, Docker server and observed cache state; changes require a new preview.
Removal may destroy build data, remove linked internal metadata, and trigger
BuildKit garbage collection; rebuilding or redownloading may be required. The
builder endpoint and cache can change after revalidation, a failed or timed-out
command can have a partial outcome, and reclaimed space is not measured. The
[Buildx JSON example](https://docs.docker.com/reference/cli/docker/buildx/du/)
shows `Size` as decimal digits; Upkit records nonnegative integer
values and digit-only strings as byte estimates when they fit in `u64`.
Human-readable values such as `1.2GB`, negative values, decimals, and overflow
remain unknown.
The estimate is not verified reclaimed space, especially when storage is shared. The
removal workflow has not yet been validated against a real Buildx engine.

A single exited container can be removed using its full 64-character ID
(obtainable with the engine's `container ls --all --no-trunc` command):

```bash
upkit --json containers preview-remove --engine docker --id FULL_CONTAINER_ID
upkit --non-interactive --yes containers remove --engine docker --id FULL_CONTAINER_ID \
  --preview-token TOKEN_FROM_PREVIEW --authorize-container-removal
```

Use `podman` for the engine when appropriate. The preview identifies the server
or storage, stopped container, and writable-layer size when available. Removal
permanently destroys the container's writable layer, configuration, and logs.
Upkit rechecks identity and state, uses neither force nor a volume-removal flag,
and checks whether the engine still lists the ID afterward. If verification
fails or the operation times out, inspect the engine before retrying. A container
or engine endpoint can still change between the last check and execution. In the
dashboard's Containers screen, select an exited container and press `d` to view
the plan; `y` confirms removal. Interactive `preview-remove` and `remove`
commands also open that plan.

Dangling image snapshots remain visible in the Containers screen and in
`containers status`, but image selection, preview and removal are disabled.
The `preview-image` and `remove-image` commands report that image operations are
unsupported without contacting Docker or Podman. Neither engine provides a
conditional delete tied to the reviewed image ID and tag set; a tag created
after inspection can otherwise be removed by an ID-based delete. The same race
applies to an image that was dangling when inspected. Use the read-only inventory
to inspect images and review current tags and users before removing them with
the engine directly.

The Containers screen also supports preview and removal of one unused bridge
network. For automation, use its full 64-character ID:

```bash
upkit --json containers preview-network --engine docker --id FULL_NETWORK_ID
upkit --non-interactive --yes containers remove-network --engine docker --id FULL_NETWORK_ID \
  --preview-token TOKEN_FROM_PREVIEW --authorize-network-removal
```

Upkit checks the engine's unused-network list, rejects the standard default
names and non-bridge networks, and checks the selected network again before
removal without force. Docker also requires a custom, local network with no
attached containers. Podman's unused filter is used; a custom configured
default network is not independently identified by Upkit.
Removal deletes network configuration that services may need later. Network
attachments and engine endpoints can change after the last check. Volume and
image removal are unsupported; image inventory remains read-only.

Check installed versions and status:

```bash
upkit check
```

Upkit does not create its directories or edit shell configuration when checking
versions; the tool executables it invokes may have their own side effects.
Use `upkit --help` for the current command and flag list.

In an interactive terminal, `upkit` opens the Ratatui dashboard. `upkit tui`
opens it explicitly; `upkit check`, `upkit update`, and `upkit doctor` open their
corresponding screens. Use Tab or Shift+Tab to switch screens, arrow keys or
`j`/`k` to navigate, Space to mark toolchains, Enter to review an update, and
`q` to quit. Press `?` for contextual keyboard help. Updates require confirmation. Non-terminal output retains the CLI
behavior; `--non-interactive` explicitly disables the dashboard and prompts.
When a confirmation first opens, Upkit discards pending input before drawing the
plan and discards early confirmation input after drawing; navigation and
cancellation remain available. Review the displayed details and then press the confirmation key.
Terminal input has no timestamp, so delayed input can still arrive later.
The dashboard summarizes toolchain status, available maintenance information,
loaded artifact and cache inventories, Doctor results, and recent local
operations. It does not scan workspaces automatically; `r` refreshes history
and `c` opens the cache screen and starts an inventory.

Automatic pruning of older managed tool directories is currently suspended
because their ownership cannot yet be verified. Archive installs use unique
staging directories and retain existing versions. An activation failure may
leave a staged directory that requires review. Toolchain archive downloads are
limited to 8 GiB even when the server does not advertise a size; a larger release
cannot be installed until that limit is revisited. Release metadata and other
HTTP text responses are limited to 32 MiB; larger responses fail the check.
Node archive installs fetch `SHASUMS256.txt` from nodejs.org for the selected
version and compare its SHA-256 entry before extraction. They limit extraction
to 100,000 entries and 3 GiB, and check the expected archive root and required
executable files or links before activation. The archive and manifest come from
the same host, so this is not independent signature verification.
Windows Node.js x64 and ARM64 installs use the official ZIP layout so that
`node.exe`, `npm.cmd`, `npx.cmd`, and npm's files remain together. Add the
`node\active` directory under the Upkit home shown by `upkit --dry-run paths`
to your user PATH, ahead of other Node installations, then open a new terminal;
the Node installer does not modify the Windows PATH.
Creating the active link requires Windows symbolic-link permission. Upkit leaves
the existing npm global prefix and packages unchanged; npm's global executable
directory may also need to be on PATH. Native Windows installation and updating
have not yet been verified.
Go archive updates verify the published SHA-256, limit extraction to 100,000
entries and 3 GiB, and check the root, selected version, Go binaries, compiler,
linker, and runtime source before activation. The checksum is not independent
signature verification. These checks do not establish complete installation
integrity or validate executable format. Go updates create wrapper scripts without overwriting existing files. On Unix,
the Go root and wrapper directory must not be writable by group or others;
existing wrappers must be singly linked, executable, and not group/other writable.
Linux also requires current-user ownership. Existing wrappers must match the
current generated scripts, so older or customized wrappers may require manual
review before updating. On Windows, Go ZIP installs link `go.exe` and
`gofmt.exe` directly instead of creating shell wrappers; creating these links
requires symlink permission. [Go discovers its SDK from the executable](https://go.dev/src/cmd/go/internal/cfg/cfg.go),
but an existing `GOROOT` setting can override that discovery. Native Windows behavior
has not yet been verified. Filesystem paths can still change concurrently during
these checks.
New Flutter archive installs require the SHA-256 supplied by Flutter's release
metadata and fail before extraction if it is missing or does not match. Linux
TAR and macOS/Windows ZIP installs limit extraction to 100,000 entries and 8 GiB and
validate required SDK components, release version, and symlink targets before
activation. These checks do not prove complete SDK integrity or executable format,
and the checksum is not independent signature verification. macOS ZIP
entry names are limited to 64 MiB and must satisfy Windows-compatible name rules;
link targets are limited to 16 KiB each and 8 MiB total. Unsafe or duplicate paths
and dangling or escaping links are rejected. Flutter selection requires matching architecture metadata for the
latest stable release; an unavailable architecture is reported instead of
choosing an older archive. On Windows, add `flutter\active\bin` under the Upkit
home to your user PATH ahead of other Flutter installations. Flutter also needs
Git and PowerShell on PATH, and creating the active link requires symbolic-link
permission. Windows managed updates install a new archive and retain the prior
version; Upkit does not modify the Windows PATH. As of 2026-11-01, Flutter's
latest stable metadata did not offer a Windows ARM64 archive. Windows and macOS
installation and update behavior have not been tested natively. Python archive installs
prefer the standard `install_only` gzip distribution and require the SHA-256
digest supplied by GitHub's release API. Free-threaded builds are not selected.
Extraction
rejects unsafe paths, links, and special files, including dangling or cyclic
symlinks, and is limited to 100,000 entries and 3 GiB. The HTML fallback can check versions but cannot install when the API
digest is unavailable. A checksum from the same release is not an independent
signature verification. Windows Python installs use the official x64 or ARM64
archive (`aarch64` builds start at CPython 3.11), and expose `python.exe` through
Upkit's binary directory. The archive has no `pip.exe` or `python3.exe` launcher;
use `python -m pip`. Creating the active and binary links requires Windows
symbolic-link permission. Native Windows installation and execution remain
unverified.

The `install` alias runs the update command. Set `UPKIT_NO_PATH_UPDATE=1` to
prevent Upkit from editing shell PATH configuration during toolchain updates.
On Linux, Upkit refuses to replace a shell configuration when its metadata
cannot be preserved, including linked files and files with extended attributes;
it also refuses a linked or shared-writable configuration directory. Add the
PATH entry manually in these cases. Concurrent changes can still race the final
replacement. Automatic profile writes on other platforms are not covered by
this Linux safeguard.
To inspect generated project files
without deleting anything, provide one or more workspace roots:

```bash
upkit sweep scan ~/projects
upkit --json sweep scan ~/projects ~/work
upkit --json sweep scan ~/projects --exclude vendor --exclude project/target/private
upkit --json sweep scan ~/projects --older-than 30d
```

Scan and preview JSON use tagged objects for non-Unicode paths, as described
under cache management below.

The scanner recognizes selected manifest-backed Cargo, Go, Zig, Maven, Gradle,
sbt, CMake, Meson, Ninja, .NET, Flutter/Dart, Python, and JavaScript artifacts. It skips
symlinks and filesystem boundaries, and on Linux skips nested mount points.
On Windows it also skips reparse points and will not descend into directories
whose volume cannot be verified or differs from the scan root. Path replacement
can still race these checks. Windows CI is configured to exercise reparse-point
and volume-boundary fixtures, but has not yet run on a Windows host.
A directory with its own recognized project manifest is treated as a project
even when its name matches a parent project's artifact directory. During size
measurement, recognized nested project and version-control markers and the
first symbolic link are also reported. Symbolic links are never followed. Markers may be generated files; absence of a marker does
not prove that a directory contains no source, especially when measurement is
incomplete or the tree changes after scanning. Preview flags changed or
unavailable identity and incomplete inventories as unsuitable for removal.
Logical sizes count regular-file bytes; on Unix, allocated-size estimates count
blocks for distinct regular files. On Unix and Windows, the first observed
multiply linked file is reported because other links may keep its blocks
allocated. Detection is a scan-time observation, and a failed Windows link-count
query marks the estimate incomplete. Estimates
can be incomplete when access fails and
are not guaranteed reclaimed space. `--older-than` accepts hours (`h`), days
(`d`), or weeks (`w`) and uses the newest measured modification in the entire
artifact tree. Artifacts with incomplete or unknown ages are omitted and
reported as warnings. Age does not establish that a build is inactive. At a Go
project root, `build/` and `bin/` are listed as review-only possibilities; their
contents may be source or user data, so Upkit cannot remove them. Other custom Go
output locations remain undiscovered; the shared Go build cache appears in
`cache status`. CMake and
Meson build directories with generated metadata can be discovered under nested
paths or custom names; their contents still require review. For standalone Ninja
projects, a root `build.ninja` and a direct `build/.ninja_log` identify a possible
build directory for inspection only. Upkit does not remove it, and custom build
directories are not discovered. Ninja's [build log documentation](https://ninja-build.org/manual.html#_the_ninja_log)
explains that its location can be configured. A Gradle project's
root `.gradle` directory is also listed for review; its name and manifest do not
prove that every entry can be regenerated. sbt projects with `build.sbt` expose
their root `target/` directory as review-only; custom and subproject target
directories are not discovered. See the [sbt directory reference](https://www.scala-sbt.org/1.x/docs/Directories.html).
For Cargo, a single project-local `.cargo/config.toml` or `.cargo/config` may
identify a relative custom target directory within the project. Upkit inventories
that directory for review only and will not remove it. Ambiguous or unsupported
local configuration also makes the default `target/` review-only. An ancestor
or Cargo home config, a known output-directory environment override, or an
uncheckable configuration also prevents Cargo removal; these checks are repeated
during removal. Cargo command-line overrides from other processes cannot be
determined, so the inventory may not reflect the target Cargo currently uses.
Cargo cleanup requires a workspace root confirmed within the selected scan
scope; workspace members, excluded packages, and standalone packages without a
confirmed workspace root remain review-only. Local configuration identity is
rechecked during removal, but configuration sources can still change between checks.
Exclusions are paths relative to each root or
absolute paths. Prefix a root-relative pattern with `glob:`, for example
`--exclude 'glob:**/vendor'`; `*` does not cross directory separators and `**`
can match multiple directories. Literal exclusions retain their existing meaning.
When an exclusion is inside a
candidate, its size is marked incomplete. Scans use up to four workers. In an
interactive terminal, the scan opens the artifact screen in the background;
press Esc to request cancellation. Directory enumeration checks the request
between entries, but a filesystem call already in progress cannot be interrupted.
From the dashboard, `s` scans configured
roots; on the artifact screen, `r` rescans its current scope using the latest
configuration. Python projects can include `.hypothesis` as a review
candidate: deleting it removes saved failure examples used to reproduce tests.
The preview and removal confirmation disclose that consequence. The default
pytype `.pytype` output directory is also review-only because it can contain
generated `.pyi` stubs that users may want to inspect or merge into source.
Ruff's `.ruff_cache` is also review-only: the scanner cannot verify that every
entry is disposable, and custom Ruff cache locations are not discovered.
Project-root `.tox` and `.nox` work directories are review-only because they
can contain virtual environments, build logs, packages, and other project
state that may include user data. Custom work directories are not discovered;
see [tox's work directory](https://tox.wiki/en/stable/reference/config.html#work-dir)
and [Nox's environment directory](https://nox.thea.codes/en/stable/config.html#nox.options.envdir).
Project-root Python `build/` and `dist/` packaging outputs are review-only because
they can contain source files or release artifacts; custom output locations are
not inferred. The `build` frontend defaults distributions to `dist/` ([output directory documentation](https://build.pypa.io/en/latest/how-to/basic-usage.html#specifying-the-output-directory)).
Root `*.egg-info` package metadata directories are also review-only because
project workflows may depend on their contents; custom and nested metadata paths
are not discovered ([setuptools packaging guidance](https://setuptools.pypa.io/en/latest/userguide/miscellaneous.html)).
For JavaScript projects, the default Parcel `.parcel-cache` directory is also
review-only: its name and `package.json` do not prove that its contents are
generated. Custom Parcel cache paths are not discovered automatically. See
[Parcel's cache documentation](https://parceljs.org/features/development/#caching).
Project-root `coverage/` directories with known coverage report filenames are
also shown for review. Such a filename does not prove every file in the
directory is disposable; custom coverage locations are not discovered. See
[Jest coverage configuration](https://jestjs.io/docs/configuration#coveragedirectory-string).
The same review applies to `.next` and `.nuxt`: names alone do not prove the
contents are generated, and custom [Next.js](https://nextjs.org/docs/pages/api-reference/config/next-config-js/distDir)
or [Nuxt](https://nuxt.com/docs/2.x/api/configuration/configuration-builddir)
output paths are not discovered.
The default Vite `node_modules/.vite` directory is likewise review-only;
its contents are not verified as generated, and custom `cacheDir` paths are
not discovered. See [Vite's cacheDir documentation](https://vite.dev/config/shared-options#cachedir).
Angular CLI's default `.angular/cache` is a review candidate in a project with
`package.json` and a bounded, readable `angular.json` identifying a workspace.
Its contents are not verified as disposable, and custom cache paths are not
discovered. See [Angular's cache configuration](https://angular.dev/cli/cache).
SvelteKit's `.svelte-kit` output is also review-only and cannot be removed by
Upkit. Discovery requires a direct `@sveltejs/kit` package manifest; manifests
over 1 MiB are skipped. The [SvelteKit configuration](https://svelte.dev/docs/kit/@sveltejs-kit-vite)
documents `.svelte-kit` as the default configurable `outDir`. Linux kernels
without `openat2` skip this discovery. The Windows reader checks reparse points
and volume boundaries, but concurrent path replacement can still race its checks;
native Windows behavior has not yet been verified.
In projects with `build.zig`, Upkit recognizes `.zig-cache` and marks `zig-out`
for review because installed output can include user data. Neither directory is
removed without an explicit selection and confirmation.
`sweep scan` is read-only. Linux also offers explicitly reviewed removal of
eligible artifact directories and selected CPython bytecode files. Existing
`upkit clean` continues to remove managed toolchain installations, not project
artifacts.

On Linux, Cargo candidates also show bounded manifest evidence about an enclosing
workspace within the selected scan roots, including explicit member and exclude
pattern matches. This does not resolve path-dependency members, explicit workspace
overrides, Cargo configuration, or custom target directories. A match is not
confirmation that Cargo currently uses the displayed target; a workspace outside
the selected roots is not inspected. Workspace evidence never authorizes cleanup.
See the [Cargo workspace reference](https://doc.rust-lang.org/cargo/reference/workspaces.html)
for Cargo's membership and output-directory rules.

Inspect recognized shared developer caches:

```bash
upkit cache status
upkit --json cache status
```

On the Cache screen, `s` cycles sorting by name, logical size, and observed
risk or uncertainty. Unknown sizes sort last; size snapshots are not verified
reclaimed space. Filtering and sorting retain the selected cache when possible.

The inventory identifies shared dependencies separately from build caches and
explains the likely cost of removal. On Linux it estimates logical and allocated
file sizes. On macOS it estimates logical and allocated sizes using no-follow
traversal and device-ID checks, but does not enumerate mounts; same-device
mounted subtrees may be included, so these estimates are marked incomplete. On
Windows it estimates logical sizes while skipping reparse points and directories
whose volume cannot be verified; skipped entries make estimates incomplete.
Concurrent path replacement remains a race. Windows traversal fixtures are
configured in CI but have not yet run on a Windows host. Linux also reports a
snapshot of the cache directory's owner; this does not verify ownership of its
contents. It does not invoke package managers or delete files. Custom
package-manager configuration and some caches may not appear; inferred locations
may differ from the paths tools actually use. Upkit reads the Go user persistent
environment file (including `GOENV` overrides) without invoking Go. Nonempty
process environment values take precedence, as in the [Go command
environment](https://pkg.go.dev/cmd/go#hdr-Environment_variables). A present
empty value in the user file is preserved and suppresses a system setting.
Linked, special, over-256-KiB, or files whose inspected metadata changes are
skipped with a warning; macOS also rejects files with multiple hard links.
Windows reads `%APPDATA%\go\env` or an absolute `GOENV` override without
following reparse points, rejects files with multiple hard links, and rechecks
file identity after reading. Its Windows identity uses a 64-bit file index;
Microsoft documents that this index is not guaranteed unique on ReFS, so path
replacement detection can collide on ReFS. See
[BY_HANDLE_FILE_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information).

Upkit cannot safely determine the effective Go installation root without
invoking Go: `GOTOOLCHAIN` may select a toolchain whose root differs from the
Go executable found on `PATH`. It therefore does not read that toolchain's
`GOROOT/go.env`. Only nonempty process values and values present in the user
file are known. Missing keys remain unknown, including when `GOENV=off` disables
the user file; paths that depend on unknown settings are omitted, and inventory
warns when the Go cache scope is incomplete. An explicit empty user value may
use the normal platform default when it does not depend on the active GOROOT.
Go's default GOPATH is normally `$HOME/go` or `%USERPROFILE%\go`, but Go leaves
it unset when that path equals GOROOT. Since the effective GOROOT is unknown,
Upkit does not infer GOPATH or a GOPATH-based module cache from an empty value.
To inventory modules, provide an absolute `GOMODCACHE`, or a present empty
`GOMODCACHE` setting together with an explicit nonempty `GOPATH`.
Go's default build-cache directory follows
[`os.UserCacheDir`](https://pkg.go.dev/os#UserCacheDir) and is independent of
GOROOT. `GOCACHEPROG` can provide an external build-cache provider; Upkit reports
but never runs it. Linux shared-cache removal is blocked when Go cache locations
or `GOCACHEPROG` status are unknown, because an unknown Go cache may overlap the
selected directory; a configured external cache program also blocks removal.
Use `go env` to inspect the active toolchain's effective settings. See Go's
[GOPATH default](https://go.dev/src/go/build/build.go) and
[build-cache initialization](https://go.dev/src/cmd/go/internal/cache/default.go).
Readers inspect path components without following links, but directories can
still change between checks. Linux and macOS size estimates may be incomplete
and do not guarantee reclaimed space.

Empty or relative values for recognized cache-directory environment overrides
and `XDG_CACHE_HOME` are reported as unresolved and block Linux shared-cache
removal. On Linux, Cargo output paths configured by environment variables or by
the current directory's ancestor Cargo configuration and `CARGO_HOME` are
inventoried without granting removal permission. An overlap blocks shared-cache
removal; unreadable, ambiguous, included, or templated configuration can also
block it. Cargo command-line overrides and configuration outside that search
are not visible to Upkit, so other output paths may be missed.

npm environment paths containing unsupported variable expansion are also
unresolved. npm cache and log-directory keys are matched without regard to case;
conflicting absolute cache values are inventoried as possible locations but cannot
be removed until the conflict is resolved. Upkit reads the user `.npmrc`, bounded
ancestor project `.npmrc` files, absolute `npm_config_userconfig` and
`npm_config_globalconfig` paths, and their user/global redirects with a bounded
parser. It accepts absolute paths, `~/`, and `${HOME}` when the home value is
known; unresolved paths, unsupported syntax, unreadable files, or exceeded limits
block shared-cache removal. Cache paths found only in npm configuration are
inspection-only, and npm log directories are protected. When `NPM_CONFIG_PREFIX`,
`PREFIX`, or a readable `.npmrc` sets an absolute prefix, Upkit also reads
`$PREFIX/etc/npmrc` as a possible global config path, following npm's documented
default ([npm v6](https://docs.npmjs.com/cli/v6/configuring-npm/npmrc/),
[current npm](https://docs.npmjs.com/cli/using-npm/config/)). That candidate does
not verify the effective global config: npm loads builtin config before env
settings, so a builtin `globalconfig` can replace the default, and CLI options are
not visible to Upkit. See [npm's config loader](https://github.com/npm/cli/blob/latest/workspaces/config/lib/index.js).
Shared-cache removal still requires
`NPM_CONFIG_GLOBALCONFIG` to name an absolute path. Conflicting prefix environment
aliases, relative or unresolved prefixes, and symlinked candidate paths block
removal. Warnings do not print configured values. Unset environment variables
continue to use their defaults.

Maven discovery reads only the user-level `~/.m2/settings.xml`, capped at
256 KiB, and uses its direct `<localRepository>` value when it is an absolute
path or uses `${user.home}`. Missing settings use Maven's default repository.
Malformed, linked, oversized, relative, duplicate, DTD-based, or otherwise
ambiguous settings leave the location unverified: Maven is omitted from the
inventory and Linux shared-cache removal is blocked until the settings can be
resolved. Diagnostics never print settings contents or credentials. Linux
shared-cache removal also stops when recognized Maven or Java environment
options, observed project/user configuration, or installation configuration
may redirect the repository. This conservative check can block removal even
when a detected configuration does not actually change the repository. Maven
installation paths not exposed in the environment, other projects and command
lines of other processes remain uninspected. Concurrent configuration changes
can still race these checks.

The pnpm inventory uses `PNPM_CONFIG_STORE_DIR`, `PNPM_HOME`, `XDG_DATA_HOME`,
or platform defaults in that order. It does not read pnpm configuration files or
discover every per-filesystem store. A relative effective location blocks shared
cache removal because overlap cannot be ruled out; pnpm removal itself also
requires an explicit absolute `PNPM_CONFIG_STORE_DIR`. The configured path is
still inferred and its contents must be reviewed.

The uv package cache is inventory-only. Discovery uses an absolute `UV_CACHE_DIR`
override or, when it is unset, the documented platform default. A relative
override is skipped with a warning; uv configuration files and command-line
overrides are not inspected. Upkit does not remove this cache:
uv advises against modifying it directly and provides its own cache commands.
See [uv's cache documentation](https://docs.astral.sh/uv/concepts/cache/).

The Bun package cache is inventory-only. Upkit checks the documented default or
an absolute or `~/`-prefixed `BUN_INSTALL_CACHE_DIR`, tracks a `BUN_INSTALL`
cache-command target, and protects cache paths from the global `.bunfig.toml`,
`bunfig.toml` files in the current directory's ancestor chain, and `.npmrc`
cache settings, including the XDG user config location. It unions observed paths
without inferring which setting wins;
unreadable, linked, malformed, ambiguous, or unresolved config blocks Linux
shared-cache removal. Bun's per-command `--cache-dir` and `--config` options,
and cache paths supplied through `.env`, may still point elsewhere. Bun can
hard-link packages into projects, so cache sizes do not guarantee reclaimed
space. See Bun's [global cache](https://bun.com/docs/pm/global-cache),
[configuration](https://bun.com/docs/runtime/bunfig), [.npmrc support](https://bun.com/docs/pm/npmrc), and
[cache commands](https://bun.com/docs/pm/cli/pm) documentation.

NuGet package folders and local feeds are inventory-only. Upkit includes the
platform default and known paths from environment variables, supported MSBuild
environment properties, user configuration, NuGetDefaults.Config, and
NuGet.Config files in the current directory's ancestor chain. It protects the
union of known locations, including defaults alongside `DOTNET_CLI_HOME` and
XDG overrides, because other processes may use different settings.
Ambiguous, unsafe, unreadable, or unsupported configuration blocks Linux
shared-cache removal. Other projects' configuration files, project-file MSBuild
properties, and command-line `--source`/`-Source` overrides are not inspected and
can still select different locations. See Microsoft's
[global packages folder documentation](https://learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders).

Zig's global cache is inventoried as a shared build cache. `ZIG_GLOBAL_CACHE_DIR`
takes precedence; otherwise, on non-Windows systems Upkit follows Zig's
`XDG_CACHE_HOME/zig` and `$HOME/.cache/zig` defaults. If neither is available,
Linux can use `XDG_DATA_HOME/zig`; Windows uses `LOCALAPPDATA\zig`. On macOS,
the location is unavailable if neither earlier default resolves. A relative or
unresolved location is skipped with a warning and blocks Linux shared-cache
removal until it can be resolved. The cache can contain build artifacts and
downloaded package dependencies, so removal may require recompilation and
downloads. Per-command `--global-cache-dir` overrides are not visible to Upkit
and can point Zig at a different location. See Zig's [global-cache resolver](https://github.com/ziglang/zig/blob/master/src/introspect.zig#L92-L110)
and [platform app-data defaults](https://github.com/ziglang/zig/blob/master/lib/std/fs/get_app_data_dir.zig#L14-L41).

On the Cache screen, `/` filters names and escaped paths; Enter applies the
filter and Esc cancels editing. On Linux, press `d` to select a visible shared
cache for permanent removal. Review every listed entry, then confirm the exact
path and consequences. For automation, inspect the full plan and use its token:

```sh
upkit --non-interactive --json sweep run --scope cache --select /absolute/cache/path --preview
upkit --non-interactive --yes sweep run --scope cache --select /absolute/cache/path --authorize-shared-cache --preview-token TOKEN
```

This removes the selected directory and all listed contents, which can include
user data or dependency source files. Packages may need downloading or
recompilation. Locations are inferred; any other caches inside the selected
directory are also removed. External cache programs are not run and their
contents may remain. Upkit rejects a project manifest at the cache root, even if
it belongs to an unusual cache layout. Nested dependency manifests are allowed;
Upkit cannot distinguish dependency source from personal source inside the cache.
It also rejects overlapping discovered cache locations, links, hard links, nested VCS markers, child mounts, incomplete inspections,
unsafe ownership or permissions, and observed or uninspectable same-user process
activity. It rechecks identity and contents, then stages the directory in a
private sibling quarantine before deletion. Interrupted or partial removal can
leave data there; same-user races and hidden processes remain possible. Review
is limited to 10,000 entries and 128 directory levels. The final confirmation
must fit on screen. Cache removal requires Linux `openat2` and is not yet
supported on other platforms.
Workspace roots, exclusions, age filters, and profiles do not apply to this
operation; the CLI rejects them instead of silently ignoring them.
Artifact listings, removal reviews, and other messages that use Upkit’s path
formatter show Unix paths with reversible `%XX` byte escapes for `%`, control
bytes, and non-ASCII bytes so distinct paths remain distinguishable. On Windows,
that formatter uses `%uXXXX` escapes for UTF-16 code units outside printable
ASCII and for `%`. Pass the original filesystem path to `--select`, not the
escaped text.

In `sweep scan` and `sweep preview` JSON, Unicode paths remain strings as before.
The `sweep scan` JSON field `complete` is false if scanning was cancelled,
warnings occurred, or any candidate size estimate is incomplete. Even a complete
scan is a snapshot and does not guarantee that every possible artifact was found.
A non-Unicode path is instead an object, for example
`{"encoding":"unix-percent-bytes","value":"/work/project-%FF/target"}`.
For `unix-percent-bytes`, decode each `%XX` to one byte; unescaped characters
are printable ASCII. On Windows, `windows-percent-utf16` uses `%uXXXX` for one
UTF-16 code unit and unescaped printable ASCII for the rest. This applies to
scan and preview roots, candidate paths, marker paths, and Cargo workspace
evidence. Linux artifact and CPython bytecode removal plans, scope paths,
bytecode batch results, cache inventory and Go test-cache preview paths, and
Trash location paths use the same representation; `paths --json` uses it for
home, binary directory, and path-check entries as well. Preview tokens retain
the original path bytes. Bytecode filenames must still use a supported CPython
name. These objects are for reporting; `--select` and other path arguments still
require the original OS path. Non-Unicode paths are not automatically written
to shell configuration; add them manually. Other commands do not yet consistently
support non-Unicode paths.

On Linux, cache inventory and artifact previews also report a bounded snapshot
of same-user process working directories, executables, and open handles under each target.
Other users, hidden processes, different namespaces and activity after the
snapshot may be missed; no observation does not establish that a build or
cache is idle. Inspection errors and limits are reported as incomplete, and
other platforms report the check as unavailable. No process IDs or command
lines are included in the report. For compatibility, the status
`no_open_handles_or_cwd_observed` also means no executable was observed.

For an inferred Go build cache on Linux, inventory also reads the test-cache
expiration marker when available. This is a snapshot, not proof that Go uses
that path. Expiring test results makes tests run again; it does not itself
reclaim the space occupied by those results.
On Linux, the Cache screen offers `e` to preview expiration for the inferred
Go build cache, followed by an explicit `y` confirmation. The exact path is
shown before confirmation. An interactive `cache go-test --path PATH --preview`
opens a read-only preview for that path. The non-interactive equivalent requires a preview
and its token:

```bash
upkit --non-interactive cache go-test --path /absolute/canonical/cache --preview
upkit --non-interactive --yes cache go-test --path /absolute/canonical/cache --run --authorize-shared-cache --preview-token TOKEN
```

The operation requires Linux `openat2` and rejects insecure or linked cache
directories and markers, including group-writable directories. It may therefore
be unavailable for an existing cache; Upkit does not change permissions to make
it eligible. Concurrent changes can make verification fail or leave the result
unknown; inspect the marker before retrying.

`upkit sweep preview` performs a fresh scan and shows an inspection-only removal
plan. In the terminal interface, use `/` to filter by ecosystem or path, `s`
to cycle through path, size, and age sorting, Space to select a visible candidate,
and Enter to inspect its details. Incomplete sizes and unknown ages sort last. The preview
shows the total selected and how many selections are hidden by the filter. An
interactive CLI preview is read-only; use the dashboard or a reviewed `sweep run`
workflow to perform cleanup. For JSON, select exact discovered paths explicitly:

```bash
upkit --json sweep preview ~/projects --select ~/projects/example/target
```

No candidates are selected by default. On Unix, the preview compares filesystem
metadata for the project, one identifying manifest, and target against the
scan snapshot. A metadata match is not a content check or proof of safety;
identity comparison is currently unavailable on Windows. The preview does not
remove anything. When Git 2.36 or newer (within the 2.x series) is available
outside the selected roots, the preview checks its index and current HEAD with
optional locks, fsmonitor, hooks, and Git transports disabled. Git 2.45+ also
uses `--no-lazy-fetch`; Git 2.36–2.44 requires a repository without partial-clone
configuration. Missing objects and unavailable HEADs are reported as unavailable.
For targets selected when the preview starts, it also searches
history reachable from Git refs; shallow repositories, repositories with a
graft file, failed queries, and
unsupported Git versions report that check as unavailable. A selection made
later in the terminal interface does not trigger this history check. These checks
do not cover nested repositories, untracked files, unreachable history, or other
version-control systems, and a no-match result is not proof that deletion is safe.
For CLI Git-backed previews, `--dry-run` validates the scan scope and selected
paths without invoking Git, then reports `skipped_unverified` without a plan or
preview token. Use the normal preview command to collect Git evidence; ordinary
`sweep scan` remains a scan-only inventory.
On Linux, the selected Git executable must be a protected ELF file; shebang
wrappers are treated as unavailable. Relative `PATH` entries require a private
current working directory, while absolute paths require trusted ownership along
their full path. Git and its path components must be on an allowlisted local
filesystem (`ext2`, `ext3`, `ext4`, `xfs`, `btrfs`, `f2fs`, or `tmpfs`); overlay,
FUSE, network, unknown, and idmapped mounts are rejected. Upkit verifies that
mount information comes from procfs and rechecks its mount records. Kernels that
backport idmapped mounts without exposing an `idmapped` marker in mountinfo may
not be detected. Ambiguous user-namespace UID mappings fail closed.
These inspection results do not authorize deletion; the separate removal preview
repeats stricter checks.

On Linux, highlight a discovered artifact and press `d` for a separate removal
review. To review several directories together, mark them with Space and press
`d`; marks persist when filtering or sorting. Scroll through every entry and
selected target, then review the final warning and confirm.
Long paths continue on rows marked `+`; changing the terminal width restarts
the list review. The final confirmation must fit on the screen.
The operation permanently deletes all listed contents, including any user data.
It rejects incomplete scans, links, nested project/VCS markers, unsupported Git
history and observed or uninspectable same-user process activity. Project,
manifest and target identity, exclusions and the full tree are checked again
before execution. A private sibling quarantine reduces path races; failure or
interruption can leave a partially deleted directory there. Git and process
checks are snapshots, hidden processes and same-user races remain possible, and
the logical size does not guarantee reclaimed space. Trees are limited to 10,000
entries and 128 directory levels. Git 2.36+ and Linux `openat2` are required;
strict ownership, permission and `/proc` checks can reject otherwise valid
projects. Other platforms do not support directory removal yet.

For automation, inspect the complete JSON plan and its token before authorizing
one exact target:

```sh
upkit --non-interactive --json sweep run --scope artifacts --select /absolute/project/target --root /absolute/project --preview
upkit --non-interactive --yes sweep run --scope artifacts --select /absolute/project/target --root /absolute/project --authorize-artifact-removal --preview-token TOKEN
```

For multiple directories, repeat `--select` in both commands and use the
combined token from that batch preview. A batch accepts at most 32 distinct,
non-overlapping targets. Upkit revalidates every target before starting, then
quarantines and reports each directory separately. A later failure can leave
previous targets removed or a partially removed directory in quarantine;
inspect each result and any history warning. `--dry-run` removes nothing and
writes no history. Shared cache removal accepts one selection at a time.

On Linux, selected CPython bytecode files can be removed. In the Ratatui artifact
scan or preview, highlight a Python `__pycache__` candidate and press `b` to list
supported filenames. Use Space to mark up to 32 files and Enter to preview the
selection, or press Enter without marks to preview the highlighted file. The
listing is read-only and limited to 10,000 directory entries; eligibility is
checked again before each removal.
Alternatively, supply its absolute canonical path and a workspace root (or
configure a root first). Both terminal workflows require a visible confirmation;
the terminal must be large enough to show the complete plan.

```bash
upkit sweep bytecode "$HOME/projects/example/__pycache__/module.cpython-311.pyc" --root "$HOME/projects/example"
upkit --non-interactive --json sweep bytecode "$HOME/projects/example/__pycache__/module.cpython-311.pyc" --root "$HOME/projects/example"
upkit --non-interactive --yes sweep bytecode "$HOME/projects/example/__pycache__/module.cpython-311.pyc" --root "$HOME/projects/example" --run --authorize-bytecode-removal --preview-token TOKEN
upkit --non-interactive --json sweep bytecode-batch FILE1 FILE2 --root "$HOME/projects/example"
upkit --non-interactive --yes sweep bytecode-batch FILE1 FILE2 --root "$HOME/projects/example" --run --authorize-bytecode-removal --preview-token BATCH_TOKEN
```

The batch token binds the complete ordered selection; an outdated token rejects
the batch before deletion. Each file is rechecked and each attempted removal is
recorded individually,
and the batch stops on the first failure or unverified result. In the terminal,
Esc requests cancellation, the result dialog shows individual outcomes, and the
complete confirmation must fit on screen. Repeated safety scans can take time.

The commands support timestamp-based and checked or unchecked hash-based caches
for CPython 3.10–3.15 and 3.16a1
(its exact pre-release bytecode magic number only) up to 64 MiB,
with an existing matching source file. They require Linux `openat2`, a complete
inventory of the selected cache, a non-shallow Git repository without a graft file, Git 2.36 or later,
and no observed or
uninspectable same-user process activity. The project directories, manifest,
source, and cache file must be user-owned and not group/other writable; links,
hard links, child mounts, exclusions, and several VCS markers cause refusal.
These restrictions may make the operation unavailable, including when `/proc`
permissions prevent inspecting other processes. Git and process checks are
snapshots and cannot eliminate concurrent changes or prove that no build is
active. The file is moved into a private quarantine before permanent deletion;
an interrupted operation or failed rollback can leave a file there. The logical
size is not a guarantee of reclaimed space.

For hash-based caches, Upkit checks the source hash against the bytecode header
and limits source files to 64 MiB. A matching header does not prove the bytecode
body came from that source. In particular, Python normally does not validate the
source for unchecked hash caches, so removing one can change program behavior;
the preview identifies that mode before confirmation.

Git 2.36–2.44 cannot disable lazy fetching directly, so Upkit rejects repositories
configured as partial clones for HEAD and history checks and denies all Git
transport protocols. Git 2.45 and newer also receive `--no-lazy-fetch`.
These checks do not prevent concurrent repository changes.

The bytecode magic values follow CPython's versioned source headers for
[3.14](https://github.com/python/cpython/blob/v3.14.0/Include/internal/pycore_magic_number.h),
[3.15](https://github.com/python/cpython/blob/v3.15.0/Include/internal/pycore_magic_number.h),
and [3.16a1](https://github.com/python/cpython/blob/v3.16.0a1/Include/internal/pycore_magic_number.h).

To save scan settings, create a configuration file and then scan its roots:

```bash
upkit config init "$HOME/projects" --exclude vendor --retention 30d
upkit config show
upkit sweep scan
```

The default configuration is `upkit/config.toml` in the operating system's
configuration directory (for example, `~/.config/upkit/config.toml` on Linux).
Use `--config <path>` to choose another file. `config init` never overwrites an
existing file. In a terminal, open **Settings** from the dashboard (or run
`upkit config show`). Press `e` for the structured form, or `t` for the advanced
TOML editor, and use Ctrl+S to validate and review a save. `y` confirms after
review; Esc exits or offers to discard unsaved edits. The form edits global
settings and profiles while retaining unrelated text; press `n` in the form to
add a profile. Use the TOML editor to remove profiles or edit formats the form
cannot safely update. Configuration creation and loading are capped at 1 MiB;
the advanced editor accepts existing files up to 128 KiB, preserves comments, and
can repair invalid TOML. Non-newline control characters, including bidirectional controls, appear as `�` in
the editor without changing the underlying text; changed setting values show
their escapes during save review. Changing settings does not start cleanup or
alter a schedule.
The global theme can be switched between `dark` (default) and `light` in the
form or with `theme = "light"` in TOML; it takes effect after a reviewed save.

On Linux, saving an existing file retains a private backup in the same directory
and checks for concurrent changes. It requires a user-owned configuration
directory that is not group/other writable, no symlink or hard-linked target,
and no extended attributes or ACLs; it uses an atomic exchange where supported.
Concurrent filesystem changes can still race with verification or rollback.
On macOS and Windows, the editor can create a new configuration but cannot yet
replace an existing one while preserving all platform metadata. A file can look
like:

```toml
version = 1
workspace_roots = ["/path/to/projects"]
exclusions = ["vendor", "project/target/private"]
artifact_retention = "30d"
schedule_frequency = "weekly"

[profiles.work]
workspace_roots = ["/path/to/work"]
exclusions = ["private-project"]
artifact_retention = "14d"
enabled_ecosystems = ["cargo", "python"]
schedule_frequency = "daily"
```

Explicit scan roots replace configured roots; command-line exclusions are added
to configured exclusions, and `--older-than` overrides the configured age. No
roots or automatic cleanup are enabled by default. Unknown fields and unsupported
configuration versions are rejected rather than ignored.

Use `upkit --profile work sweep scan` or `upkit --profile work sweep preview`
to select a named workspace. A profile uses its own roots, adds its exclusions
to the global exclusions, and overrides the global retention when specified.
An empty or unknown profile never falls back to the default roots. Explicit scan
roots still override profile roots, and explicit `--older-than` takes precedence.
Profiles can be created and edited in the form or TOML editor; they do not
themselves schedule or delete files.
For schedule preview and changes, an explicit `--frequency` takes precedence
over the profile setting, then the global setting, then the weekly default.
Changing the setting does not modify an existing schedule; review and edit it
to apply the new frequency.
An optional `enabled_ecosystems` list can also be set globally or in a profile.
When both are present, only their intersection is scanned. Omit the field for
all supported ecosystems, or use `[]` for none. Accepted names are `cargo`, `go`, `zig`,
`cmake`, `meson`, `ninja`, `gradle`, `maven`, `sbt`, `dotnet`, `flutter`, `dart`,
`python`, and `javascript`. With `go` enabled, only root `build/` and `bin/`
directories are listed for inspection; they cannot be removed. Other Go output
locations are not discovered. Flutter `build` and Dart `.dart_tool` are separate entries.
Recognized artifact subtrees belonging to disabled ecosystems are skipped to
avoid walking large generated trees; the scan warns that nested projects may
not be detected there and is marked incomplete.
When more than one ecosystem signature matches the same artifact directory,
Upkit skips it and marks the scan incomplete because it cannot separate the
contents by producer.
Unsupported ecosystem names are rejected.

Update a specific tool:

```bash
upkit update go
upkit update rust
upkit update node
upkit update python
upkit update flutter
upkit update mojo
upkit update java
upkit update dotnet
```

Java targets the latest Eclipse Temurin LTS JDK. Upkit verifies the archive
SHA-256 from the [Adoptium release metadata](https://adoptium.net/installation/gpg-verification)
before extracting it into a new managed directory. Extraction is limited to
100,000 entries and 3 GiB. The initial archive URL must use GitHub or the
Adoptium API; HTTP redirects are not restricted to those hosts. Selected JDK executables are linked into the Upkit
binary directory; `JAVA_HOME` is not changed. Earlier managed versions remain
in place. A checksum from the same metadata is not independent signature
verification.

.NET targets the latest supported LTS SDK using [Microsoft release metadata](https://github.com/dotnet/core/blob/main/release-notes/README.md).
Upkit verifies the archive's SHA-512 before extraction, limited to 100,000 entries
and 3 GiB. The initial archive URL must use an identified Microsoft download
host; HTTP redirects are not restricted to that host. The checksum is not
independent signature verification. Detection
infers stable SDK versions from directories beside the resolved executable
without running it. A version counts only if its SDK directory contains a
nonempty `dotnet.dll` resolved inside that installation root; this layout check
does not verify integrity. Earlier managed versions remain, and `DOTNET_ROOT` is
not changed. The SDK may require additional system
libraries provided by the operating system.

For both providers, Windows ZIP extraction rejects links, unsafe or duplicate
paths, and more than 64 MiB of entry names. Activation requires permission to
create directory and file symbolic links; the existing installation is retained
if activation fails. Windows and macOS installations have not been verified on
native systems. As of November 2026, [Adoptium does not ship JDK 25 for
Windows ARM64](https://adoptium.net/news/2026/08/eclipse-temurin-8u502-11032-17020-21012-2504-2602-available),
so the latest JDK is unavailable there unless Adoptium adds that asset.
Concurrent changes can still race extraction or activation.

Mojo updates use `pixi update mojo` for Pixi projects, or
`uv pip install --system --upgrade mojo` otherwise. See the [official Mojo install
docs](https://mojolang.org/install/).

Clean managed installs and symlinks:

```bash
upkit clean
```

Uninstall managed installs and symlinks:

```bash
upkit uninstall
```

In an interactive Linux terminal, these commands open the Toolchains screen.
On the Toolchains screen, `/` filters by tool name, version, status, or notes.
Press `r` to refresh the toolchain inventory in the background. Marks remain
selected when hidden by the filter. On the Toolchains screen,
`Space` marks a cleanup target and `D` opens one combined preview for all marked
targets; if none are marked, `D` previews the selected tool. Use `d` to preview
only the selected tool. The combined preview lists every selected root, its
matching binary links, logical size, process observations, installation status,
and all top-level entries. Scroll through the entire review with the arrow keys
before pressing `y`; `Esc` or `n` cancels. If the review cannot fit the terminal
or its supported scroll range, enlarge the terminal or mark fewer targets. A
single-tool preview also lists the root entries and known links, and requires the
full plan to fit on screen before confirmation. Cleanup selects only installation
directories whose Upkit-created seals still match their contents, and links whose
receipts match. It preserves unverified installations and other root entries.
Older installations without seals are not adopted automatically. Shell PATH
hints remain unchanged.
For Go, recorded binary links to Upkit's wrapper paths are included when their
active installation is selected; the wrapper files themselves are preserved.
An unrecorded link to a Go wrapper blocks removal of the active installation.

Seals are written best-effort for new archive installations; a changed tree,
hard-linked files, nested mounts, or an inventory exceeding the verification
limits can prevent cleanup. A failed seal does not prevent installation. If the
receipt directory is missing or damaged, or the configured binary directory has
changed, preview fails closed. Restore the original binary directory and inspect
the old links and receipts before repairing them manually. These receipts do not
authenticate data against another process running as the same user. The read-only
preview reports whether the managed home, tool root, or binary directory is
writable by group or others. Removal refuses an eligible plan with such a
directory and checks the opened directory modes again before staging and after
staging; a detected change restores the staged paths.

Before a batch begins removing anything, Upkit rechecks every target plan and
process activity. A changed plan, an eligible target with a group/other-writable
managed path, or an observed process using any selected root vetoes the entire
batch before its first removal; fix the directory permissions or stop the
process, then preview again. An incomplete process inspection is a warning and
can miss active use.
Each target is checked again as it is processed. Process visibility, concurrent
filesystem changes, and mounts can still race with cleanup. A failure,
unverified result, history warning, or cancellation stops later targets;
completed removals are not rolled back. Each selected installation and recorded
link is moved into private quarantine before deletion; the tool root remains.
Interruption or failure can leave quarantined files or a partially removed
installation. Upkit checks known binary names in the configured directory, not
every possible external link. Review per-target results and any quarantine before
retrying. Estimates are not reclaimed space.
The interactive cleanup workflow currently requires Linux `openat2`. On macOS
and Windows, the dashboard reports managed cleanup as unavailable until
equivalent filesystem safeguards are implemented. For Linux automation, preview
the exact selection and use its unchanged token to authorize removal:

```bash
upkit --non-interactive --json clean go node --preview
upkit --non-interactive --yes clean go node --authorize-managed-cleanup --preview-token TOKEN
```

`uninstall` accepts the same flags. Select names, `--only`, or `--all`; keep
the same selection and command when using the token. The preview includes absent
tools. A changed plan rejects the batch before removal, and a failed or
unverified operation stops the remaining tools. The preview is read-only,
and its JSON uses the tagged path representation described above for
non-Unicode paths; ordinary Unicode paths remain strings.
`--dry-run` never removes files, and shell PATH hints remain unchanged. Existing
scripts that used `--yes` alone must obtain a preview token and explicitly
authorize cleanup. `managed-clean` remains available for a single tool.

Library callers must migrate from the legacy `clean_tool` function: it now
only supports dry runs and refuses removal even when `yes` is set. Use
`managed_cleanup::preview`, present the complete plan for explicit confirmation,
then execute the reviewed plan with `reports::perform_managed_cleanup` to record
the outcome. The reviewed removal workflow is currently Linux-only.

Diagnose common setup problems:

```bash
upkit doctor
```

On Linux, macOS, and Windows, Doctor reports available bytes on the Upkit home
filesystem and warns below 1 GiB. The value is a snapshot; it is unavailable if
the home cannot be measured. Windows paths that are not Unicode are currently
unavailable, and a filesystem query may block on a slow network volume. JSON uses
`home_available_bytes`.
Doctor reports missing Upkit directories without creating them or editing shell
configuration. The CLI tests write permission with temporary files in existing
directories; the dashboard and `--dry-run` skip those write probes.
For managed Go, Node, Python, Flutter, Java, and .NET links, Doctor also warns
when a resolved binary is outside that tool's managed installation directory.
This path check does not verify executable contents or rule out later changes.
On Unix, Doctor also compares sealed managed installations against their recorded
contents without changing them. Its aggregate verification is capped at 16 seals,
256 MiB, 50,000 entries and 64 directory levels; it reports skipped or unsealed
installations as unknown. A matching seal does not prove the tool works. Press
Esc while Doctor is running to request cancellation; a filesystem call already
underway may finish first. After cancellation is observed, Doctor skips
remaining capability and diagnostic checks. Windows seal verification remains
unsupported.
In the Doctor screen, `/` filters diagnostic lines, Enter applies the filter,
and Esc cancels editing it; clear the filter to show all diagnostics again.
Doctor can also warn about substantial artifact growth between the two most
recent complete scheduled scans of the same scope and policy. This uses local
history and estimated logical sizes; opening Doctor does not start a scan.
Doctor also reports whether Linux `openat2` can be called, the `fstrim` and
Upkit scan timer snapshots, and whether Docker and Podman executables are on
PATH. The cache probe does not approve any target, the scan timer's ownership and
action are unverified, and Docker/Podman connections are not tested by Doctor.
For explicitly configured container endpoints, Doctor also reports whether a
local Unix socket exists or the endpoint requires further checking. It does not
display endpoint values or contact them; a socket's existence does not prove the
daemon is reachable. Named contexts and endpoints without a supported local
socket check remain unverified.
Timer checks query systemd on Linux and launchd for the Upkit scan label on
macOS; they do not alter schedules. On Linux, `--offline` skips the timer
queries because a systemd manager endpoint can be remote. With `--dry-run`,
Doctor skips platform timer-manager queries and reports their state as skipped.
For managed Windows Node and Flutter installations, Doctor also checks whether
their directories are on PATH and reports earlier candidate commands as possible
overrides. Shell aliases, working-directory lookup, and native Windows behavior
are not verified by these checks.

Inspect Linux TRIM timer status without changing storage or schedules:

```bash
upkit maintenance status
upkit --json maintenance trim --status
```

With `--dry-run`, Upkit still reports local mount information but skips the
systemd timer query and reports its state as skipped.

In status JSON, Unicode mount paths remain strings in `mount_point`; a
non-Unicode path adds a tagged `mount_path` object using the path representation
described above. Terminal mount labels keep Unicode readable and escape literal
`%`, backslashes, and control characters so they are distinct from encoded
bytes. Pass the original filesystem path to `--mount`.

On Linux, `maintenance temp` can review abandoned Upkit symlink staging
directories. It examines only recognized `.upkit-link-*` directories under
the managed Upkit roots and configured binary directory, never general system
temporary directories. Candidates must be at least 30 days old and pass path,
ownership, contents, and process-activity checks. Preview a specific selection
and use its token to authorize removal:

```bash
upkit --non-interactive --json maintenance temp --preview
upkit --non-interactive --json maintenance temp --preview --select /path/to/.upkit-link-example
upkit --non-interactive --yes maintenance temp --run --select /path/to/.upkit-link-example \
  --authorize-temp-cleanup --preview-token TOKEN
```

The selection is revalidated and staged into quarantine; interruption or a
partial failure can leave a quarantine directory. Process inspection is a
bounded snapshot and concurrent changes can still race. `--dry-run` makes no
changes. In the Maintenance screen, press `l` to inspect, mark eligible staging
directories, and review them before confirming removal. An interactive
`upkit maintenance temp --preview` without a selection opens the same view.
The cleanup is
unsupported on macOS and Windows.

A read-only scan schedule can be previewed before installation. Linux uses
systemd user units, macOS uses a per-user LaunchAgent in
`~/Library/LaunchAgents`, and Windows uses the current user's Task Scheduler:

```bash
upkit --non-interactive schedule preview --frequency weekly --exclude 'glob:**/vendor' /absolute/workspace
upkit --json schedule preview --frequency daily /absolute/workspace
```

`upkit schedule list` and the Automation screen inspect the platform schedule.
On Linux this is the `upkit-scan.timer` label in the user manager; on macOS it
is the `upkit-scan.timer` LaunchAgent; on Windows it is `\Upkit-Workspace-Scan`.
Windows status is available only when the task path, task XML,
current-user SID, task owner, access rules, and state can all be verified. A
missing or unavailable manager is reported separately.
On Linux, manager output reads have a timeout. A timed-out schedule change may
still have taken effect; inspect the manager state before retrying. A child
process spawned by an external manager can outlive the timeout.
On macOS, timed-out `launchctl` calls attempt to stop their process group.
External child reaping can release process IDs before this signal, so that
protection is not a guarantee in environments that reap Upkit's children.

In a terminal, the `schedule preview*` commands open a scrollable, read-only
Ratatui preview. The `add`, `enable`, `disable`, `edit`, and `remove` commands
without automation authorization flags open the corresponding confirmation;
the supplied roots, exclusions, and frequency are retained. Preview commands
do not change schedules, even when `y` is pressed. Redirected previews use text
output, and `--dry-run` plans an operation without changing the schedule.
With `--dry-run`, status and previews that need the current manager state are
skipped; Upkit reports that state as uninspected and returns no plan or
authorization token. Run the ordinary read-only preview to get a complete,
reviewable plan. The filesystem-only `schedule preview` command and dry-run
`schedule add` still render the intended schedule without querying the manager.

The preview writes no unit and changes no schedule. For an explicitly approved
scan, repeat the same roots, exclusions, and frequency with the preview token:

```bash
upkit --non-interactive --yes schedule add --frequency weekly --exclude 'glob:**/vendor' \
  --authorize-schedule --preview-token TOKEN /absolute/workspace
```

The unit directory shown by the Linux or macOS preview must already exist, be
owned by the current user, and not be group- or world-writable. On Linux, Upkit
refuses existing units and systemd drop-ins, creates unit files without
overwriting, verifies the user manager loaded those files, then enables the
timer. On macOS, Upkit creates a private, user-owned plist without overwriting
an existing file, checks that any loaded label points to that plist, then
enables and bootstraps the LaunchAgent. The plist uses `RunAtLoad=false` and
runs a read-only scan at 03:00 local time daily or Sunday weekly; it does not
launch a scan immediately.

On Windows, Upkit registers one task at `\Upkit-Workspace-Scan` for the
current account with `InteractiveToken` and `LeastPrivilege`. It runs a read-only scan at 03:00
local time daily or Sunday weekly. Registration uses utilities from the Windows
system Known Folder and never searches `PATH`. Upkit refuses to overwrite an
existing task and only changes a task whose path, Upkit XML, current-user SID,
owner, access rules, and state match the reviewed plan. The task DACL must not
grant any other account nonzero access. The temporary task XML must be
in a private current-user cache directory. Disabling and removing bind the full
task, security, and state snapshot to the preview and check it again immediately
before acting; Task Scheduler can still change state after that final check.
Upkit requires a disabled, idle task before removal or edit. Automatic cleanup
schedules remain Linux-only. Each
platform's command can fail after creating files or changing manager state;
inspect the files or task and manager before retrying. `--dry-run` makes no
changes. The CLI commands do not apply
configured profiles when workspace roots are supplied explicitly: include every
desired exclusion explicitly. To use the selected profile's roots, exclusions,
retention, and ecosystem filters, omit the roots and `--exclude`:

```bash
upkit --non-interactive --profile work schedule preview --frequency weekly
upkit --non-interactive --yes --profile work schedule add --frequency weekly \
  --authorize-schedule --preview-token TOKEN
```

Use the same profile and configuration when previewing and executing `add`,
`enable`, or `edit`. Their configuration is checked again before activation and
the resulting job checks it again on every run. `--exclude` requires explicit
roots; add profile exclusions to the configuration instead. By default, a scheduled
scan writes JSON output to the user journal, records its outcome in local Upkit
history, and never deletes files. Incomplete scans are recorded as partial and return a
nonzero exit status. History write failures appear as warnings in the output;
`--dry-run` does not write history. Scheduled scans check the executable and
workspace identities before scanning. Linux requires `openat2` and filesystem
birth timestamps; macOS verifies opened files without following symbolic links
and checks filesystem creation identity; Windows compares canonical paths and
filesystem identities and rejects reparse-point paths. Replacing a root or
executable, or a device identity change after reboot, can stop scheduled scans
until the schedule is reviewed and recreated. Schedules generated by older versions do not have
this check and cannot be re-enabled through the new matching workflow; disable
and review those units before replacing them. The executable starts before it
can check its own identity, and paths can still change during traversal. Unit
files, task XML, or manager state can also change after checks; the user manager
may use a different configuration directory. To stop and disable the schedule,
review the preview and use the resulting token:

```bash
upkit --non-interactive schedule preview-disable
upkit --non-interactive --yes schedule disable --authorize-schedule --preview-token TOKEN
```

To opt in to automatic Python bytecode cleanup instead of a scan, explicitly set
the policy on the profile being scheduled:

```toml
version = 1

[profiles.work]
workspace_roots = ["/absolute/workspace"]
artifact_retention = "30d"
enabled_ecosystems = ["python"]
scheduled_bytecode_cleanup = true
```

Preview and confirm the schedule with the same `--profile work` commands above.
The plan warns that the timer permanently deletes eligible bytecode automatically;
the exact future filenames are discovered within the approved roots on each run.
Retention must be at least seven days and Python must be enabled. A profile must
opt in itself; a global opt-in does not enable cleanup for profiles. Upkit inspects
at most 32 files and 32 cache directories per run, and chooses at most one file per
cache because removal changes the cache directory's age. Unchecked-hash bytecode is
skipped. Each selected file is rechecked against the scan scope, configuration,
source metadata or hash, Git history, paths, permissions, and process activity.
If the initial workspace scan is incomplete, nothing is deleted; unverifiable
files are skipped. Header checks do not prove that
bytecode bodies match their sources, and concurrent changes can still race checks.
A removal failure stops further removals and can leave a quarantine file. Results are recorded
in local history and the user journal. `--dry-run` lists candidate files as
`skipped_unverified`; `inspected` counts only enumerated filenames because
bytecode, source, process, and Git checks are skipped. When files are found, the
report is incomplete and no history or files are changed. This policy
does not remove shared caches, Trash, or whole artifact directories. When
there are more than 32 caches or files, cache order rotates weekly in UTC and the
file window advances after each full cache cycle, without storing a cursor.
Repeated runs in the same week can inspect the same
ineligible entries; additions or removals can shift the window, so this does not
guarantee every file will be cleaned. Each removal reserves an unfinished local
history record before it starts; an interrupted operation or history write can
leave that record unfinished. Cleanup stops if a record cannot be reserved.

For scheduled project artifact cleanup on Linux, a profile can instead or also
set `scheduled_artifact_cleanup = true`, list its enabled ecosystems, and set
`artifact_retention` to at least `30d`. Review and authorize the same schedule
preview before installation. Each run selects at most eight eligible Maven
`target`, Zig `.zig-cache`, Dart `.dart_tool`, or Python `.pytest_cache`
and `.mypy_cache` directories within the approved roots. The scope and policy,
Git evidence, activity, identity and contents are rechecked before removal. A
failure stops subsequent artifact removals and can leave files in quarantine.
History records an attempt before each removal; a crash or failed history write
can leave an unfinished record that the in-app history purge skips and that may
require manual recovery. Reclaimed space is not guaranteed by the size estimate.
Scheduled Cargo removal is unavailable until Cargo's inherited configuration and
target identity can be verified across preview and execution.

In the Automation screen, `d` opens the same disable preview. Review the wrapped
plan with the arrow or Page Up/Down keys; `y` confirms only after the complete
plan has been displayed. Resizing resets review. Backslashes and control
characters are escaped in the display. On Linux, the disable preview requires
the expected local units, no systemd drop-ins, and a manager that does not
report a pending reload. Upkit rechecks these facts and unit identity before
acting. Disabling leaves the Linux or macOS schedule files in place and does
not stop an already running service, including cleanup. Windows disabling is
allowed only while the verified task is idle; its XML, owner, access rules,
principal, and scope are checked again before changing it. Inspect the manager
before retrying if the outcome is unknown. Linux unit ownership is not
independently proven, and state may change after revalidation. To enable the same
disabled schedule again, repeat its
original root, exclusions, and frequency in both commands:

```bash
upkit --non-interactive schedule preview-enable --frequency weekly --exclude 'glob:**/vendor' /absolute/workspace
upkit --non-interactive --yes schedule enable --frequency weekly --exclude 'glob:**/vendor' \
  --authorize-schedule --preview-token ENABLE_TOKEN /absolute/workspace
```

The installed schedule must match the regenerated plan. In the Automation
screen, `1` or `7` previews re-enable for a daily or weekly timer using the
active configuration profile; review the complete plan before confirming with `y`.
The profile's roots, exclusions, retention, and ecosystem filters must match the
installed units. New configured schedules snapshot the effective policy and
recheck the configuration before activation and before each run; if the scope
or policy changes, the scheduled operation stops until the schedule is reviewed and recreated.
Older scope tokens still work for their original unrestricted scans. A matching
older unit can be re-enabled when the selected profile has no retention or
ecosystem filter; its runtime does not reload the configuration, so review and
replace it if the scope or policy changes.
For a new timer, the Automation screen also offers `a` for daily installation
and `w` for weekly installation using the active profile; it shows both units
before `y` confirms. Installation and re-enable recheck the supported profile
scope immediately before enabling. Enabling may start the scheduled operation
promptly. On Linux and macOS, disable the timer or LaunchAgent and wait for its
service to become inactive before reviewing files for removal. On Windows,
the task must be disabled and idle before it can be removed:

```bash
upkit --non-interactive schedule preview-remove
upkit --non-interactive --yes schedule remove --authorize-schedule-removal --preview-token REMOVE_TOKEN
```

On Linux, removal checks the manager and unit identities, then moves the two
files to the previewed quarantine names before deleting them. It never
overwrites a quarantine file. Windows removal unregisters only the verified,
disabled task and leaves workspace files unchanged. A failure can leave one or
both Linux units at quarantine names or leave a partial removal; inspect the
directory and manager before retrying. File and manager state can still race
after checks. In the Automation screen, `x` opens the
removal preview and `y` confirms after the platform plan has been reviewed. To
replace a disabled schedule, inspect both the old and replacement plans, then
use the edit token:

```bash
upkit --non-interactive schedule preview-edit --frequency weekly /absolute/workspace
upkit --non-interactive --yes schedule edit --frequency weekly --authorize-schedule-edit \
  --preview-token EDIT_TOKEN /absolute/workspace
```

Editing removes the old schedule and then installs and enables the replacement.
It does not roll back automatically: failures may leave quarantined Linux or
macOS files, a missing old schedule, or a partially installed or active
replacement. On Windows the old disabled task is unregistered before the new
task is registered. Review the manager and schedule files before retrying. In
Automation, `e` previews a daily replacement and `E` previews a weekly
replacement using the active profile. Review both plans before `y` confirms.
Supported profile scope is checked again before removal and activation.

The report and the dashboard's System Maintenance screen check for `fstrim` and
the existing systemd `fstrim.timer`. On Linux, the report also shows discard
limits advertised by visible block devices and available filesystem bytes for
the listed mounts, when measurable. Available bytes are a snapshot for an
unprivileged user and do not predict reclaimed space. These limits do not prove the
mounted filesystem supports TRIM or that the user has permission. In the
mount list, Upkit also reports explicit online-discard mount options and
whether `X-fstrim.notrim` was observed in a unique, well-formed `/etc/fstab`
entry with the same mount point and filesystem type. Duplicate, malformed,
missing, or unmatched entries remain unknown. `not_observed` describes only
that entry; it does not prove the entry applies, the timer honors it, or that
FITRIM is supported.
On Linux, the maintenance screen lets you select a mount and press Enter to
review a TRIM plan; `y` confirms it. Manual TRIM is also available through an explicit
non-interactive preview and authorization:

```bash
upkit --non-interactive maintenance trim --preview --mount /path/to/mount
upkit --non-interactive --yes maintenance trim --run --mount /path/to/mount \
  --preview-token TOKEN_FROM_PREVIEW --authorize-trim
```

In an interactive terminal, `maintenance trim --preview --mount PATH` opens
an inspection-only preview; it cannot start TRIM.
Use the same canonical filesystem-root mount for both commands. Upkit checks
the current boot and mount-table record again before starting `fstrim`; it does
not elevate privileges or change timers. TRIM affects unused blocks throughout
the filesystem and does not increase its free-space figure. A mount can still
change between the final check and the system command. Manual TRIM on other
platforms is not implemented.

On macOS, status reads the root filesystem type and available space, and checks
direct children of `/Volumes` for mounts on a different device. This is a partial
inventory: other mount locations and mounts sharing a device identity can be
omitted. It does not establish device TRIM support or the system maintenance
schedule. On Windows, the read-only `fsutil` query reports filesystem
delete-notification settings, not device support. Windows also inventories
filesystem types and user-available space on fixed volumes with drive letters;
network drives, removable drives and volumes mounted only in folders are omitted.
Failed volume queries are marked incomplete. Dry-run skips these queries. Native
macOS and Windows behavior has not yet been verified.

Inspect Trash without deleting items:

```bash
upkit trash status
upkit --json trash status
```

On macOS, status lists escaped names for up to 10,000 top-level entries in the
current user's [home Trash](https://developer.apple.com/documentation/foundation/url/trashdirectory)
without following a linked Trash directory. Names and counts are a read-only
snapshot and entries may change during inspection; deletion dates and item actions
are unavailable. Names escape non-ASCII bytes, control bytes, and `%` as `%XX`.
This snapshot includes any metadata entries and may differ from Finder's count.
It estimates the total logical size of regular files without reading their
contents, within a 100,000-entry and 128-level limit. Symlinks, special files,
and entries on different devices are skipped and mark the estimate incomplete;
same-device mounts are not detected, and hard links are counted per entry.
Upkit also checks direct mounted children of `/Volumes` for a user-owned
`.Trashes/<effective UID>` directory. This undocumented layout is a heuristic,
not a complete Finder inventory: same-device mounts, other mount paths and
other Trash layouts can be omitted. Volume inspection is capped at 256 entries,
10,000 listed Trash items and 100,000 size-walk entries across volumes; limits
or inaccessible locations are reported as incomplete. Per-item sizes are not
available.
Access may be denied by macOS privacy controls, and a slow filesystem can delay
inspection. This integration has not been tested natively.

On Windows, status uses the system PowerShell host and the Shell's virtual
Recycle Bin to report an item count and an estimated total logical size of
measurable files. Folders and unmeasurable entries are excluded and mark the
size incomplete; inspection is limited to 100,000 items. No filesystem path is
assumed; JSON reports the virtual location's path as `null`. Item names,
individual sizes, dates, and removal are not available. The query has a
two-second process timeout; resolving the system host or starting a process can
still be delayed, including on a mapped drive.
This Windows integration has not been tested natively.

On Linux this inventories the FreeDesktop home Trash and accessible user-owned
Trash directories on mounted volumes. It lists up to 10,000 items per location
and shows a deletion date when valid matching metadata is available; dates are
local timestamps. An age-based, read-only preview is available with
`upkit --json trash preview --older-than 30d`; it leaves all entries unselected.
In an interactive terminal, `upkit trash preview --older-than 30d` opens the
preview screen. On the Trash screen, press `7`, `1`, or `3` for a 7-, 14-, or
30-day preview, or `0` to return to the inventory. Use the arrow keys and Space
to mark known-old entries in a completely inspected Trash location. Press `A`
to mark eligible old files and directories in the highlighted item's location; it
reports how many entries were newer, had unknown dates, or were unsupported.
If more than 100 files qualify, select a smaller set manually. Marks are cleared on refresh;
press Enter to review them, then `d` to preview permanent deletion of up to
100 selected items. The full plan must fit on screen before `y` confirms
it. Names escape non-ASCII bytes, control bytes, and `%` as `%XX` so distinct
names remain distinguishable. For automation, use the exact location and
escaped name from the inventory:

```bash
upkit --json --non-interactive trash preview-remove --location /absolute/path/to/Trash --name NAME --older-than 30d
upkit --non-interactive --yes trash remove --location /absolute/path/to/Trash --name NAME --older-than 30d \
  --preview-token TOKEN_FROM_PREVIEW --authorize-trash-removal
upkit --json --non-interactive trash preview-batch --location /absolute/path/to/Trash --name NAME1 --name NAME2 --older-than 30d
upkit --non-interactive --yes trash remove-batch --location /absolute/path/to/Trash --name NAME1 --name NAME2 --older-than 30d \
  --preview-token BATCH_TOKEN --authorize-trash-removal
upkit --json --non-interactive trash preview-retention --location /absolute/path/to/Trash --older-than 30d
upkit --non-interactive --yes trash retain --location /absolute/path/to/Trash --older-than 30d \
  --preview-token RETENTION_TOKEN --authorize-trash-removal
upkit --json --non-interactive trash preview-empty --location /absolute/path/to/Trash
upkit --non-interactive --yes trash empty --location /absolute/path/to/Trash \
  --preview-token EMPTY_TOKEN --authorize-trash-removal
```

The retention preview selects eligible items in that location by age and lists
every selected item; it also counts excluded entries. A changed selection
invalidates the token. Empty or ineligible locations produce a preview without
a deletion plan. Location-specific previews enumerate items only in the chosen
location; discovery still checks metadata for other candidate Trash directories
to validate and deduplicate locations. This manual retention command does not
run automatically; scheduled Linux Trash retention is a separate opt-in below.

For manual emptying, `upkit trash empty --location /absolute/path/to/Trash`
opens the confirmation in an interactive terminal. The plan lists every file
in that location regardless of age, including files with invalid dates. It
refuses the whole operation if inventory is incomplete, there are more than
100 items, or any item is not a safely inspectable file or directory with matching
metadata. Directory previews include descendant counts and logical sizes, bind
the complete tree to the token, and permit up to 10,000 entries and 128 levels.
An unsafe or unreadable directory stops the preview so the remaining selection
is not mistaken for a complete operation.
The selection is checked again immediately before removal. The result
reports whether the location's `files` directory was empty afterward; new files
can still arrive concurrently, and orphaned metadata in `info` is not removed.

Deletion is irreversible. It requires Linux `openat2`, an unchanged item and
matching metadata, a complete inventory of that location, and user-owned directories and files
that are not writable by group or others. Top-level symlinks, hard-linked files,
special files, and mounted child paths are rejected. Symlinks inside a reviewed
directory are removed as links; their targets are never followed. Upkit moves the item and its
metadata into a private quarantine before deletion and attempts to restore them
if validation fails; interruption or partial failure can leave quarantine files
or orphaned metadata that require inspection. If directory deletion stops after
removing some descendants, the remaining tree and its metadata stay in the
private quarantine for inspection. A batch reports each item; after
an unverified or failed result it skips remaining items in that location while
continuing other selected locations. During a batch, Esc requests cancellation
after the current item; the result identifies completed and cancelled items.
Concurrent changes by the same
user can still race the final checks. Age uses the current local time zone,
which may differ from the zone at deletion; ambiguous or invalid dates are
unknown. Counts include orphaned entries and size estimates may be incomplete.
Emptying locations containing unsupported items and native macOS or Windows
Trash deletion are not yet implemented.

### Scheduled Linux Trash retention

Scheduled Trash retention is Linux-only and defaults off. It is a separate
global opt-in in the bound Upkit configuration, not a workspace-profile policy
and not implied by scheduled scans or bytecode cleanup:

```toml
version = 1
scheduled_trash_retention = true
```

The Settings screen can change this flag. Saving it does not install, enable,
disable, or remove a timer. Turning it off makes a later scheduled run fail
closed, but does not disable or remove an installed timer. The scheduled policy
must select one exact, canonical Trash location and an age of at least 30 days;
it does not discover and clean every Trash location automatically. A policy is
bound to the private, user-owned configuration file, the selected location, the
age, and the Upkit executable. The config file and existing user unit directory
must be canonical, owned by the current user, and not writable by other users.

Installing and re-enabling require reviewing a preview and using that action's
token. For a non-interactive CLI workflow, use the same config file, location,
and age in the preview and install commands:

```bash
upkit --non-interactive --json --config /absolute/path/to/private-upkit.toml \
  schedule trash-retention preview --location /absolute/path/to/Trash --older-than 30d
upkit --non-interactive --yes --json --config /absolute/path/to/private-upkit.toml \
  schedule trash-retention install --location /absolute/path/to/Trash --older-than 30d \
  --authorize-scheduled-trash-retention --preview-token TOKEN
```

The preview reports current eligible, deferred, and skipped counts and lists at
most 32 current candidates. This is only a sample: installing or re-enabling
authorizes permanent deletion of matching current and future items at the exact
location. Each daily run removes at most 32 eligible items; excess eligible
items remain deferred and make the run partial. Items with unknown or
ambiguous age evidence, unsupported file types, or incomplete inventory are
left untouched. Deletion is permanent, including directory contents.

The timer uses the current user's local systemd manager and a persistent daily
timer. A missed run can catch up, and the service may start soon after install
or re-enable. The local user manager and its `XDG_RUNTIME_DIR/bus` socket,
`systemctl`, an existing current-user-owned unit directory (normally
`~/.config/systemd/user`), Linux `openat2`, and filesystem mount and birth-time
identity support are required. The manager must be active when the timer runs;
enable systemd user lingering outside Upkit if it must run without a login
session. The selected Trash must be a discovered, user-owned FreeDesktop Trash
whose `files` and `info` directories share a supported mount.
Checking the bus socket's ownership and the manager's reported state does not
authenticate the manager peer against a malicious process with the same UID;
these checks cannot guarantee safety while such a same-user process is active.

Trash deletion dates have no time-zone offset. Upkit interprets them using the
current system time zone, which may differ from the zone in effect when an item
was trashed. Scheduled retention uses a conservative 48-hour age margin and
skips missing, invalid, or ambiguous dates; a backward clock change stops the
run. It rechecks configuration, schedule, Trash and mount identity, item
metadata, and age before removal, but same-user filesystem changes can still
race the final checks. An interrupted or partial deletion can leave a file,
metadata, or part of a directory in the Trash location's private quarantine;
inspect that location and the operation result before retrying.

Preview and re-enable an installed timer with its own token. The interactive
Automation screen also offers `T` to preview installing the home Trash policy
at 30 days, `G` to preview re-enabling, `D` to disable, and `X` to remove; review
the complete plan and confirm it explicitly. CLI lifecycle commands require
`--non-interactive` or `--json`:

```bash
upkit --non-interactive --json schedule trash-retention preview-enable
upkit --non-interactive --yes --json schedule trash-retention enable \
  --authorize-scheduled-trash-retention --preview-token ENABLE_TOKEN
upkit --non-interactive --json schedule trash-retention status
upkit --non-interactive --json schedule trash-retention preview-disable
upkit --non-interactive --yes --json schedule trash-retention disable \
  --authorize-scheduled-trash-retention --preview-token DISABLE_TOKEN
```

Disabling turns off the timer but does not stop a service that has already
started; it may finish. Removal requires the timer disabled and the service
inactive. It quarantines the exact two unit files before removing them, so a
failure can leave unit files under quarantine names or leave manager state
unverified. Review status and the manager before retrying:

```bash
upkit --non-interactive --json schedule trash-retention preview-remove
upkit --non-interactive --yes --json schedule trash-retention remove \
  --authorize-scheduled-trash-retention --preview-token REMOVE_TOKEN
```

Print version details:

```bash
upkit version
```

Update upkit itself:

```bash
upkit self-update
```

Standalone self-update runs the release installer and compares the binary with
that release's `SHA256SUMS` before replacing it; this does not independently
authenticate the release. Cargo installations continue using Cargo.
In an interactive terminal, the command opens a Ratatui preview. You can also
press `U` on the Toolchains screen. The preview identifies the program and
operation; it must fit on screen before confirmation. The selected executable
can still change at the same path after review. Non-interactive use retains the
existing `--yes` requirement.
You can also update a standalone installation by running its installer again.

Generate shell completions:

```bash
upkit completions bash
upkit completions zsh
```

## Common Flags

```bash
upkit check --json
upkit update --dry-run
upkit update --offline
upkit update --no-progress
upkit update --yes
upkit check --only rust
upkit check --timeout 30
upkit check --retries 3
upkit check --quiet
upkit check -v
upkit check -vv
upkit check --no-color
```

During `--dry-run`, toolchain checks do not run installed tool executables or
Rustup, because those programs can write files. Installed versions may therefore
be reported as unknown, and an update plan may need a normal check before it can
identify the exact action. Release metadata may still be fetched unless offline
mode is enabled.

In offline mode, Upkit skips its network requests and does not run Go, Rust or
Flutter version commands that can bootstrap or download toolchains. Their
installed versions may be unknown; managed Windows Flutter metadata can still
be read locally. Other external executables may have their own network behavior,
so `--offline` is not a network sandbox.

## Paths

```bash
upkit paths
```

Override locations:

```bash
upkit check --home ~/.local/share/upkit
upkit check --bindir ~/.local/bin
```

## Publishing standalone releases

After the implementation and release checks are complete, choose a new version
that does not already exist on the remote. Update `Cargo.toml` and the lockfile,
commit the verified changes, and push a matching tag. Replace `X.Y.Z` with that
new version:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

The standalone release workflow checks the tag against `Cargo.toml` and refuses
an existing GitHub Release, then runs the format, build, Clippy, Rust, installer,
and Linux terminal checks, builds all six targets, and publishes the binaries,
`install.sh`, `install.ps1`, and `SHA256SUMS` to GitHub Releases. It does not
publish to npm. It accepts stable `vMAJOR.MINOR.PATCH` tags only; prerelease and
build-metadata tags are rejected because the standalone installers accept only
numeric three-part versions. Tag builds are serialized, and publication checks
that the latest release has not changed during the build.
Linux ARM64 tests and release smoke checks run on a native ARM64 runner.
Some terminal removal tests require Git and isolated user/PID namespaces; the
test reports when they are unavailable and skipped.
For a manual rerun before publication, select the matching version tag when
running the workflow. Once the release exists, the workflow refuses to replace it.
