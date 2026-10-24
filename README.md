# upkit

![Coverage](https://github.com/christiandoxa/upkit/actions/workflows/coverage.yml/badge.svg)

One CLI to check and update Go, Rust, Node, Python, Flutter, and Mojo toolchains.

## Features

- Unified `check`, `update`, and `clean` commands for multiple toolchains.
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

To install a specific release or choose a different directory:

```bash
curl -fsSL https://github.com/christiandoxa/upkit/releases/latest/download/install.sh |
  sh -s -- --release v0.4.15 --install-dir "$HOME/.local/bin"
```

### Windows

Run in PowerShell:

```powershell
irm https://github.com/christiandoxa/upkit/releases/latest/download/install.ps1 | iex
```

The installer detects x64 or ARM64, verifies `SHA256SUMS`, and installs to
`%LOCALAPPDATA%\upkit\bin`. It adds that directory to your user `PATH`; open a new
terminal if an existing terminal does not find `upkit`. Administrator access is
not required.

To choose a release or install directory, set these variables before running
the installer:

```powershell
$env:UPKIT_RELEASE = 'v0.4.15'
$env:UPKIT_INSTALL_DIR = "$env:LOCALAPPDATA\upkit\bin"
irm https://github.com/christiandoxa/upkit/releases/latest/download/install.ps1 | iex
```

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

The action downloads a verified standalone binary from GitHub Releases and adds
the CLI to `PATH`.

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

Check installed versions and status:

```bash
upkit check
```

Full help output:

```bash
$ upkit help
Check and update Go/Rust/Node/Python/Flutter/Mojo

Usage: upkit [OPTIONS] [COMMAND]

Commands:
  check        Show installed version + latest version + status
  update       Update tools (interactive by default) [aliases: install]
  clean        Remove managed tool installs and symlinks
  uninstall    Uninstall managed tool installs and symlinks
  doctor       Diagnose common setup problems and provide fixes
  version      Print version details
  completions  Generate shell completions
  self-update  Update upkit itself
  paths        Print where upkit stores installs and symlinks
  help         Print this message or the help of the given subcommand(s)

Options:
      --json               Print JSON instead of pretty text
  -y, --yes                Assume "yes" for prompts (non-interactive)
  -v, --verbose...         Increase verbosity (-v, -vv)
  -q, --quiet              Suppress non-error output
      --no-color           Disable ANSI colors
      --dry-run            Don't perform actions; only show what would happen
      --no-progress        Disable progress indicators
      --offline            Disable network access (skip latest checks and downloads)
      --timeout <TIMEOUT>  Network timeout in seconds [default: 60]
      --retries <RETRIES>  Retry failed network requests this many times [default: 2]
      --only <ONLY>        Limit which tools to operate on [possible values: go, rust, node, python, flutter, mojo]
      --home <HOME>        Where upkit stores tool installs (default: ~/.local/share/upkit)
      --bindir <BINDIR>    Where upkit places symlinks (default: ~/.local/bin)
  -h, --help               Print help
  -V, --version            Print version
```

Run without a subcommand defaults to `check`:

```bash
upkit
```

Update tools interactively:

```bash
upkit update
```

The `install` alias runs the same command:

```bash
upkit install
```

Interactive selection uses letter codes (comma-separated), for example:

```bash
# Choose items shown as a), b), c), ...
upkit update
# Input example: a,c,f
```

Update a specific tool:

```bash
upkit update go
upkit update rust
upkit update node
upkit update python
upkit update flutter
upkit update mojo
```

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

Diagnose common setup problems:

```bash
upkit doctor
```

Print version details:

```bash
upkit version
```

Update upkit itself:

```bash
upkit self-update
```

Standalone installations update from GitHub Releases, verifying the checksum
before replacing the running binary. Cargo installations continue using Cargo.
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

Set the version in `Cargo.toml`, commit the change, and push a matching tag:

```bash
git tag v0.4.15
git push origin v0.4.15
```

The standalone release workflow checks the tag against `Cargo.toml`, runs the
tests, builds all six targets, and publishes the binaries, `install.sh`,
`install.ps1`, and `SHA256SUMS` to GitHub Releases. It does not publish to npm.
For a manual rerun, select the matching version tag when running the workflow.
