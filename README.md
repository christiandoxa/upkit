# upkit

![Coverage](https://github.com/christiandoxa/upkit/actions/workflows/coverage.yml/badge.svg)

One CLI to check and update Go, Rust, Node, Python, and Flutter toolchains.

## Features

- Unified `check`, `update`, and `clean` commands for multiple toolchains.
- Hybrid model: uses native installers when available and direct downloads when needed.
- JSON output for scripting and integrations.
- Offline and dry-run modes for safe previews.

## Install

From crates.io:

```bash
cargo install upkit
```

From source:

```bash
git clone https://github.com/christiandoxa/upkit.git
cd upkit
cargo install --path .
```

## Usage

Check installed versions and status:

```bash
upkit check
```

Full help output:

```bash
$ upkit help
Check and update Go/Rust/Node/Python/Flutter

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
      --only <ONLY>        Limit which tools to operate on [possible values: go, rust, node, python, flutter]
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
```

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
