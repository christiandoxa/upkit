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
