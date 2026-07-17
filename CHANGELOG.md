# Changelog

## [0.3.0]

### Added
- **SSH auto-discovery and import**: New `teleprompt import` workflow reads literal hosts from `~/.ssh/config`, correlates matching unhashed `known_hosts` records, tests connectivity, and stores confirmed devices securely.
- **Safe automation flags**: `teleprompt import --all --yes` runs without prompts, requires matching unhashed `known_hosts` trust with strict verification, and skips incomplete or failed candidates.
- **Cross-platform Ed25519 generation**: New `teleprompt generate-key` creates `~/.ssh/teleprompt_ed25519` and `.pub` without external tools or overwriting existing files.
- **Initialization onboarding**: `teleprompt init` now offers opt-in key generation and SSH device import after creating the encrypted store.

### Changed
- Device connection testing and Linux sudo capability detection now share the same workflow between manual add and SSH import.

## [0.2.2] — 2026-07-07

### Fixed
- **Skip sudo detection for non-Linux devices**: Adding or editing SSH devices now checks sudo capability only when the selected OS is Linux. Non-Linux devices still run the normal connection test, but Teleprompt no longer executes sudo probes that can hang on unsupported platforms.

## [0.2.1] — 2026-06-14

### Changed
- **Real-time output streaming**: Output from command execution (SSH and Telnet) is now streamed to stdout and stderr in real-time instead of being buffered and printed at the end.
- **Removed execution timeout**: Command execution is no longer subject to the 30-second timeout. The `--timeout` flag is now strictly for connection establishment (TCP, SSH handshake, and login phases).
- **Sudo password prompt handling**: Kept prompt filtering internally, streaming only the actual command output after sudo authorization succeeds.

## [0.2.0] — 2026-06-13

### Added
- **SSH private key passphrase support**: `Device` now stores `key_passphrase` for encrypted SSH keys. Prompt during `add`/`edit`, auto-wired into `userauth_pubkey_file`. (`src/credentials.rs`, `src/ssh.rs`, `src/commands/add.rs`, `src/commands/edit.rs`)
- **Host key verification**: New `HostKeyPolicy` enum (`Strict`, `AcceptNew`, `Off`) on each device. Defaults to `AcceptNew` — auto-accepts new hosts, verifies known ones. Stored in `~/.teleprompt/known_hosts` (OpenSSH format). Mismatch triggers `HostKeyRejected` error (exit code 2). (`src/credentials.rs`, `src/ssh.rs`, `src/error.rs`, `src/commands/mod.rs`, `src/commands/add.rs`, `src/commands/edit.rs`)
- **Verbose/debug mode**: `--verbose`/`-v` global flag; prints `eprintln!` diagnostics at each connection stage (TCP connect → handshake → host key verify → auth). (`src/cli.rs`, `src/main.rs`, `src/ssh.rs`, `src/telnet.rs`, `src/commands/exec.rs`, `src/commands/test.rs`)
- **Auth column in `list`**: `list` command now shows per-device auth method: `password`, `key`, or `key (encrypted)`.

### Changed
- Test module rewritten with a shared `make_device()` helper — new fields (`key_passphrase`, `host_key_policy`) covered in all 4 test cases.
- `.gitignore` whitelists `CHANGELOG.md` alongside `README.md`.

## [0.1.3] — 2026-06-13

### Fixed
- SSH keyboard-interactive auth fallback & DNS resolution.

## [0.1.2] — 2026-06-12

### Fixed
- Sudo prompt counting bug in SSH command execution.

### Added
- Warning against autonomous agent YOLO mode in docs.
