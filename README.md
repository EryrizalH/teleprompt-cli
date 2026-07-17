# Teleprompt CLI

A secure, agent-friendly remote execution and connection manager for SSH and Telnet.

<div align="center">
  <p>
    <a href="https://www.npmjs.com/package/teleprompt-cli"><img src="https://img.shields.io/npm/v/teleprompt-cli.svg?style=flat-square&color=blue" alt="NPM Version" /></a>
    <a href="https://github.com/EryrizalH/teleprompt-cli/actions"><img src="https://img.shields.io/github/actions/workflow/status/EryrizalH/teleprompt-cli/release.yml?branch=main&style=flat-square" alt="Build Status" /></a>
    <a href="https://github.com/EryrizalH/teleprompt-cli/blob/main/LICENSE"><img src="https://img.shields.io/github/license/EryrizalH/teleprompt-cli.svg?style=flat-square" alt="License" /></a>
  </p>
</div>

---

> [!WARNING]
> **DO NOT use Teleprompt CLI in "Yolo mode" (fully autonomous mode without human confirmation/supervision) on AI agents.**
> The author/maintainer assumes no responsibility for any operating system damage, data loss, or misconfigurations caused by the execution of AI agents. Always verify agent actions in a sandbox or require explicit human approval before execution.

---

Teleprompt CLI allows developers and AI agents to connect to and execute commands on remote servers, switches, and other devices via SSH or Telnet. It stores credentials locally in an encrypted database, keeping passwords and private keys secure and preventing them from leaking into shell histories or LLM context prompts.

---

## Key Features

* **SSH Auto-Discovery & Import**: Detect hosts from `~/.ssh/config`, correlate them with `~/.ssh/known_hosts`, test connectivity, and import confirmed devices into the encrypted store.
* **Cross-Platform Ed25519 Key Generation**: Create `~/.ssh/teleprompt_ed25519` and its public key without relying on an external `ssh-keygen` executable or overwriting existing keys.
* **Zero-Exposure Credentials**: All device credentials (passwords, private keys, passphrases) are encrypted locally using AES-256-GCM (Argon2id key derivation) in a local database (`~/.teleprompt/credentials.enc`).
* **Bypass Interactive Prompts**: Load the `TELEPROMPT_KEY` environment variable in your automation or AI agent context to retrieve credentials and execute commands without interactive password prompts.
* **Encrypted SSH Key Support**: Use password-protected SSH private keys — Teleprompt now prompts for and securely stores the key passphrase alongside the key path.
* **Host Key Verification**: Prevents MITM attacks by verifying server host keys against a local `known_hosts` file. Three policies: `Strict`, `AcceptNew` (default), or `Off`.
* **Automatic Sudo Password Injection**: Detects remote `sudo` prompts automatically and securely injects the sudo password to prevent script hangs.
* **SSH and Telnet Support**: Connect to modern SSH servers (passwords or private keys with optional passphrase) and legacy Telnet systems.
---

## Installation

### NPM (Recommended)
Install globally to make the `teleprompt` command available system-wide:
```bash
npm install -g teleprompt-cli
```
*Note: The installer automatically downloads the precompiled binary for your operating system and architecture. If a precompiled binary is not available, it compiles from source using Cargo.*

### Cargo (Rust)
Compile from source:
```bash
cargo install --git https://github.com/EryrizalH/teleprompt-cli.git
```

---

## Quick Start Guide

### Step 1: Initialize the Secure Store
Initialize the database and configure your master password:
```bash
teleprompt init
```
This creates the encrypted store at `~/.teleprompt/credentials.enc`. Keep your master password safe; it is required to decrypt your credentials.

### Step 2: Set the Master Password Environment Variable
Export your master password to run commands non-interactively (ideal for automation and AI agent workflows):

* **Linux / macOS:**
  ```bash
  export TELEPROMPT_KEY="your-master-password"
  ```
* **Windows (PowerShell):**
  ```powershell
  $env:TELEPROMPT_KEY="your-master-password"
  ```

### Step 3: Add a Remote Device
Register a new remote device configuration interactively:
```bash
teleprompt add
```

### Step 4: List Registered Devices
List your configured remote devices (passwords and private keys are masked):
```bash
teleprompt list
```

### Step 5: Execute Remote Commands
Run commands on your registered devices:
```bash
# Run a single command
teleprompt <device-name> uname -a

# Run chained commands (enclosed in quotes)
teleprompt <device-name> "cd /var/log && cat syslog | tail -n 20"
```

---

## Command Reference

| Command | Description |
| :--- | :--- |
| `teleprompt init` | Initialize the secure encrypted credential database. |
| `teleprompt add` | Interactively register a new remote device (SSH/Telnet). |
| `teleprompt import` | Detect SSH config hosts and confirm each import interactively. |
| `teleprompt import --all` | Select all discovered hosts while retaining required prompts. |
| `teleprompt import --all --yes` | Import non-interactively; skip incomplete, untrusted, or failed devices. |
| `teleprompt generate-key` | Safely generate the default Teleprompt Ed25519 key pair. |
| `teleprompt list` | View all registered devices. |
| `teleprompt remove <name>` | Delete a device configuration. |
| `teleprompt edit <name>` | Interactively modify a device configuration. |
| `teleprompt test <name>` | Test connectivity and credential validation. |
| `teleprompt install-skill` | Copy the AI Agent instructions (`TELEPROMPT_SKILL.md`) to the current directory. |
| `teleprompt <name> <command...>` | Run a command on the remote device. |

`--all --yes` requires every candidate to match an unhashed OpenSSH `known_hosts` entry and uses strict host-key verification. The SSH config parser accepts literal values for the supported fields; wildcard blocks and advanced OpenSSH token expansion are intentionally outside this initial scope.

### Global Options
* `--timeout <seconds>`: Override execution timeout (default is `30` seconds).
* `--verbose` / `-v`: Print detailed connection diagnostics (TCP, handshake, auth stages).
* `--db-path <path>`: Specify a custom database path (default is `~/.teleprompt/credentials.enc`).

Example:
```bash
teleprompt --verbose --timeout 60 --db-path ./custom.db my-device "df -h"
```

---

## Security Details

### Auto-Sudo Prompt Interception
When running remote commands, Teleprompt monitors stream outputs. If it detects a password prompt (e.g. `[sudo] password for ...:`), it automatically sends the stored sudo password (or connection password if no separate sudo password is set) followed by a newline, avoiding interactive hangs.

### Encryption Standards
* **Key Derivation**: Key derived from your Master Password using Argon2id.
* **Cipher**: AES-256-GCM encrypts and decrypts the credential database.
* **Memory Safety**: Sensitive credentials and keys are zeroed out of memory when no longer needed using the `zeroize` Rust crate.

---

## AI Agent Integration Guidelines

If you are equipping an AI agent (such as Claude Code, ChatGPT, or Gemini) with this tool, you can install the agent-specific instructions (`TELEPROMPT_SKILL.md`) in your workspace automatically by running:

```bash
teleprompt install-skill
```

This will create `TELEPROMPT_SKILL.md` in the current directory, which instructs the AI agent on how to:
- Detect the target operating system using `teleprompt list`.
- Adapt its command syntax based on the OS Type (Linux, Windows, RouterOS, Cisco IOS, JunOS).
- Run commands securely and process stdout/stderr and exit codes programmatically.

> [!WARNING]
> **Disclaimer on AI Agent Execution:**
> Never allow AI agents to run commands in fully autonomous "Yolo mode" without human supervision and explicit approval. The author/maintainer of Teleprompt CLI is not responsible for any system damage, configuration issues, or data loss resulting from commands executed by AI agents.

> [!TIP]
> **Quick AI Agent Tips:**
> - To check configured servers and their OS types, run `teleprompt list`.
> - Ensure the `TELEPROMPT_KEY` environment variable is loaded in your execution context before running commands.
> - When running commands with pipes (`|`), redirects (`>`), or multiple instructions, group them in a single string, e.g., `teleprompt server-name "command1 && command2 | grep foo"`.
> - Check exit codes: a non-zero exit code represents a remote command failure or connection loss.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
