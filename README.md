# Agent Keychain (`akc`)

Open Source - A Secure way for agents to request secrets.

`akc` is a local-first, terminal-managed encrypted keychain designed for humans and agents.

V1 is entirely run on your machine - I intend to extend this project to connect to a self-hosted backend but I don't want to bundle that by default as not everybody has the same desire. A future release may contain a small update to add a connection tool but it will be disabled by default.

This project is intended to be long-term software that will not be bloated with features or monetized in any way.

The only updates this tool will recieve is the above mentioned connector, and security updates.

## Security model

- Vaults are encrypted by default.
- V1 is local-only: no cloud service and no network listener.
- Agent access goes through a local IPC daemon: Unix domain sockets on macOS/Linux and named pipes on Windows.
- Agents do not receive blanket access. Each request is approved or denied by the user unless auto-approval is explicitly enabled.
- Requests and approvals are written to the vault audit log.


## Homebrew

Install from the project tap:

```sh
brew tap Goooooooooody/agent-keychain https://github.com/Goooooooooody/agent-keychain.git
brew install --cask Goooooooooody/agent-keychain/agent-keychain
```

The cask installs a prebuilt Apple Silicon macOS binary and does not require Xcode or Cargo. Homebrew links `akc` into its prefix automatically.

If your shell cannot find `akc` after installation, add Homebrew to your PATH:

```sh
echo 'eval "$(brew shellenv)"' >> ~/.zprofile
eval "$(brew shellenv)"
```

## Windows

Windows is supported for the CLI, encrypted vault operations, TUI, daemon, and agent request flow. The daemon uses Windows named pipes through the same local IPC abstraction that maps to Unix domain sockets on macOS/Linux.

For now, install from a tagged GitHub release artifact or build from source with Rust:

```powershell
cargo install --git https://github.com/Goooooooooody/agent-keychain.git --tag v0.1.2
```

The command remains `akc.exe` on Windows.

## Basic usage

```sh
akc init
akc add --name secret-for-thing
akc get --name secret-for-thing
akc list
akc remove --name secret-for-thing
```

The convenience form is supported:

```sh
akc --add 'secret-key-value' --name 'secret-for-thing'
```

Prefer `akc add --name ...` instead. Inline secrets can be captured by shell history.


## Agent installation

You can ask your agent to install Agent Keychain support from this repository. If you do, the installer will automatically create both:

- an agent skill at `~/.codex/skills/agent-keychain/SKILL.md`
- an agent hook at `~/.codex/hooks/agent-keychain-secret-access.*`

That hook does **not** bypass security. It wraps `akc agent-get`, so requests still go through daemon approval or explicit auto-approval config, and fetches are still audited with the agent label and reason.

Install manually if preferred:

```sh
bash agents/install.sh
```

On Windows PowerShell:

```powershell
.\agents\install.ps1
```

See [`agents/README.md`](agents/README.md) for details.

## Agent access

Start the local approval daemon:

```sh
akc daemon
```

Then an agent/client can request a one-time secret read:

```sh
akc agent-get --name secret-for-thing --agent codex --reason 'deploy token needed'
```

The daemon prompts the user before returning the secret.

## Auto-approve agent requests

Auto-approval is disabled by default. Enable it only when you trust the local agent/session:

```sh
akc config auto-approve enable
akc config auto-approve status
akc config auto-approve disable
```

When enabled, the daemon returns requested secrets without prompting, but still writes audit entries for the request, fetch, approval mode, agent label, and reason.

## TUI

```sh
akc tui
```

The TUI shows secret names and audit history without rendering secret values.

## Environment variables

- `AKC_VAULT_PATH`: override the default vault path.
- `AKC_CONFIG_PATH`: override the default config path.
- `AKC_SOCKET_PATH`: override the default Unix socket path.
- `AKC_MASTER_PASSPHRASE`: non-interactive passphrase, intended for tests only.
