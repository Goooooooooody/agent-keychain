# Agent Keychain (`akc`)

Open Source - A Secure way for agents to request secrets.

`akc` is a local-first, terminal-managed encrypted keychain designed for humans and agents.

## Security model

- Vaults are encrypted by default.
- V1 is local-only: no cloud service and no network listener.
- Agent access goes through a Unix socket daemon.
- Agents do not receive blanket access. Each request is approved or denied by the user unless auto-approval is explicitly enabled.
- Requests and approvals are written to the vault audit log.

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
