# Agent installation

Agent Keychain can install agent-facing assets that teach an AI agent how to request secrets safely.

## What gets installed

Running the installer creates:

- `~/.codex/skills/agent-keychain/SKILL.md` — agent instructions for secret requests.
- `~/.codex/hooks/agent-keychain-secret-access.sh` — shell helper for `akc agent-get`.
- `~/.codex/hooks/agent-keychain-secret-access.ps1` — PowerShell helper for `akc agent-get`.

Set `CODEX_HOME` to install somewhere other than `~/.codex`.

## Install from this repo

macOS/Linux:

```sh
bash agents/install.sh
```

Windows PowerShell:

```powershell
.\agents\install.ps1
```

## How agents should request secrets

Agents should use `akc agent-get` or the installed hook. They should not use `akc get`.

Shell:

```sh
source "${CODEX_HOME:-$HOME/.codex}/hooks/agent-keychain-secret-access.sh"
akc_secret_get secret-for-thing "explain why this task needs the secret"
```

PowerShell:

```powershell
. "$env:USERPROFILE\.codex\hooks\agent-keychain-secret-access.ps1"
Get-AkcSecret -Name "secret-for-thing" -Reason "explain why this task needs the secret"
```

The request still goes through the local daemon. If auto-approval is disabled, the user must approve it. If auto-approval is enabled, the request is still audited with the agent label and reason.
