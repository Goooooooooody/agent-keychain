# Agent installation

Agent Keychain can install agent-facing assets that teach an AI agent how to request secrets safely.

## What gets installed

Running the installer creates:

- `~/.codex/skills/agent-keychain/SKILL.md` — agent instructions for secret requests.
- `~/.codex/hooks/agent-keychain-secret-access.sh` — shell helpers for audited name discovery and `akc agent-get`.
- `~/.codex/hooks/agent-keychain-secret-access.ps1` — PowerShell helpers for audited name discovery and `akc agent-get`.

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

Agents should use `akc agent-get` or the installed hook. They should not use `akc get`. When an
agent needs multiple known secrets, it should request them together with multiple `--name` values,
`akc_secret_get_many`, or `Get-AkcSecrets` so the user receives one approval prompt.
If the exact name is unknown, they should fuzzy-search eligible names through `akc agent-search`
instead of guessing or repeatedly requesting names.

Shell:

```sh
source "${CODEX_HOME:-$HOME/.codex}/hooks/agent-keychain-secret-access.sh"
akc_secret_search "github production" "find the deployment credential"
akc_secret_get secret-for-thing "explain why this task needs the secret"
```

PowerShell:

```powershell
. "$env:USERPROFILE\.codex\hooks\agent-keychain-secret-access.ps1"
Find-AkcSecret -Query "github production" -Reason "find the deployment credential"
Get-AkcSecret -Name "secret-for-thing" -Reason "explain why this task needs the secret"
```

Searches go through the unlocked local daemon, return at most ten non-expired names eligible for
the agent label, require at least two query characters, and are audited. They never return secret
values or descriptive metadata. Secret retrieval still requires normal daemon approval or an
explicit scoped grant and is audited with the agent label and reason.
