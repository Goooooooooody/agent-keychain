---
name: agent-keychain
description: >
  Discover and request secrets from Agent Keychain without bypassing policy, user approval, or audit logging.
  Trigger: When an agent needs to find or use a password, API token, credential, key, or secret stored in akc.
license: Apache-2.0
metadata:
  author: goody
  version: "1.3"
---

## When to Use

Use this skill when a task requires a secret that may be stored in Agent Keychain (`akc`).

## Critical Patterns

- NEVER ask the user to paste a secret into chat if `akc` can provide it.
- NEVER use `akc get` for agent access. That is the direct human CLI path.
- If the exact secret name is unknown, use `akc agent-search` or the installed search helper. Do not guess repeatedly or enumerate names.
- Search queries MUST contain at least two characters and SHOULD include meaningful service, environment, or purpose terms.
- Search returns eligible secret names only—never values, notes, URLs, or capability tokens. Results are bounded and audited.
- ALWAYS request the selected secret with `akc agent-get` or the installed hook wrapper.
- When multiple secrets are known up front, request them together as one batch. Do not create avoidable sequential approval prompts.
- ALWAYS include a concrete reason with the request.
- Treat returned secrets as ephemeral: use once, do not store in files, logs, memory notes, commits, or summaries.
- If the daemon is locked, continue with the normal `agent-get` request: the desktop tray can prompt
  the user to unlock the vault and then show the approval dialog. Do not ask the user to paste a
  passphrase or try to unlock the vault through another path.
- If the tray/provider is unavailable, the daemon cannot unlock interactively, or access is denied,
  tell the user exactly what failed and stop; never work around the approval flow.
- Some secrets may have an explicit per-secret auto-approval policy. This is still audited and scoped
  to the requested client label and secret; do not assume it applies to other secrets or agents.

## Commands

Find an eligible secret name without retrieving its value:

```bash
akc agent-search --query "<service environment purpose>" --agent "${AKC_AGENT_NAME:-agent}" --reason "<why this task needs discovery>" --json
```

Request a secret directly:

```bash
akc agent-get --name <secret-name> --agent "${AKC_AGENT_NAME:-agent}" --reason "<why this task needs it>"
```

Request 2–64 secrets with one approval prompt:

```bash
akc agent-get --name <secret-one> <secret-two> [<secret-three> ...] --agent "${AKC_AGENT_NAME:-agent}" --reason "<why this task needs them>"
```

Batch output uses `name=value`. Each item is audited and checked independently; treat every returned value as ephemeral.

When using the desktop tray, a locked-vault request may produce two user prompts in sequence: unlock
the vault, then approve the secret request. A cancelled or failed unlock must be reported as a
failure; do not retry repeatedly.

Using the installed shell hook:

```bash
source "${CODEX_HOME:-$HOME/.codex}/hooks/agent-keychain-secret-access.sh"
akc_secret_search "github production" "find the deployment credential"
akc_secret_get <secret-name> "<why this task needs it>"
akc_secret_get_many "<why this task needs them>" <secret-one> <secret-two> [<secret-three> ...]
```

Using the installed PowerShell hook:

```powershell
. "$env:USERPROFILE\.codex\hooks\agent-keychain-secret-access.ps1"
Find-AkcSecret -Query "github production" -Reason "find the deployment credential"
Get-AkcSecret -Name "<secret-name>" -Reason "<why this task needs it>"
Get-AkcSecrets -Name "<secret-one>", "<secret-two>" -Reason "<why this task needs them>"
```

## Resources

- Agent install docs: `agents/README.md`
- Shell hook: `agents/hooks/agent-keychain-secret-access.sh`
- PowerShell hook: `agents/hooks/agent-keychain-secret-access.ps1`
