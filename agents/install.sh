#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
codex_home="${CODEX_HOME:-$HOME/.codex}"
skill_dir="$codex_home/skills/agent-keychain"
hook_dir="$codex_home/hooks"

mkdir -p "$skill_dir" "$hook_dir"
cp "$repo_root/agents/skills/agent-keychain/SKILL.md" "$skill_dir/SKILL.md"
cp "$repo_root/agents/hooks/agent-keychain-secret-access.sh" "$hook_dir/agent-keychain-secret-access.sh"
cp "$repo_root/agents/hooks/agent-keychain-secret-access.ps1" "$hook_dir/agent-keychain-secret-access.ps1"
chmod +x "$hook_dir/agent-keychain-secret-access.sh"

printf 'Installed Agent Keychain agent access assets:\n'
printf -- '- Skill: %s\n' "$skill_dir/SKILL.md"
printf -- '- Shell hook: %s\n' "$hook_dir/agent-keychain-secret-access.sh"
printf -- '- PowerShell hook: %s\n' "$hook_dir/agent-keychain-secret-access.ps1"
printf '\nAgents can discover eligible names with `akc agent-search`, then request values through the hook or `akc agent-get`; both paths remain audited.\n'
