$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME ".codex" }
$SkillDir = Join-Path $CodexHome "skills\agent-keychain"
$HookDir = Join-Path $CodexHome "hooks"

New-Item -ItemType Directory -Force -Path $SkillDir | Out-Null
New-Item -ItemType Directory -Force -Path $HookDir | Out-Null

Copy-Item (Join-Path $RepoRoot "agents\skills\agent-keychain\SKILL.md") (Join-Path $SkillDir "SKILL.md") -Force
Copy-Item (Join-Path $RepoRoot "agents\hooks\agent-keychain-secret-access.sh") (Join-Path $HookDir "agent-keychain-secret-access.sh") -Force
Copy-Item (Join-Path $RepoRoot "agents\hooks\agent-keychain-secret-access.ps1") (Join-Path $HookDir "agent-keychain-secret-access.ps1") -Force

Write-Host "Installed Agent Keychain agent access assets:"
Write-Host "- Skill: $SkillDir\SKILL.md"
Write-Host "- Shell hook: $HookDir\agent-keychain-secret-access.sh"
Write-Host "- PowerShell hook: $HookDir\agent-keychain-secret-access.ps1"
Write-Host ""
Write-Host "Agents can discover eligible names with 'akc agent-search', then request values through the hook or 'akc agent-get'; both paths remain audited."
