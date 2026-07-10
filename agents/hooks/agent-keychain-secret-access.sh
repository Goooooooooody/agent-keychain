#!/usr/bin/env bash
# Agent Keychain secret access hook.
# Source this file to get akc_secret_get and akc_secret_get_many, or execute it directly:
#   agent-keychain-secret-access.sh <secret-name> <reason>
#   agent-keychain-secret-access.sh batch <reason> <secret-name> [<secret-name> ...]
#   agent-keychain-secret-access.sh search <query> <reason>
set -euo pipefail

akc_secret_get() {
  if [ "$#" -lt 2 ]; then
    printf 'usage: akc_secret_get <secret-name> <reason>\n' >&2
    return 64
  fi

  local secret_name="$1"
  shift
  local reason="$*"
  local agent_name="${AKC_AGENT_NAME:-${USER:-agent}}"

  command -v akc >/dev/null 2>&1 || {
    printf 'akc is not installed or not on PATH\n' >&2
    return 127
  }

  akc agent-get --name "$secret_name" --agent "$agent_name" --reason "$reason"
}

akc_secret_get_many() {
  if [ "$#" -lt 3 ]; then
    printf 'usage: akc_secret_get_many <reason> <secret-name> <secret-name> [<secret-name> ...]\n' >&2
    return 64
  fi

  local reason="$1"
  shift
  local agent_name="${AKC_AGENT_NAME:-${USER:-agent}}"

  command -v akc >/dev/null 2>&1 || {
    printf 'akc is not installed or not on PATH\n' >&2
    return 127
  }

  akc agent-get --name "$@" --agent "$agent_name" --reason "$reason"
}

akc_secret_search() {
  if [ "$#" -lt 2 ]; then
    printf 'usage: akc_secret_search <query> <reason>\n' >&2
    return 64
  fi

  local query="$1"
  shift
  local reason="$*"
  local agent_name="${AKC_AGENT_NAME:-${USER:-agent}}"

  command -v akc >/dev/null 2>&1 || {
    printf 'akc is not installed or not on PATH\n' >&2
    return 127
  }

  akc agent-search --query "$query" --agent "$agent_name" --reason "$reason"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    search)
      shift
      akc_secret_search "$@"
      ;;
    batch)
      shift
      akc_secret_get_many "$@"
      ;;
    *)
      akc_secret_get "$@"
      ;;
  esac
fi
