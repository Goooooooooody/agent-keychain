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
- Agents do not receive blanket access. Each request is approved or denied by the user unless a
  time- and use-bounded grant matches its OS principal, client label, and secret name.
- Requests and approvals are written to the vault audit log.


## Homebrew

Install from the project tap:

```sh
brew tap Goooooooooody/agent-keychain https://github.com/Goooooooooody/agent-keychain.git
brew install --cask Goooooooooody/agent-keychain/agent-keychain
```

The cask installs a prebuilt Apple Silicon macOS binary and does not require Xcode or Cargo.
Homebrew links `akc` into its prefix automatically. A release containing the desktop companion
will also link `akc-tray` after the cask version and checksum are updated for that release.

If your shell cannot find `akc` after installation, add Homebrew to your PATH:

```sh
echo 'eval "$(brew shellenv)"' >> ~/.zprofile
eval "$(brew shellenv)"
```

## Windows

Windows is supported for the CLI, encrypted vault operations, TUI, daemon, and agent request flow. The daemon uses Windows named pipes through the same local IPC abstraction that maps to Unix domain sockets on macOS/Linux.

For now, install from a tagged GitHub release artifact or build from source with Rust:

```powershell
cargo install --git https://github.com/Goooooooooody/agent-keychain.git --tag v0.2.0
```

The command remains `akc.exe` on Windows. Releases containing the desktop companion also include
`akc-tray.exe`.

## Desktop tray approvals

`akc-tray` runs the daemon as a menu-bar app on macOS, a system-tray app on Linux, and a
notification-area app on Windows. It starts the daemon locked, sends native notifications for
secret requests, and opens a trusted approval dialog showing the agent label, secret name, reason,
command context, and OS-reported process ID. Secret values and capability tokens are never shown in
notifications or dialogs.

Launch it after installing a release archive:

```sh
akc-tray
```

The tray menu provides **Start daemon**, **Unlock**, **Lock**, **Stop daemon**, and **Launch at
login** controls. Approval dialogs default to denial and time out after 60 seconds. Starting the
tray companion replaces an already-running terminal daemon so the trusted tray process becomes the
approval provider.

Linux requires a desktop notification service, Zenity or KDialog, GTK 3, XDo, and AppIndicator.
For Debian or Ubuntu:

```sh
sudo apt install zenity libgtk-3-0 libxdo3 libayatana-appindicator3-1
```

To install both binaries from source:

```sh
cargo install --path . --features tray --bins
```

## Basic usage

```sh
akc init
akc add --name secret-for-thing
akc get --name secret-for-thing
akc list
akc remove --name secret-for-thing
```

Secrets can carry versioned, non-secret lifecycle metadata:

```sh
akc add --name deploy-token --tags prod,deploy --expires-at 2026-12-31T23:59:59Z \
  --rotate-after 2026-10-01T00:00:00Z --allow-client codex --notes 'production deploy' \
  --url https://example.invalid/tokens
akc add --name bootstrap-code --one-time
```

Expired secrets are never returned. A one-time secret is deleted atomically after its first
successful read. Allowed clients are exact self-reported labels and are useful policy selectors,
but MUST NOT be interpreted as verified executable identity. `akc list` displays lifecycle status
and tags, never values. Existing `{}` metadata migrates automatically to metadata version 1.

The convenience form is supported:

```sh
akc --add 'secret-key-value' --name 'secret-for-thing'
```

Prefer `akc add --name ...` instead. Inline secrets can be captured by shell history.


## Agent installation

You can ask your agent to install Agent Keychain support from this repository. If you do, the installer will automatically create both:

- an agent skill at `~/.codex/skills/agent-keychain/SKILL.md`
- an agent hook at `~/.codex/hooks/agent-keychain-secret-access.*`

That hook does **not** bypass security. It provides audited fuzzy name discovery through
`akc agent-search` and wraps `akc agent-get`, so value requests still go through daemon approval or
an explicit scoped grant.

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

Start the local approval daemon directly, or use `akc-tray` for visible desktop approvals and
lifecycle controls:

```sh
akc daemon
```

Then an agent/client can request a one-time secret read:

```sh
akc agent-get --name secret-for-thing --agent codex --reason 'deploy token needed'
```

If the exact name is unknown, the agent can fuzzy-search eligible secret names without retrieving
values:

```sh
akc agent-search --query 'github production' --agent codex \
  --reason 'find the deployment credential' --json
```

Search requires an unlocked daemon and a query of at least two characters. It returns at most ten
non-expired names whose `allowed_clients` policy permits the supplied agent label. It never returns
values, tags, notes, URLs, or capability tokens. Every search is audited with the OS-reported peer
PID, agent label, query, reason, and match count. Agent labels remain self-reported policy selectors,
not verified executable identities.

Multiple `--name` values form a batch with one approval prompt:

```sh
akc agent-get --name api-key db-password --agent codex --reason deploy
```

A user denial denies the whole batch. After approval, expiry, one-time, allowed-label and existence
checks are applied independently: permitted values are returned while denied items are reported,
the command exits non-zero if any item failed, and exactly one outcome audit event is stored per
item. Batch stdout uses `name=value`; do not redirect it to an untrusted destination.

The daemon prompts the user before returning the secret.

For commands that accept a secret on standard input, avoid printing it or placing it in argv or the
environment:

```sh
akc exec --secret secret-for-thing -- command --flag
```

This reserves the child's standard input for the secret and closes it after delivery. The child may
still disclose what it reads; `akc` cannot enforce the behavior of another executable.

Daemon lifecycle commands never display secret data:

```sh
akc daemon status
akc lock                 # also available as: akc daemon lock
akc daemon unlock
akc daemon stop
akc config idle-lock 900 # applied after daemon restart
```

Set `AKC_METRICS=1` when starting the daemon to include privacy-safe aggregate counters in
`akc daemon status` (latency, lock wait, queue rejection/timeouts, vault bytes and archive count).
Metrics never contain secret values, names, labels, reasons, command context, or paths.

The daemon keeps the decrypted vault and its derived encryption key in zeroizing memory while it is
unlocked. Normal audited requests reuse that key but encrypt every new vault generation with a fresh
nonce, avoiding another Argon2 run and disk reload per request. Manual lock, idle timeout (15 minutes
by default), graceful stop, and process shutdown drop the session. The on-disk vault format remains
version 1 and is backward compatible; no migration is required.

## Temporary auto-approve grants

Auto-approval is disabled by default and can only be enabled from an interactive terminal after
re-entering the vault passphrase. The command prints a random capability token exactly once; the
daemon stores only its digest. A grant is exact-match scoped to a client label and secret, has a use
limit, exists only in the running daemon, and expires (five minutes by default, fifteen minutes
maximum):

```sh
akc config auto-approve enable --client codex --secret secret-for-thing --ttl-seconds 300 --max-uses 1
export AKC_GRANT_TOKEN='<the one-time output>'
akc config auto-approve status
akc config auto-approve disable
```

Older persistent `auto_approve_agent_requests` configuration is ignored and cleared when the daemon
starts. When a temporary grant is active, the daemon returns requested secrets without prompting,
but still writes audit entries for the request, fetch, approval mode, agent label, and reason.

IPC access is limited to the daemon's OS user on Unix. A scoped grant is authorized only by its
unguessable capability token plus exact selectors. Agent names, executable identity, and request context remain
client-supplied labels; they are sanitized for terminal/audit output and MUST NOT be treated as a
verified executable identity. Where supported, the audit PID is replaced with the OS-reported peer PID.
Requests are newline-framed and limited to 16 KiB. Non-interactive IPC operations have five-second
I/O timeouts; an interactive secret request has a 60-second response window.
Protocol version 2 adds random request IDs and structured error codes for retry-safe correlation.
On Windows, endpoint access relies on the named pipe ACL inherited from the daemon process. Tray
approval decisions travel over an in-process channel owned by the daemon's approval provider; no
public IPC command can approve a pending request.

## Vault persistence and audit rotation

Vault mutations use a cross-process lock and revision check, then replace the encrypted file through
a unique same-directory temporary file. The previous valid encrypted generation is retained as
`vault.bak` for recovery when the primary is missing. Unix replacements and parent-directory syncs
are atomic; platforms without atomic replacement use the safest available synced replacement.

The encrypted vault keeps the newest 1,000 audit events. Older events are moved, without deletion,
into individually authenticated encrypted chunks under `vault.audit.d/`. Automatic retention is
intentionally not implemented yet: deleting an archive would silently weaken the audit history.
Archive deletion is available only through the verified export-and-prune workflow below.
Events contain predecessor digests and the encrypted vault authenticates the live head and total
count, so missing, reordered, or modified chained archives are rejected before reads and
maintenance. Legacy version-1 chunks remain readable as an explicitly recognized unchained prefix;
`akc rekey` rewrites that prefix into the chained format.

## Rekey, backup, restore, and audit management

These maintenance commands coordinate with a running daemon by locking and clearing its cached
session first. Unlock the daemon again explicitly after maintenance.

```sh
akc rekey --memory-kib 65536 --iterations 3 --parallelism 1
akc backup --output vault.akc-backup
akc restore --input vault.akc-backup --verify

akc audit list --since 2026-01-01T00:00:00Z --actor codex --secret deploy-token --decision approve
akc audit export --output audit.json
akc audit prune --verified-export audit.json
```

`rekey` requests a new passphrase (automation may use `AKC_NEW_MASTER_PASSPHRASE`), validates KDF
bounds, verifies the new encrypted generation, and retains the prior encrypted generation as the
rollback backup. `backup` creates and reopens an authenticated encrypted bundle containing the
vault and rotated audit archives. `restore --verify` authenticates and validates bundle/file
versions before replacement and rolls back the prior generation on write failure. If a backup uses
a different passphrase, set `AKC_BACKUP_PASSPHRASE` for restore.

Audit export includes live and rotated events and never includes secret values. Archive pruning is
refused unless the supplied versioned export is parseable and covers every archived event; a
checkpoint event is persisted after pruning. Existing format-1 vaults and protocol-v2 clients remain
compatible; metadata defaults are applied during deserialization and no eager migration is needed.

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
