# Security policy

## Supported versions

Only the latest published release receives security fixes. Older releases are
unsupported; upgrade before reporting an issue that may already be fixed.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** button on this repository's Security
tab when it is available. That opens a private GitHub Security Advisory report
visible only to the reporter and repository maintainers.

Do not disclose exploit details, secrets, or proof-of-concept code in a public
issue. If private vulnerability reporting is not available, the project does
not currently document another private reporting channel. You may open a
public issue containing only a request for a private contact method and no
sensitive details.

Please include the affected version and operating system, impact, reproduction
conditions, and any suggested mitigation. Never include real credentials or
vault contents.

## Security model and limits

Agent Keychain encrypts vault data at rest and limits local access through its
daemon and approval flow. It does not protect against an attacker who can:

- control the user's account or execute code with equivalent privileges;
- inspect the process memory of an unlocked client or daemon;
- replace the executable, configuration, vault, socket, or approval UI;
- capture a secret after it has been released to an approved process; or
- compromise the operating system, release pipeline, or dependencies.

The project is a local secret-access tool, not a remote secret manager or a
hardware-backed keystore. Backups and host hardening remain the user's
responsibility.
