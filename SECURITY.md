# Security Policy

## Current behavior: read-only

hardrail 0.1.x only reads the state of the system and prints a report. It does
not change files, permissions, users, services or packages, and it applies no
fixes. The fix hints in the report are plain text.

The only file writes you may see come from Python itself, which can create
`__pycache__` folders next to the source code when it runs as root. Run with
`PYTHONDONTWRITEBYTECODE=1` to avoid them.

## Planned: fixes with guardrails

The name comes from *hardening* and *guardrail*: hardrail is meant to grow from
assessment into hardening, with a safety net. When fixes are added, they will
follow these rules:

- Opt-in only: a scan never changes anything, and fixes need an explicit command
- Dry-run by default: you see what would change before anything is applied
- A snapshot of the affected state is taken before every change, with a way to
  roll back
- High-risk fixes are never applied automatically

This policy will be updated before the first release that can modify the
system. Until then, any write to the system by hardrail is a bug.

### What hardrail reads and runs

Because hardrail is meant to run as root, here is exactly what it touches today:

- Files read: `/etc/passwd`, `/etc/shadow` (only to find empty password
  fields; hashes are never printed), `/etc/sudoers` and `/etc/sudoers.d/`,
  `/etc/login.defs`, `/etc/apt/apt.conf.d/`, `/proc/self/mounts`
- Metadata read (no file contents): permissions and ownership of
  `/etc/ssh/sshd_config` and of the files and directories under `/etc`,
  `/usr`, `/opt`, `/home`, `/var`, `/tmp`; the apt package list timestamps
- Commands run: `sshd -T` (prints the effective SSH configuration),
  `apt-get -s dist-upgrade` (a simulation: nothing is installed) and
  `dpkg-query -W` (lists installed packages)

Nothing is sent over the network.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| Older | No |

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private reporting instead: open the **Security** tab of this
repository and click **Report a vulnerability**. Include:

- the hardrail version (`hardrail --version`) and your operating system
- the steps to reproduce the problem
- what you expected and what happened, and the impact you see

hardrail is maintained by one student, so replies are best-effort: I aim to
acknowledge a report within 7 days and to fix confirmed problems in the next
release.

## What counts as a security issue

In scope:

- hardrail writes, deletes or changes anything on the system (apart from the
  Python bytecode caches described above)
- A command or path injection (for example data read from a system file ends
  up executed)
- Sensitive data in the output, such as password hashes
- A crash or hang that can be triggered by crafted system files
- Once fixes exist: a change applied without an explicit request, or a
  snapshot that cannot be restored

Out of scope (please open a normal issue instead):

- False positives or false negatives of a check
- Missing checks or unsupported distributions
- Vulnerabilities in the tools hardrail calls (`sshd`, `apt`, `dpkg`)