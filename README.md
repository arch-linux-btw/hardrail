# hardrail

**Read-only risk assessment for Linux servers.**

> hardrail 0.1 only reads: it does not modify your system. Fixes with
> snapshots and rollback are planned for future versions.

hardrail runs on the machine it audits and checks user accounts, file
permissions, installed packages and SSH configuration. It turns the findings
into a risk score where every lost point is explained, with the evidence it
found and a hint on how to fix it.

The name comes from *hardening* and *guardrail*: the goal is to harden a
server with a safety net.

## What it checks

19 checks in four areas. Each check has a stable ID, a severity and, when it
fails, the evidence and a remediation hint (text only: version 0.1 does not
apply fixes).

| ID | Check | Severity | Needs root |
|---|---|---|---|
| SSH-001 | SSH root login is disabled | high | yes |
| SSH-002 | SSH password authentication is disabled | medium | yes |
| SSH-003 | SSH empty passwords are not permitted | high | yes |
| SSH-004 | sshd_config is owned by root with mode 600 or stricter | medium | no |
| SSH-005 | SSH MaxAuthTries is 4 or less | low | yes |
| SSH-006 | SSH X11 forwarding is disabled | low | yes |
| USR-001 | Only root has UID 0 | critical | no |
| USR-002 | No account has an empty password | high | yes |
| USR-003 | No sudo rule skips the password prompt | high | yes |
| USR-005 | Password maximum age is 365 days or less | low | no |
| USR-006 | System accounts have no login shell | low | no |
| FS-001 | Critical account files have correct ownership and permissions | high | no |
| FS-002 | No world-writable files or unprotected directories in system paths | high | yes |
| FS-003 | No unexpected setuid/setgid files | medium | yes |
| FS-004 | Sticky bit is set on world-writable temp directories | high | no |
| FS-005 | /tmp is a separate mount with nodev, nosuid and noexec | low | no |
| PKG-001 | No security updates are pending | high | no |
| PKG-002 | No insecure network service packages are installed | high | no |
| PKG-003 | Automatic security updates are enabled | medium | no |

## Requirements

**To install and run**

- Linux and Python 3.10 or newer, with the `venv` module (on Debian/Ubuntu:
  `sudo apt install python3-venv`)
- Git, to clone the repository (or download the ZIP from GitHub)
- Internet access during installation, to download the build tool
  (`setuptools`)
- Root privileges (`sudo`) for a complete scan. Without root, the checks that
  need it are reported as `SKIPPED`, never as `PASS`.

**Python dependencies**

hardrail has no runtime dependencies: it uses only the Python standard
library. `pytest` is needed only for development (see
[Development](#development)).

**System tools used by the checks**

hardrail calls these tools when they are present. If one is missing, the
checks that need it are reported as `SKIPPED`.

| Tool | Used by | Package on Debian/Ubuntu |
|---|---|---|
| `sshd` | SSH-001, SSH-002, SSH-003, SSH-005, SSH-006 | `openssh-server` |
| `apt-get` | PKG-001 | `apt` |
| `dpkg-query` | PKG-002, PKG-003 | `dpkg` |

The package checks (`PKG-*`) support Debian and Ubuntu only. On other
distributions they are reported as `SKIPPED`.

**Tested on**

Ubuntu Server 24.04 (full scan) and Arch Linux. On Arch the package checks
(`PKG-*`) were reported as `SKIPPED`, because it does not use `apt`.

## Installation

```bash
git clone https://github.com/arch-linux-btw/hardrail.git
cd hardrail
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```bash
hardrail scan                  # text report
hardrail scan --format json    # same report as JSON
hardrail scan --no-color       # plain text, no colors
hardrail --version
```

`sudo` does not see the virtual environment, so call the command by its full
path for a complete scan:

```bash
sudo env PYTHONDONTWRITEBYTECODE=1 .venv/bin/hardrail scan
```

`PYTHONDONTWRITEBYTECODE=1` stops Python from writing `__pycache__` files as
root inside the project folder.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No `FAIL` and no `ERROR` |
| 1 | At least one `FAIL` or `ERROR` |
| 2 | No command given (or invalid arguments) |

## How results are reported

| Status | Meaning |
|---|---|
| `PASS` | The condition was checked and is fine |
| `FAIL` | The condition was checked and is a problem; evidence and a fix hint are shown |
| `SKIPPED` | The check could not run here (no root, service or tool not installed, outdated data). It does not count in the score. |
| `ERROR` | The check itself failed. It is never turned into a `PASS`. |

**Score.** The score is the percentage of passed weight over the weight of the
evaluated checks (`PASS` and `FAIL`). Weights: low 1, medium 3, high 5,
critical 10. `SKIPPED` and `ERROR` checks are left out, and the report then
tells you the score is partial and shows the coverage. For every `FAIL`, the
report lists the points it cost.

Password hashes are never printed: account checks report names only.

## Example output

Abridged, from a deliberately weakened Ubuntu Server 24.04 virtual machine
(account and file names depend on your system):

```text
hardrail 0.1.0 - risk assessment
Running as root: yes

FAIL     SSH-001  high      SSH root login is disabled
    evidence: permitrootlogin = yes
    fix:      Set 'PermitRootLogin no' in /etc/ssh/sshd_config (or a file in /etc/ssh/sshd_config.d/) and reload sshd.
FAIL     USR-001  critical  Only root has UID 0
    evidence: accounts with UID 0 besides root: extrauser
    fix:      Investigate the extra UID 0 account (it is a common backdoor), then remove it or give it a unique UID.
PASS     FS-004   high      Sticky bit is set on world-writable temp directories
...

Summary: PASS 6 | FAIL 13 | SKIPPED 0 | ERROR 0
Score: 33.3/100 (evaluated 19 of 19 checks, coverage 100.0%)
Points lost:
  USR-001  critical  -13.9  Only root has UID 0
  FS-001   high      -6.9   Critical account files have correct ownership and permissions
  FS-002   high      -6.9   No world-writable files or unprotected directories in system paths
  ...
```

## JSON output

`hardrail scan --format json` prints the same information in a machine-readable
form, useful to compare two scans (for example before and after a manual fix).
Top-level keys: `tool`, `version`, `generated_at`, `running_as_root`,
`summary`, `score` (value, coverage, impacts) and `checks` (one entry per check
with id, title, category, severity, reference, status, evidence, reason and
remediation). Unlike the text report, the JSON also keeps the evidence of
passed checks.

## Limitations

hardrail v0.1.0 is a first version. Known limits:

- `SSH-004` checks only `sshd_config`, not the files in `sshd_config.d/`.
- `FS-003` and `USR-006` use fixed lists and system rules, so they can report
  false positives on systems with extra software (for example a legitimate
  setuid binary, or a service account that really has a shell). There is no
  configurable allowlist yet.
- `FS-003` matches set-id files by file name only.
- `USR-003` is not a full sudoers parser: it detects `NOPASSWD` and
  `Defaults !authenticate`, and a `NOPASSWD` written in a trailing comment on
  a rule line is reported as a rule.
- `PKG-001` relies on the local apt package lists. If they are older than 7
  days (or their age is unknown), and no security update is visible, the check
  is `SKIPPED` instead of `PASS`. Run `apt update` first.
- `PKG-003` recognises only the one-line form of `APT::Periodic` settings.
- The package checks work on Debian and Ubuntu only.
- Checks are independent: hardrail does not correlate findings.

## Roadmap

Ideas for future versions, roughly in priority order:

1. Configuration file: allowlists for `FS-003` and `USR-006`, disabling single
   checks, and an administrators list (the reserved `USR-004`).
2. More coverage: `sshd_config.d/` in `SSH-004`, legacy clients (telnet,
   rsh-client), listening services (`PKG-004`), network and firewall, kernel
   parameters (sysctl), logging and auditing.
3. Optional Lynis integration (import of its report when present).
4. Correlation of findings (for example passwordless sudo plus a weak SSH
   setup) and matching of installed packages to known CVEs.
5. Fixes with guardrails: opt-in commands, dry-run by default, a snapshot
   before every change with rollback, and high-risk fixes never applied
   automatically. These will be the first features that write to the
   system, so they will stay clearly separate from `scan`.
6. Support for other distributions (RHEL and derivatives).

## Development

```bash
pip install -e ".[dev]"
pytest
```

Each check lives in `hardrail/checks/` and is a function that only reads,
registered in the `CHECKS` list of its module. The engine discovers checks by
itself.

## Security

hardrail runs as root, so please read [SECURITY.md](SECURITY.md) to see what
it reads and how to report a problem.

## Acknowledgments

hardrail is a student project and builds on ideas from others. No code was
copied from any of them.

- [linux-security-checker](https://github.com/Arnavisnotsane/linux-security-checker)
  by Arnav (MIT): the modular layout with one module per area, the scoring
  that explains its reasons, and the environment awareness that skips checks
  that cannot run.
- [Lynis](https://cisofy.com/lynis/) by CISOfy: studied to understand how a
  security audit is organised, with stable test IDs, a hardening index and a
  machine-readable report.
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) by the Center
  for Internet Security: the reference for what a hardened Linux system
  should look like.

## AI assistance

hardrail was developed with the help of AI assistants:

- Claude (Anthropic): design discussion, code generation, code review and
  drafts of the documentation.
- Qwen3.5 9B (`qwen3.5:9b`), run locally through OpenCode: used briefly at
  the beginning of the project.


## License

MIT