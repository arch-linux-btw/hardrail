# Test report: Ubuntu Server

Manual test of hardrail on a fresh Ubuntu Server virtual machine, with a few extra services and accounts added so that it looks like a real server. The tool was installed following the instructions in the README (clone, virtual environment, `pip install -e .`).

## Environment

| Item | Value |
|---|---|
| Distro | Ubuntu Server 24.04 (fresh install) |
| Virtualization | VirtualBox VM |
| hardrail version | 0.1.0 |
| Date | 2026-10-16 |
| Install method | README: `git clone`, `python3 -m venv .venv`, `pip install -e .` |
| Extra packages | `python3-venv`, `git`, `nginx`, `mariadb-server`, `fail2ban`, `ufw` |
| Extra accounts | `deploy` (regular user in the `sudo` group), `myapp` (system account with `/usr/sbin/nologin`) |

`apt update` was run before the scan: PKG-001 relies on the local apt package lists and is skipped when they are old.

## Runs

| Run | Command | PASS | FAIL | SKIPPED | ERROR | Evaluated | Coverage | Score |
|---|---|---|---|---|---|---|---|---|
| 1 | `hardrail scan` (no root) | 7 | 3 | 9 | 0 | 10/19 | 54.2% | 87.2 |
| 2 | `sudo env PYTHONDONTWRITEBYTECODE=1 .venv/bin/hardrail scan` | 11 | 8 | 0 | 0 | 19/19 | 100.0% | 75.0 |

Without root, the 9 skipped checks are FS-002, FS-003, SSH-001, SSH-002, SSH-003, SSH-005, SSH-006, USR-002 and USR-003, each with the reason "requires root privileges". Run 2 is the only complete assessment: all 19 checks evaluated, no skipped, no errors.

## Findings (run 2)

| Check | Points lost | Evidence | Comment |
|---|---|---|---|
| SSH-001 | -6.9 | `permitrootlogin = prohibit-password` | OpenSSH default, same as on Arch (open point 1) |
| FS-003 | -4.2 | 2 setuid files: `/usr/bin/ntfs-3g` and a helper under `/usr/lib/mysql/plugin/auth_pam_tool_dir/` | Both legitimate, see below (open point 2) |
| SSH-002 | -4.2 | `passwordauthentication = yes` | Default |
| SSH-004 | -4.2 | mode 644, owner 0:0 | Ubuntu default |
| FS-005 | -1.4 | `/tmp` mounted without `noexec` | `/tmp` was already a separate mount with `nodev,nosuid` (open point 3) |
| SSH-005 | -1.4 | `maxauthtries = 6` | Default |
| SSH-006 | -1.4 | `x11forwarding = yes` | Ubuntu default; this check passes on Arch |
| USR-005 | -1.4 | `PASS_MAX_DAYS = 99999` | Ubuntu sets it explicitly in `/etc/login.defs` |

## What works as expected

- No crashes, no ERROR.
- Checks that need root are skipped with a clear reason, and the report says to re-run with sudo.
- PKG-001..003 are evaluated on Ubuntu (they are skipped on Arch) and pass on a fresh installation.
- The added accounts did not cause false positives: USR-001, USR-002, USR-003 and USR-006 pass, including with `deploy` in the `sudo` group (a password is required) and with `myapp` as a service account.
- Every FAIL is either an Ubuntu default (a correct finding against a hardening baseline) or comes from the software added to the server (FS-003).

## Open points

Each of these should become a GitHub issue. The points that also appear on Arch are described in more detail in `arch-linux.md`.

1. **SSH-001, `prohibit-password`.** Same as on Arch: it is the OpenSSH default, and it is the check that costs the most points on a default Ubuntu installation. Decide whether it deserves a lower severity than `PermitRootLogin yes`.
2. **FS-003, legitimate setuid binaries.** Two real examples on this server: `ntfs-3g` and the PAM helper shipped with MariaDB, both setuid by design. On Arch the same check flagged `ksu`. Three different packages in two distros show that fixed rules are not enough: this is the case for the allowlist already planned in the README roadmap.
3. **FS-005, fix message.** `/tmp` was already a separate mount here too, with only `noexec` missing, but the fix text suggests mounting it as its own filesystem.
4. **Partial score.** Run 1 gives 87.2 and run 2 gives 75.0 on the same machine, because the score only counts evaluated checks. The report states that the score is partial, but a lower score after a more complete scan can still be misleading.

## Negative cases still to verify

An earlier test on a deliberately weakened Ubuntu Server 24.04 VM (before the final fixes of v0.1.0) gave 13 FAIL, 6 PASS and a score of 33.3. It showed a false positive on `/usr/bin/sudo.ws` in FS-003 (fixed) and left some checks unverified in the negative case: FS-004, PKG-001, PKG-002, PKG-003, USR-003 and USR-006. PKG-002 was never really exercised, because the test installed the `telnet` client and not a `telnetd` server package. A fresh installation like this one cannot verify them either, since they all pass: the next step is a re-test on a weakened VM with the final v0.1.0.
