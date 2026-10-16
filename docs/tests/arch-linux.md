# Test report: Arch Linux

Manual test of hardrail on a fresh Arch Linux virtual machine, installed the way a normal user would install it (not as a developer).

## Environment

| Item | Value |
|---|---|
| Distro | Arch Linux (fresh install) |
| Kernel | 7.2.9-arch1-1 |
| Virtualization | VirtualBox VM |
| hardrail version | v0.1.0 |
| Date | 2026-10-16 |
| Install method | `pipx install` from the GitHub repository |
| Extra packages | `python`, `python-pipx`, `git`, `sudo`, `openssh` |

## Install notes

- Arch blocks system-wide `pip install` (PEP 668), so `pipx` is the right way to install the tool.
- After `pipx ensurepath` the terminal must be reopened, otherwise `hardrail` returns "command not found" because `~/.local/bin` is not yet in `PATH`.
- `sudo hardrail` does not find the command for the same reason. Use `sudo "$(which hardrail)" scan`.

## Runs

| Run | Command | PASS | FAIL | SKIPPED | ERROR | Evaluated | Coverage | Score |
|---|---|---|---|---|---|---|---|---|
| 1 | `hardrail scan` (no root) | 3 | 4 | 12 | 0 | 7/19 | 36.1% | 76.9 |
| 2 | with sudo, `sshd` never started | 6 | 5 | 3 | 5 | 11/19 | 61.1% | 79.5 |
| 3 | with sudo, `sshd` running | 8 | 8 | 3 | 0 | 16/19 | 81.9% | 69.5 |

The score is computed only on evaluated checks, so scores from runs with different coverage are not comparable (see open point 6).

## What works as expected

- No crashes in any run.
- Without root, checks that need it are skipped with a clear reason, and the report tells the user to re-run with sudo.
- PKG-001..003 are skipped on Arch with an explicit message (`apt-get` / `dpkg-query` not found, Debian/Ubuntu only).
- SSH-001..006 correctly report ERROR when `sshd -T` fails (no host keys yet) and are evaluated correctly once `sshd` has been started.
- The remaining SSH findings match OpenSSH defaults (`PasswordAuthentication yes`, `MaxAuthTries 6`), so they are real findings against a hardening baseline, not false positives.

## Open points

Each of these should become a GitHub issue.

1. **SSH-001, `prohibit-password`.** The effective value is the OpenSSH default. Root login with a password is blocked, but root login with a key is still allowed. The check reports FAIL with severity high (the biggest penalty in the run). Decide whether `prohibit-password` should have a lower severity than `yes`, or keep the strict CIS-style behaviour and document it.
2. **USR-006, `git-shell`.** The account `git` has `/usr/bin/git-shell` as its shell, and the check flags it. `git-shell` is a restricted shell meant for Git-only accounts. Decide whether it should be treated differently from a normal login shell.
3. **FS-003, `/usr/bin/ksu`.** A setuid binary flagged as unexpected. Decide between an allowlist for known packages and leaving it as a finding for the user to review.
4. **FS-005, fix message.** `/tmp` was already mounted separately (as a tmpfs with `nodev,nosuid`), and only `noexec` was missing. The fix text suggests mounting `/tmp` as its own filesystem, which is misleading in this case. The message should depend on the actual state.
5. **PKG-001..003 on Arch.** Add `pacman` support, or keep the checks Debian/Ubuntu only and document it. On Arch this limits coverage to 16/19.
6. **Partial score.** The score changes with coverage (76.9, then 79.5, then 69.5 on the same machine), which can look like the system got less secure after doing a more complete scan. Decide how to present this, for example by showing coverage next to the score or by marking partial scores more clearly.

## Known limitations on Arch (v0.1.0)

- PKG-001..003 are not supported (skipped by design).
- A full assessment requires root, and `sshd` must be installed and have host keys for the SSH checks to run.
- Several findings (SSH-004, USR-005) correspond to Arch defaults, so a fresh installation will show them as FAIL.
