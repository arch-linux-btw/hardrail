"""Identity and access checks: accounts, passwords and sudo. Read-only."""

import os
import re
from dataclasses import dataclass

from hardrail.models import Category, Check, CheckResult, Severity, Status

PASSWD_PATH = "/etc/passwd"
SHADOW_PATH = "/etc/shadow"
SUDOERS_PATH = "/etc/sudoers"
SUDOERS_DIR = "/etc/sudoers.d"
LOGIN_DEFS_PATH = "/etc/login.defs"

SYSTEM_UID_LIMIT = 1000
NON_LOGIN_SHELLS = ("nologin", "false", "sync", "shutdown", "halt")
MAX_PASSWORD_DAYS_LIMIT = 365


@dataclass
class PasswdEntry:
    name: str
    uid: int
    shell: str


@dataclass
class ShadowEntry:
    name: str
    password: str  # the hash field: never put it in a report


# File helpers ------------------------------------------------------------


def run_file_check(path, evaluate):
    """Read a text file and hand its content to `evaluate`.

    Shared by the checks that read a single file, so a missing or
    unreadable file is handled in one place only.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except FileNotFoundError:
        return CheckResult(Status.SKIPPED, reason=path + " not found")
    except OSError as error:
        return CheckResult(
            Status.ERROR, reason="cannot read " + path + ": " + str(error)
        )

    return evaluate(text)


def parse_passwd(text):
    """Parse /etc/passwd into PasswdEntry objects, skipping malformed lines."""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        try:
            uid = int(fields[2])
        except ValueError:
            continue
        entries.append(PasswdEntry(name=fields[0], uid=uid, shell=fields[6]))
    return entries


def parse_shadow(text):
    """Parse /etc/shadow into ShadowEntry objects, skipping malformed lines."""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        entries.append(ShadowEntry(name=fields[0], password=fields[1]))
    return entries


def parse_login_defs(text):
    """Parse /etc/login.defs into a dict. The last occurrence of a key wins."""
    defs = {}
    for line in text.splitlines():
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            defs[parts[0]] = parts[1].strip()
    return defs


# USR-001 -----------------------------------------------------------------


def evaluate_uid_zero(entries):
    """PASS only when root is the single account with UID 0."""
    if len(entries) == 0:
        return CheckResult(Status.ERROR, reason="no accounts found in passwd data")

    extra = []
    for entry in entries:
        if entry.uid == 0 and entry.name != "root":
            extra.append(entry.name)

    if len(extra) == 0:
        return CheckResult(Status.PASS, evidence="root is the only account with UID 0")
    else:
        return CheckResult(
            Status.FAIL,
            evidence="accounts with UID 0 besides root: " + ", ".join(extra),
        )


def check_uid_zero():
    return run_file_check(
        PASSWD_PATH, lambda text: evaluate_uid_zero(parse_passwd(text))
    )


# USR-002 -----------------------------------------------------------------


def evaluate_empty_passwords(entries):
    """PASS when no account has an empty password field.

    Locked accounts ('!', '*', '!!') are fine: only a truly empty field
    means "no password needed". The evidence lists names, never hashes.
    """
    if len(entries) == 0:
        return CheckResult(Status.ERROR, reason="no accounts found in shadow data")

    empty = []
    for entry in entries:
        if entry.password == "":
            empty.append(entry.name)

    if len(empty) == 0:
        return CheckResult(
            Status.PASS,
            evidence="no account with an empty password (" + str(len(entries)) + " checked)",
        )
    else:
        return CheckResult(
            Status.FAIL,
            evidence="accounts with an empty password: " + ", ".join(empty),
        )


def check_empty_passwords():
    return run_file_check(
        SHADOW_PATH, lambda text: evaluate_empty_passwords(parse_shadow(text))
    )


# USR-003 -----------------------------------------------------------------


def logical_lines(text):
    """Join lines that end with a backslash, as sudoers allows."""
    lines = []
    current = ""
    for raw in text.splitlines():
        if raw.endswith("\\"):
            current += raw[:-1] + " "
            continue
        current += raw
        lines.append(current)
        current = ""
    if current != "":
        lines.append(current)
    return lines


def find_nopasswd_rules(text):
    """Return the sudoers rules (comments excluded) that use the NOPASSWD tag."""
    rules = []
    for line in logical_lines(text):
        stripped = line.strip()
        if stripped == "" or stripped.startswith("#"):
            continue
        if re.search(r"\bNOPASSWD\s*:", stripped):
            rules.append(" ".join(stripped.split()))
    return rules


def read_sudoers_files():
    """Return [(path, text)] for sudoers and the files in sudoers.d.

    Like sudo itself, skip files in sudoers.d whose name contains a dot or
    ends with '~'. Raises OSError if a file cannot be read.
    """
    paths = [SUDOERS_PATH]
    if os.path.isdir(SUDOERS_DIR):
        for name in sorted(os.listdir(SUDOERS_DIR)):
            if "." in name or name.endswith("~"):
                continue
            full_path = os.path.join(SUDOERS_DIR, name)
            if not os.path.isfile(full_path):
                continue
            paths.append(full_path)

    files = []
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            files.append((path, handle.read()))
    return files


def evaluate_sudoers(files):
    """PASS when none of the given sudoers files has a NOPASSWD rule."""
    findings = []
    for path, text in files:
        for rule in find_nopasswd_rules(text):
            findings.append(path + ": " + rule)

    if len(findings) == 0:
        return CheckResult(
            Status.PASS,
            evidence="no NOPASSWD rules in " + str(len(files)) + " sudoers file(s)",
        )
    else:
        return CheckResult(Status.FAIL, evidence="; ".join(findings))


def check_sudo_nopasswd():
    if not os.path.exists(SUDOERS_PATH):
        return CheckResult(
            Status.SKIPPED, reason=SUDOERS_PATH + " not found (sudo not installed?)"
        )

    try:
        files = read_sudoers_files()
    except OSError as error:
        return CheckResult(
            Status.ERROR, reason="cannot read sudoers files: " + str(error)
        )

    return evaluate_sudoers(files)


# USR-005 -----------------------------------------------------------------


def evaluate_password_max_days(defs):
    """PASS when PASS_MAX_DAYS is between 1 and MAX_PASSWORD_DAYS_LIMIT."""
    value = defs.get("PASS_MAX_DAYS")

    if value is None:
        return CheckResult(
            Status.FAIL,
            evidence="PASS_MAX_DAYS is not set (passwords never expire by default)",
        )

    try:
        number = int(value)
    except ValueError:
        return CheckResult(
            Status.ERROR, reason="unexpected PASS_MAX_DAYS value: " + value
        )

    if number >= 1 and number <= MAX_PASSWORD_DAYS_LIMIT:
        return CheckResult(Status.PASS, evidence="PASS_MAX_DAYS = " + value)
    else:
        return CheckResult(Status.FAIL, evidence="PASS_MAX_DAYS = " + value)


def check_password_max_days():
    return run_file_check(
        LOGIN_DEFS_PATH,
        lambda text: evaluate_password_max_days(parse_login_defs(text)),
    )


# USR-006 -----------------------------------------------------------------


def has_login_shell(shell):
    """True when the shell lets the account log in interactively."""
    if shell == "":
        return True
    name = os.path.basename(shell)
    if name in NON_LOGIN_SHELLS:
        return False
    else:
        return True


def evaluate_system_shells(entries):
    """PASS when no system account (UID 1 to 999) has a login shell."""
    if len(entries) == 0:
        return CheckResult(Status.ERROR, reason="no accounts found in passwd data")

    offenders = []
    for entry in entries:
        if entry.uid > 0 and entry.uid < SYSTEM_UID_LIMIT:
            if has_login_shell(entry.shell):
                if entry.shell == "":
                    shell_text = "empty shell field"
                else:
                    shell_text = entry.shell
                offenders.append(entry.name + " (" + shell_text + ")")

    if len(offenders) == 0:
        return CheckResult(
            Status.PASS, evidence="no system account has a login shell"
        )
    else:
        return CheckResult(
            Status.FAIL,
            evidence="system accounts with a login shell: " + ", ".join(offenders),
        )


def check_system_shells():
    return run_file_check(
        PASSWD_PATH, lambda text: evaluate_system_shells(parse_passwd(text))
    )


# The engine discovers checks through this list. USR-004 is reserved. ------

CHECKS = [
    Check(
        id="USR-001",
        title="Only root has UID 0",
        category=Category.IDENTITY,
        severity=Severity.CRITICAL,
        run=check_uid_zero,
        reference="CIS Linux benchmark, user accounts section (root is the only UID 0 account)",
        requires_root=False,
        remediation=(
            "Investigate the extra UID 0 account (it is a common backdoor), "
            "then remove it or give it a unique UID."
        ),
    ),
    Check(
        id="USR-002",
        title="No account has an empty password",
        category=Category.IDENTITY,
        severity=Severity.HIGH,
        run=check_empty_passwords,
        reference="CIS Linux benchmark, user accounts section (empty password fields)",
        requires_root=True,
        remediation=(
            "Lock the account with 'passwd -l <user>' or set a strong "
            "password with 'passwd <user>'."
        ),
    ),
    Check(
        id="USR-003",
        title="No sudo rule uses NOPASSWD",
        category=Category.IDENTITY,
        severity=Severity.HIGH,
        run=check_sudo_nopasswd,
        reference="Common sudo hardening guidance (require authentication)",
        requires_root=True,
        remediation=(
            "Remove the NOPASSWD tag from the rule using 'visudo' (never edit "
            "sudoers with a plain editor), unless the rule is strictly required."
        ),
    ),
    Check(
        id="USR-005",
        title="Password maximum age is 365 days or less",
        category=Category.IDENTITY,
        severity=Severity.LOW,
        run=check_password_max_days,
        reference="CIS Linux benchmark, password aging (PASS_MAX_DAYS)",
        requires_root=False,
        remediation=(
            "Set 'PASS_MAX_DAYS 365' (or lower) in /etc/login.defs. This only "
            "affects new accounts: use 'chage -M 365 <user>' for existing ones."
        ),
    ),
    Check(
        id="USR-006",
        title="System accounts have no login shell",
        category=Category.IDENTITY,
        severity=Severity.LOW,
        run=check_system_shells,
        reference="CIS Linux benchmark, user accounts section (system accounts)",
        requires_root=False,
        remediation=(
            "Set a non-login shell with 'usermod -s /usr/sbin/nologin <user>' "
            "unless the account really needs to log in."
        ),
    ),
]
