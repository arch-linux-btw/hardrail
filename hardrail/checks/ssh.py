"""SSH server checks. Everything here is read-only."""

import os
import shutil
import stat
import subprocess

from hardrail.models import Category, Check, CheckResult, Severity, Status

SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
SSHD_CANDIDATE_PATHS = ["/usr/sbin/sshd", "/usr/bin/sshd"]
MAX_AUTH_TRIES_LIMIT = 4


class SshdError(Exception):
    """Raised when the effective sshd configuration cannot be read."""


def find_sshd():
    """Return the path of the sshd binary, or None if it is not installed."""
    path = shutil.which("sshd")
    if path is None:
        for candidate in SSHD_CANDIDATE_PATHS:
            if os.path.exists(candidate):
                path = candidate
                break
    return path


def read_sshd_config(sshd_path):
    """Run `sshd -T` and return its raw output (the effective configuration)."""
    completed = subprocess.run(
        [sshd_path, "-T"], capture_output=True, text=True, timeout=10
    )
    if completed.returncode != 0:
        raise SshdError(completed.stderr.strip())
    return completed.stdout


def parse_sshd_output(output):
    """Turn lines like 'permitrootlogin no' into {'permitrootlogin': 'no'}."""
    config = {}
    for line in output.splitlines():
        line = line.strip()
        if line == "":
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        if len(parts) == 2:
            value = parts[1]
        else:
            value = ""
        config[key] = value
    return config


def run_sshd_check(evaluate):
    """Read the effective sshd configuration and hand it to `evaluate`.

    Shared by every check based on `sshd -T`, so the handling of a missing
    sshd, a failing sshd and a timeout lives in one place only.
    """
    sshd_path = find_sshd()
    if sshd_path is None:
        return CheckResult(Status.SKIPPED, reason="sshd is not installed")

    try:
        output = read_sshd_config(sshd_path)
    except SshdError as error:
        return CheckResult(Status.ERROR, reason="sshd -T failed: " + str(error))
    except subprocess.TimeoutExpired:
        return CheckResult(Status.ERROR, reason="sshd -T timed out")
    except OSError as error:
        return CheckResult(Status.ERROR, reason="cannot run sshd: " + str(error))

    return evaluate(parse_sshd_output(output))


def evaluate_directive_equals(config, key, expected):
    """PASS when the directive equals `expected`, FAIL for any other value.

    A missing directive is an ERROR: `sshd -T` prints every directive with
    its default, so a missing one means something unexpected happened and we
    must not report a false PASS.
    """
    value = config.get(key)

    if value is None:
        return CheckResult(
            Status.ERROR,
            reason=key + " not found in sshd -T output",
        )
    elif value.lower() == expected:
        return CheckResult(Status.PASS, evidence=key + " = " + value)
    else:
        return CheckResult(Status.FAIL, evidence=key + " = " + value)


# SSH-001 ---------------------------------------------------------------


def evaluate_root_login(config):
    """PASS only when PermitRootLogin is exactly 'no'.

    'prohibit-password' (the OpenSSH default) is a FAIL: CIS asks for 'no'.
    """
    return evaluate_directive_equals(config, "permitrootlogin", "no")


def check_root_login():
    return run_sshd_check(evaluate_root_login)


# SSH-002 ---------------------------------------------------------------


def evaluate_password_auth(config):
    """PASS only when password authentication is disabled (keys only)."""
    return evaluate_directive_equals(config, "passwordauthentication", "no")


def check_password_auth():
    return run_sshd_check(evaluate_password_auth)


# SSH-003 ---------------------------------------------------------------


def evaluate_empty_passwords(config):
    """PASS only when accounts with an empty password cannot log in."""
    return evaluate_directive_equals(config, "permitemptypasswords", "no")


def check_empty_passwords():
    return run_sshd_check(evaluate_empty_passwords)


# SSH-004 ---------------------------------------------------------------


def evaluate_config_permissions(mode, uid, gid):
    """PASS when the file is owned by root:root with mode 600 or stricter."""
    mode_bits = stat.S_IMODE(mode)
    evidence = (
        "mode "
        + format(mode_bits, "03o")
        + ", owner "
        + str(uid)
        + ":"
        + str(gid)
    )

    if uid != 0 or gid != 0:
        return CheckResult(Status.FAIL, evidence=evidence + " (expected owner 0:0)")
    elif mode_bits & 0o177 != 0:
        return CheckResult(
            Status.FAIL, evidence=evidence + " (expected mode 600 or stricter)"
        )
    else:
        return CheckResult(Status.PASS, evidence=evidence)


def check_config_permissions():
    """SSH-004: read the permissions of sshd_config (no root needed)."""
    try:
        info = os.stat(SSHD_CONFIG_PATH)
    except FileNotFoundError:
        return CheckResult(Status.SKIPPED, reason=SSHD_CONFIG_PATH + " not found")
    except OSError as error:
        return CheckResult(
            Status.ERROR, reason="cannot read " + SSHD_CONFIG_PATH + ": " + str(error)
        )

    return evaluate_config_permissions(info.st_mode, info.st_uid, info.st_gid)


# SSH-005 ---------------------------------------------------------------


def evaluate_max_auth_tries(config):
    """PASS when MaxAuthTries is MAX_AUTH_TRIES_LIMIT or lower."""
    value = config.get("maxauthtries")

    if value is None:
        return CheckResult(
            Status.ERROR, reason="maxauthtries not found in sshd -T output"
        )

    try:
        number = int(value)
    except ValueError:
        return CheckResult(
            Status.ERROR, reason="unexpected maxauthtries value: " + value
        )

    if number <= MAX_AUTH_TRIES_LIMIT:
        return CheckResult(Status.PASS, evidence="maxauthtries = " + value)
    else:
        return CheckResult(Status.FAIL, evidence="maxauthtries = " + value)


def check_max_auth_tries():
    return run_sshd_check(evaluate_max_auth_tries)


# SSH-006 ---------------------------------------------------------------


def evaluate_x11_forwarding(config):
    """PASS only when X11 forwarding is disabled."""
    return evaluate_directive_equals(config, "x11forwarding", "no")


def check_x11_forwarding():
    return run_sshd_check(evaluate_x11_forwarding)


# The engine discovers checks through this list. -------------------------

CHECKS = [
    Check(
        id="SSH-001",
        title="SSH root login is disabled",
        category=Category.SSH,
        severity=Severity.HIGH,
        run=check_root_login,
        reference="CIS Linux benchmark, SSH server section (PermitRootLogin)",
        requires_root=True,
        remediation=(
            "Set 'PermitRootLogin no' in /etc/ssh/sshd_config "
            "(or a file in /etc/ssh/sshd_config.d/) and reload sshd."
        ),
    ),
    Check(
        id="SSH-002",
        title="SSH password authentication is disabled",
        category=Category.SSH,
        severity=Severity.MEDIUM,
        run=check_password_auth,
        reference="Common SSH hardening guidance (key-based login only)",
        requires_root=True,
        remediation=(
            "Make sure key-based login works first, or you may lock yourself "
            "out. Then set 'PasswordAuthentication no' and reload sshd."
        ),
    ),
    Check(
        id="SSH-003",
        title="SSH empty passwords are not permitted",
        category=Category.SSH,
        severity=Severity.HIGH,
        run=check_empty_passwords,
        reference="CIS Linux benchmark, SSH server section (PermitEmptyPasswords)",
        requires_root=True,
        remediation="Set 'PermitEmptyPasswords no' and reload sshd.",
    ),
    Check(
        id="SSH-004",
        title="sshd_config is owned by root with mode 600 or stricter",
        category=Category.SSH,
        severity=Severity.MEDIUM,
        run=check_config_permissions,
        reference="CIS Linux benchmark, SSH server section (sshd_config access)",
        requires_root=False,
        remediation=(
            "Run 'chown root:root /etc/ssh/sshd_config' and "
            "'chmod 600 /etc/ssh/sshd_config'."
        ),
    ),
    Check(
        id="SSH-005",
        title="SSH MaxAuthTries is 4 or less",
        category=Category.SSH,
        severity=Severity.LOW,
        run=check_max_auth_tries,
        reference="CIS Linux benchmark, SSH server section (MaxAuthTries)",
        requires_root=True,
        remediation="Set 'MaxAuthTries 4' (or lower) and reload sshd.",
    ),
    Check(
        id="SSH-006",
        title="SSH X11 forwarding is disabled",
        category=Category.SSH,
        severity=Severity.LOW,
        run=check_x11_forwarding,
        reference="CIS Linux benchmark, SSH server section (X11Forwarding)",
        requires_root=True,
        remediation="Set 'X11Forwarding no' and reload sshd.",
    ),
]
