"""SSH server checks. Everything here is read-only."""

import os
import shutil
import subprocess

from hardrail.models import Category, Check, CheckResult, Severity, Status


class SshdError(Exception):
    """Raised when the effective sshd configuration cannot be read."""


def find_sshd():
    """Return the path of the sshd binary, or None if it is not installed."""
    path = shutil.which("sshd")
    if path is None:
        if os.path.exists("/usr/sbin/sshd"):
            path = "/usr/sbin/sshd"
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


def evaluate_root_login(config):
    """Decide the CheckResult for SSH-001 from a parsed configuration.

    PASS only when PermitRootLogin is exactly 'no'. Any other value,
    including 'prohibit-password', is a FAIL (CIS asks for 'no').
    A missing directive is an ERROR: sshd -T should always print it, so
    something unexpected happened and we must not report a false PASS.
    """
    value = config.get("permitrootlogin")

    if value is None:
        return CheckResult(
            Status.ERROR,
            reason="permitrootlogin not found in sshd -T output",
        )
    elif value.lower() == "no":
        return CheckResult(Status.PASS, evidence="permitrootlogin = " + value)
    else:
        return CheckResult(Status.FAIL, evidence="permitrootlogin = " + value)


def check_root_login():
    """SSH-001: run sshd -T and evaluate the root login setting."""
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

    return evaluate_root_login(parse_sshd_output(output))


# The engine discovers checks through this list (Phase 3).
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
]
