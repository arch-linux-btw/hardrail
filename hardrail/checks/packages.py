"""Package checks: pending security updates, insecure packages, auto updates.

These checks support Debian and Ubuntu (apt and dpkg). On other systems they
are SKIPPED. Everything here is read-only.
"""

import os
import re
import shutil
import subprocess

from hardrail.models import Category, Check, CheckResult, Severity, Status

APT_CONF_DIR = "/etc/apt/apt.conf.d"
MAX_LISTED = 10
COMMAND_TIMEOUT = 60

APT_SIMULATE_COMMAND = ["apt-get", "-s", "upgrade"]
DPKG_LIST_COMMAND = ["dpkg-query", "-W", "-f=${Package} ${db:Status-Abbrev}\\n"]

# Packages that offer unencrypted or long obsolete network services.
INSECURE_PACKAGES = [
    "telnetd",
    "telnetd-ssl",
    "inetutils-telnetd",
    "rsh-server",
    "rsh-redone-server",
    "rsh-client",
    "nis",
    "ypserv",
    "talkd",
    "tftpd",
    "tftpd-hpa",
    "xinetd",
    "openbsd-inetd",
]

UNATTENDED_PATTERN = re.compile(
    r'^\s*APT::Periodic::Unattended-Upgrade\s+"([^"]*)"', re.MULTILINE
)


class CommandError(Exception):
    """Raised when an external command exits with an error."""


# Helpers -----------------------------------------------------------------


def run_command(args):
    """Run a command with a stable locale and return its output."""
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    completed = subprocess.run(
        args, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, env=env
    )
    if completed.returncode != 0:
        raise CommandError(completed.stderr.strip())
    return completed.stdout


def run_tool_check(tool, args, evaluate):
    """Run `args` and hand the output to `evaluate`.

    Shared by every check based on a command, so a missing tool, a failing
    command and a timeout are handled in one place only.
    """
    if shutil.which(tool) is None:
        return CheckResult(
            Status.SKIPPED,
            reason=tool + " not found (this check supports Debian/Ubuntu only)",
        )

    try:
        output = run_command(args)
    except CommandError as error:
        return CheckResult(Status.ERROR, reason=tool + " failed: " + str(error))
    except subprocess.TimeoutExpired:
        return CheckResult(Status.ERROR, reason=tool + " timed out")
    except OSError as error:
        return CheckResult(
            Status.ERROR, reason="cannot run " + tool + ": " + str(error)
        )

    return evaluate(output)


def summarize_names(names):
    """Join the first MAX_LISTED names and say how many were left out."""
    shown = names[:MAX_LISTED]
    text = ", ".join(shown)
    extra = len(names) - len(shown)
    if extra > 0:
        text += ", and " + str(extra) + " more"
    return text


def parse_installed_packages(output):
    """Return the set of installed package names from dpkg-query output.

    Each line looks like 'bash ii ': the second character of the status
    is 'i' only when the package is really installed (not removed, not
    just configuration files left behind).
    """
    installed = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        status = parts[1]
        if len(status) >= 2 and status[1] == "i":
            installed.add(parts[0])
    return installed


# PKG-001 -----------------------------------------------------------------


def parse_apt_upgrades(output):
    """Return [(package, is_security)] for the 'Inst' lines of apt-get -s.

    Only the part after the first '(' describes where the new version
    comes from, so only that part is searched for 'security'.
    """
    upgrades = []
    for line in output.splitlines():
        if not line.startswith("Inst "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue

        paren = line.find("(")
        if paren == -1:
            origin = ""
        else:
            origin = line[paren:].lower()

        upgrades.append((parts[1], "security" in origin))
    return upgrades


def evaluate_security_updates(upgrades):
    """PASS when no pending upgrade comes from a security repository."""
    names = []
    for name, is_security in upgrades:
        if is_security:
            names.append(name)
    names.sort()

    if len(names) == 0:
        return CheckResult(
            Status.PASS,
            evidence=(
                "no pending security updates in the local package cache "
                "(run 'apt update' to refresh it)"
            ),
        )
    else:
        return CheckResult(
            Status.FAIL,
            evidence=str(len(names))
            + " security update(s) pending: "
            + summarize_names(names),
        )


def check_security_updates():
    return run_tool_check(
        "apt-get",
        APT_SIMULATE_COMMAND,
        lambda output: evaluate_security_updates(parse_apt_upgrades(output)),
    )


# PKG-002 -----------------------------------------------------------------


def evaluate_insecure_packages(installed):
    """PASS when none of the INSECURE_PACKAGES is installed."""
    found = []
    for name in INSECURE_PACKAGES:
        if name in installed:
            found.append(name)
    found.sort()

    if len(found) == 0:
        return CheckResult(Status.PASS, evidence="no insecure package installed")
    else:
        return CheckResult(
            Status.FAIL, evidence="insecure package(s) installed: " + ", ".join(found)
        )


def check_insecure_packages():
    return run_tool_check(
        "dpkg-query",
        DPKG_LIST_COMMAND,
        lambda output: evaluate_insecure_packages(parse_installed_packages(output)),
    )


# PKG-003 -----------------------------------------------------------------


def read_apt_conf_text():
    """Return the text of the files in apt.conf.d, in the order apt reads them."""
    if not os.path.isdir(APT_CONF_DIR):
        return ""

    texts = []
    for name in sorted(os.listdir(APT_CONF_DIR)):
        full_path = os.path.join(APT_CONF_DIR, name)
        if not os.path.isfile(full_path):
            continue
        with open(full_path, "r", encoding="utf-8", errors="replace") as handle:
            texts.append(handle.read())
    return "\n".join(texts)


def parse_unattended_setting(text):
    """Return the last value of APT::Periodic::Unattended-Upgrade, or None.

    Only the one-line form is recognised. Commented lines are ignored.
    """
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        lines.append(line)

    values = UNATTENDED_PATTERN.findall("\n".join(lines))
    if len(values) == 0:
        return None
    else:
        return values[-1]


def evaluate_auto_updates(installed, setting):
    """PASS when unattended-upgrades is installed and switched on."""
    if "unattended-upgrades" not in installed:
        return CheckResult(
            Status.FAIL, evidence="the unattended-upgrades package is not installed"
        )

    if setting is None:
        return CheckResult(
            Status.FAIL,
            evidence=(
                "unattended-upgrades is installed but "
                "APT::Periodic::Unattended-Upgrade is not set "
                "(only the one-line form is recognised)"
            ),
        )

    try:
        number = int(setting)
    except ValueError:
        return CheckResult(
            Status.ERROR,
            reason="unexpected APT::Periodic::Unattended-Upgrade value: " + setting,
        )

    if number >= 1:
        return CheckResult(
            Status.PASS,
            evidence='APT::Periodic::Unattended-Upgrade = "' + setting + '"',
        )
    else:
        return CheckResult(
            Status.FAIL,
            evidence='APT::Periodic::Unattended-Upgrade = "' + setting + '"',
        )


def check_auto_updates():
    def evaluate(output):
        installed = parse_installed_packages(output)
        try:
            text = read_apt_conf_text()
        except OSError as error:
            return CheckResult(
                Status.ERROR,
                reason="cannot read " + APT_CONF_DIR + ": " + str(error),
            )
        return evaluate_auto_updates(installed, parse_unattended_setting(text))

    return run_tool_check("dpkg-query", DPKG_LIST_COMMAND, evaluate)


# The engine discovers checks through this list. PKG-004 moved to v2. -------

CHECKS = [
    Check(
        id="PKG-001",
        title="No security updates are pending",
        category=Category.PACKAGES,
        severity=Severity.HIGH,
        run=check_security_updates,
        reference="CIS Linux benchmark, software updates (apply security patches)",
        requires_root=False,
        remediation=(
            "Run 'apt update' to refresh the package lists, then "
            "'apt upgrade' to install the pending updates."
        ),
    ),
    Check(
        id="PKG-002",
        title="No insecure network service packages are installed",
        category=Category.PACKAGES,
        severity=Severity.HIGH,
        run=check_insecure_packages,
        reference="CIS Linux benchmark, services (remove telnet, rsh, NIS, tftp, xinetd)",
        requires_root=False,
        remediation=(
            "Remove the package with 'apt remove <package>' unless a service "
            "really depends on it."
        ),
    ),
    Check(
        id="PKG-003",
        title="Automatic security updates are enabled",
        category=Category.PACKAGES,
        severity=Severity.MEDIUM,
        run=check_auto_updates,
        reference="Common Debian/Ubuntu hardening guidance (unattended-upgrades)",
        requires_root=False,
        remediation=(
            "Install the package with 'apt install unattended-upgrades', then "
            "run 'dpkg-reconfigure -plow unattended-upgrades' to enable it."
        ),
    ),
]
