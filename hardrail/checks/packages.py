"""Package checks: pending security updates, insecure packages, auto updates.

These checks support Debian and Ubuntu (apt and dpkg). On other systems they
are SKIPPED. Everything here is read-only.
"""

import os
import re
import shutil
import subprocess
import time

from hardrail.models import Category, Check, CheckResult, Severity, Status

APT_CONF_DIR = "/etc/apt/apt.conf.d"
APT_STAMP_PATH = "/var/lib/apt/periodic/update-success-stamp"
APT_LISTS_DIR = "/var/lib/apt/lists"
MAX_CACHE_AGE_DAYS = 7
SECONDS_PER_DAY = 86400
MAX_LISTED = 10
COMMAND_TIMEOUT = 60

# dist-upgrade is only simulated (-s): nothing is installed. Unlike plain
# "upgrade", it also lists updates that need new dependencies, such as new
# kernel packages, which "upgrade" would hold back and hide.
APT_SIMULATE_COMMAND = ["apt-get", "-s", "dist-upgrade"]
DPKG_LIST_COMMAND = ["dpkg-query", "-W", "-f=${Package} ${db:Status-Abbrev}\\n"]

# Server packages that offer unencrypted or long obsolete network services.
# Clients (telnet, rsh-client, ftp) are not listed on purpose.
INSECURE_PACKAGES = [
    # telnet and r-services servers
    "telnetd",
    "telnetd-ssl",
    "inetutils-telnetd",
    "rsh-server",
    "rsh-redone-server",
    "talkd",
    # FTP and TFTP servers
    "vsftpd",
    "proftpd-basic",
    "pure-ftpd",
    "inetutils-ftpd",
    "tftpd",
    "tftpd-hpa",
    # NIS
    "nis",
    "ypserv",
    # super-servers that start those services
    "xinetd",
    "openbsd-inetd",
    "inetutils-inetd",
]


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


def apt_cache_age_days():
    """Return the age in days of the apt package lists, or None if unknown.

    Uses the stamp apt writes after every successful 'apt update'. If the
    stamp does not exist, falls back to the newest file in the lists
    directory (the 'lock' file is ignored: it changes on every apt run).
    """
    newest = None

    try:
        newest = os.path.getmtime(APT_STAMP_PATH)
    except OSError:
        newest = None

    if newest is None:
        try:
            names = os.listdir(APT_LISTS_DIR)
        except OSError:
            return None

        for name in names:
            if name == "lock":
                continue
            full_path = os.path.join(APT_LISTS_DIR, name)
            if not os.path.isfile(full_path):
                continue
            try:
                modified = os.path.getmtime(full_path)
            except OSError:
                continue
            if newest is None:
                newest = modified
            elif modified > newest:
                newest = modified

    if newest is None:
        return None

    return (time.time() - newest) / SECONDS_PER_DAY


def evaluate_security_updates(upgrades, cache_age_days):
    """Judge the pending security updates.

    - security updates found          -> FAIL (true whatever the cache age)
    - none found, lists are recent    -> PASS
    - none found, lists old or unknown -> SKIPPED: "nothing found" would be
      a statement about an outdated view, so we do not claim a PASS.
    """
    names = []
    for name, is_security in upgrades:
        if is_security:
            names.append(name)
    names.sort()

    if len(names) > 0:
        return CheckResult(
            Status.FAIL,
            evidence=str(len(names))
            + " security update(s) pending: "
            + summarize_names(names),
        )

    if cache_age_days is None:
        return CheckResult(
            Status.SKIPPED,
            reason=(
                "cannot tell how recent the apt package lists are; "
                "run 'apt update' and scan again"
            ),
        )
    elif cache_age_days > MAX_CACHE_AGE_DAYS:
        return CheckResult(
            Status.SKIPPED,
            reason=(
                "apt package lists are "
                + str(round(cache_age_days, 1))
                + " days old; run 'apt update' and scan again"
            ),
        )
    else:
        return CheckResult(
            Status.PASS,
            evidence=(
                "no pending security updates (package lists are "
                + str(round(cache_age_days, 1))
                + " day(s) old)"
            ),
        )


def check_security_updates():
    def evaluate(output):
        upgrades = parse_apt_upgrades(output)
        return evaluate_security_updates(upgrades, apt_cache_age_days())

    return run_tool_check("apt-get", APT_SIMULATE_COMMAND, evaluate)


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


def parse_apt_setting(text, key):
    """Return the last value of 'APT::Periodic::<key> "<value>";', or None.

    Only the one-line form is recognised. Commented lines are ignored.
    """
    pattern = re.compile(
        r'^\s*APT::Periodic::' + re.escape(key) + r'\s+"([^"]*)"', re.MULTILINE
    )

    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        lines.append(line)

    values = pattern.findall("\n".join(lines))
    if len(values) == 0:
        return None
    else:
        return values[-1]


def parse_unattended_setting(text):
    """Return the value of APT::Periodic::Unattended-Upgrade, or None."""
    return parse_apt_setting(text, "Unattended-Upgrade")


def setting_is_on(value):
    """True if a numeric apt setting is 1 or more, False if 0, None if not a number."""
    try:
        number = int(value)
    except ValueError:
        return None

    if number >= 1:
        return True
    else:
        return False


def evaluate_auto_updates(installed, unattended, update_lists):
    """PASS when unattended-upgrades is installed, on, and has fresh lists.

    Without APT::Periodic::Update-Package-Lists the package lists are never
    refreshed, so unattended-upgrades would have nothing to install.
    """
    if "unattended-upgrades" not in installed:
        return CheckResult(
            Status.FAIL, evidence="the unattended-upgrades package is not installed"
        )

    if unattended is None:
        return CheckResult(
            Status.FAIL,
            evidence=(
                "unattended-upgrades is installed but "
                "APT::Periodic::Unattended-Upgrade is not set "
                "(only the one-line form is recognised)"
            ),
        )

    unattended_on = setting_is_on(unattended)
    if unattended_on is None:
        return CheckResult(
            Status.ERROR,
            reason="unexpected APT::Periodic::Unattended-Upgrade value: " + unattended,
        )
    if not unattended_on:
        return CheckResult(
            Status.FAIL,
            evidence='APT::Periodic::Unattended-Upgrade = "' + unattended + '"',
        )

    if update_lists is None:
        return CheckResult(
            Status.FAIL,
            evidence=(
                "APT::Periodic::Update-Package-Lists is not set: "
                "package lists are never refreshed, so no update is installed"
            ),
        )

    lists_on = setting_is_on(update_lists)
    if lists_on is None:
        return CheckResult(
            Status.ERROR,
            reason="unexpected APT::Periodic::Update-Package-Lists value: " + update_lists,
        )
    if not lists_on:
        return CheckResult(
            Status.FAIL,
            evidence='APT::Periodic::Update-Package-Lists = "' + update_lists + '"',
        )

    return CheckResult(
        Status.PASS,
        evidence=(
            'Unattended-Upgrade = "'
            + unattended
            + '", Update-Package-Lists = "'
            + update_lists
            + '"'
        ),
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
        return evaluate_auto_updates(
            installed,
            parse_apt_setting(text, "Unattended-Upgrade"),
            parse_apt_setting(text, "Update-Package-Lists"),
        )

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
            "'apt full-upgrade' to install the pending updates (a plain "
            "'apt upgrade' can hold back kernel updates)."
        ),
    ),
    Check(
        id="PKG-002",
        title="No insecure network service packages are installed",
        category=Category.PACKAGES,
        severity=Severity.HIGH,
        run=check_insecure_packages,
        reference="CIS Linux benchmark, services (remove telnet, rsh, NIS, FTP, tftp, xinetd servers)",
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
            "run 'dpkg-reconfigure -plow unattended-upgrades' to enable it "
            "(this sets both Unattended-Upgrade and Update-Package-Lists)."
        ),
    ),
]
