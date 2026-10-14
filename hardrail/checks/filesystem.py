"""File system checks: permissions, world-writable files, set-id bits, mounts.

Everything here is read-only.
"""

import os
import stat
from dataclasses import dataclass

from hardrail.models import Category, Check, CheckResult, Severity, Status

# (path, most permissive mode allowed, extra group names allowed besides root)
CRITICAL_FILES = [
    ("/etc/passwd", 0o644, []),
    ("/etc/shadow", 0o640, ["shadow"]),
    ("/etc/sudoers", 0o440, []),
]

WORLD_WRITABLE_ROOTS = ["/etc", "/usr", "/opt"]
SETID_ROOTS = ["/usr", "/opt", "/home", "/var", "/tmp"]
STICKY_DIRS = ["/tmp", "/var/tmp"]

TMP_PATH = "/tmp"
MOUNTS_PATH = "/proc/self/mounts"
TMP_REQUIRED_OPTIONS = ["nodev", "nosuid", "noexec"]

MAX_LISTED = 10

# Names of set-id binaries that are normal on common distributions. This is a
# starting point: it is matched by file name only, and false positives are
# possible on systems with extra software.
EXPECTED_SETID = {
    "su",
    "sudo",
    "passwd",
    "chsh",
    "chfn",
    "chage",
    "expiry",
    "gpasswd",
    "newgrp",
    "mount",
    "umount",
    "ping",
    "ping6",
    "fusermount",
    "fusermount3",
    "pkexec",
    "polkit-agent-helper-1",
    "unix_chkpwd",
    "unix_update",
    "pam_extrausers_chkpwd",
    "ssh-agent",
    "ssh-keysign",
    "dotlockfile",
    "at",
    "crontab",
    "wall",
    "write",
    "bsd-write",
    "newuidmap",
    "newgidmap",
    "mount.nfs",
    "mount.cifs",
    "chrome-sandbox",
    "chromium-sandbox",
    "Xorg.wrap",
    "locate",
    "plocate",
    "mlocate",
    "dbus-daemon-launch-helper",
}


@dataclass
class FileState:
    """Ownership and mode of a file, with the limits it must respect."""

    path: str
    mode: int
    uid: int
    gid: int
    max_mode: int
    allowed_gids: list


# Helpers -----------------------------------------------------------------


def read_file_info(path):
    """Return (mode, uid, gid) of a path. Raises OSError if it cannot be read."""
    info = os.stat(path)
    return info.st_mode, info.st_uid, info.st_gid


def lookup_gid(group_name):
    """Return the numeric id of a group, or None if it does not exist.

    The `grp` module only exists on Unix, so it is imported here and not at
    the top of the file: the tests must also run on other systems.
    """
    try:
        import grp
    except ImportError:
        return None

    try:
        return grp.getgrnam(group_name).gr_gid
    except KeyError:
        return None


def iter_entries(roots, unreadable):
    """Yield (path, mode) for every file and directory under the given roots.

    Symbolic links are never followed or reported, and other filesystems
    are not entered. Directories that cannot be read are appended to
    `unreadable` instead of stopping the scan.
    """

    def on_error(error):
        unreadable.append(error.filename)

    for root in roots:
        try:
            root_info = os.lstat(root)
        except OSError:
            continue
        if not stat.S_ISDIR(root_info.st_mode):
            continue

        for dirpath, dirnames, filenames in os.walk(root, onerror=on_error):
            kept = []
            for name in dirnames:
                full_path = os.path.join(dirpath, name)
                try:
                    info = os.lstat(full_path)
                except OSError:
                    continue
                if stat.S_ISLNK(info.st_mode):
                    continue
                if info.st_dev != root_info.st_dev:
                    continue
                kept.append(name)
                yield full_path, info.st_mode
            dirnames[:] = kept

            for name in filenames:
                full_path = os.path.join(dirpath, name)
                try:
                    info = os.lstat(full_path)
                except OSError:
                    continue
                if stat.S_ISLNK(info.st_mode):
                    continue
                yield full_path, info.st_mode


def run_walk_check(roots, find, evaluate):
    """Scan the given roots with `find`, then judge the findings with `evaluate`."""
    existing = []
    for root in roots:
        if os.path.isdir(root) and not os.path.islink(root):
            existing.append(root)

    if len(existing) == 0:
        return CheckResult(
            Status.SKIPPED,
            reason="none of the scanned directories exist: " + ", ".join(roots),
        )

    unreadable = []
    try:
        findings = find(iter_entries(existing, unreadable))
    except OSError as error:
        return CheckResult(Status.ERROR, reason="scan failed: " + str(error))

    return evaluate(findings, len(unreadable))


def summarize_findings(findings):
    """Join the first MAX_LISTED findings and say how many were left out."""
    shown = findings[:MAX_LISTED]
    text = ", ".join(shown)
    extra = len(findings) - len(shown)
    if extra > 0:
        text += ", and " + str(extra) + " more"
    return text


def unreadable_note(unreadable_count):
    if unreadable_count > 0:
        return " (" + str(unreadable_count) + " director(y/ies) could not be read)"
    else:
        return ""


# FS-001 ------------------------------------------------------------------


def permission_problem(mode, uid, gid, max_mode, allowed_gids):
    """Return a list of problems (empty when the file is fine).

    The mode may be `max_mode` or stricter: any extra bit, including
    setuid/setgid/sticky, is a problem.
    """
    problems = []
    mode_bits = stat.S_IMODE(mode)

    if uid != 0:
        problems.append("owner is " + str(uid) + " (expected 0)")

    if gid not in allowed_gids:
        expected_groups = []
        for allowed in allowed_gids:
            expected_groups.append(str(allowed))
        problems.append(
            "group is " + str(gid) + " (expected " + " or ".join(expected_groups) + ")"
        )

    if mode_bits & ~max_mode != 0:
        problems.append(
            "mode "
            + format(mode_bits, "03o")
            + " (expected "
            + format(max_mode, "03o")
            + " or stricter)"
        )

    return problems


def evaluate_file_permissions(states):
    """PASS when every file respects its limits."""
    if len(states) == 0:
        return CheckResult(Status.SKIPPED, reason="none of the critical files exist")

    offenders = []
    for state in states:
        problems = permission_problem(
            state.mode, state.uid, state.gid, state.max_mode, state.allowed_gids
        )
        if len(problems) > 0:
            offenders.append(state.path + ": " + "; ".join(problems))

    if len(offenders) > 0:
        return CheckResult(Status.FAIL, evidence=" | ".join(offenders))
    else:
        paths = []
        for state in states:
            paths.append(state.path)
        return CheckResult(
            Status.PASS, evidence="permissions are correct on " + ", ".join(paths)
        )


def check_critical_file_permissions():
    states = []
    for path, max_mode, extra_groups in CRITICAL_FILES:
        try:
            mode, uid, gid = read_file_info(path)
        except FileNotFoundError:
            continue
        except OSError as error:
            return CheckResult(
                Status.ERROR, reason="cannot stat " + path + ": " + str(error)
            )

        allowed_gids = [0]
        for group_name in extra_groups:
            group_id = lookup_gid(group_name)
            if group_id is not None:
                allowed_gids.append(group_id)

        states.append(FileState(path, mode, uid, gid, max_mode, allowed_gids))

    return evaluate_file_permissions(states)


# FS-002 ------------------------------------------------------------------


def find_world_writable(entries):
    """Return files writable by everyone and directories without sticky bit."""
    findings = []
    for path, mode in entries:
        if stat.S_ISREG(mode):
            if mode & stat.S_IWOTH:
                findings.append(path + " (file)")
        elif stat.S_ISDIR(mode):
            if (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
                findings.append(path + " (directory without sticky bit)")
    findings.sort()
    return findings


def evaluate_world_writable(findings, unreadable_count):
    note = unreadable_note(unreadable_count)

    if len(findings) == 0:
        return CheckResult(
            Status.PASS,
            evidence="no world-writable files or unprotected directories" + note,
        )
    else:
        return CheckResult(
            Status.FAIL,
            evidence=str(len(findings))
            + " world-writable item(s): "
            + summarize_findings(findings)
            + note,
        )


def check_world_writable():
    return run_walk_check(
        WORLD_WRITABLE_ROOTS, find_world_writable, evaluate_world_writable
    )


# FS-003 ------------------------------------------------------------------


def find_unexpected_setid(entries, expected_names):
    """Return regular files with setuid/setgid whose name is not expected."""
    findings = []
    for path, mode in entries:
        if not stat.S_ISREG(mode):
            continue

        kinds = []
        if mode & stat.S_ISUID:
            kinds.append("setuid")
        if mode & stat.S_ISGID:
            kinds.append("setgid")
        if len(kinds) == 0:
            continue

        if os.path.basename(path) not in expected_names:
            findings.append(path + " (" + "+".join(kinds) + ")")

    findings.sort()
    return findings


def evaluate_setid(findings, unreadable_count):
    note = unreadable_note(unreadable_count)

    if len(findings) == 0:
        return CheckResult(
            Status.PASS, evidence="no unexpected setuid/setgid files" + note
        )
    else:
        return CheckResult(
            Status.FAIL,
            evidence=str(len(findings))
            + " unexpected setuid/setgid file(s): "
            + summarize_findings(findings)
            + note,
        )


def check_setid():
    def find(entries):
        return find_unexpected_setid(entries, EXPECTED_SETID)

    return run_walk_check(SETID_ROOTS, find, evaluate_setid)


# FS-004 ------------------------------------------------------------------


def sticky_problem(path, mode):
    """Return a problem text if the directory is world-writable without sticky."""
    if (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
        return (
            path
            + ": world-writable without sticky bit (mode "
            + format(stat.S_IMODE(mode), "04o")
            + ")"
        )
    else:
        return None


def evaluate_sticky_dirs(directories):
    """PASS when no checked directory is world-writable without sticky bit."""
    if len(directories) == 0:
        return CheckResult(Status.SKIPPED, reason="none of the temp directories exist")

    problems = []
    paths = []
    for path, mode in directories:
        paths.append(path)
        problem = sticky_problem(path, mode)
        if problem is not None:
            problems.append(problem)

    if len(problems) > 0:
        return CheckResult(Status.FAIL, evidence="; ".join(problems))
    else:
        return CheckResult(
            Status.PASS,
            evidence="no unprotected world-writable temp directory ("
            + ", ".join(paths)
            + ")",
        )


def check_sticky_dirs():
    directories = []
    for path in STICKY_DIRS:
        try:
            info = os.stat(path)
        except FileNotFoundError:
            continue
        except OSError as error:
            return CheckResult(
                Status.ERROR, reason="cannot stat " + path + ": " + str(error)
            )
        directories.append((path, info.st_mode))

    return evaluate_sticky_dirs(directories)


# FS-005 ------------------------------------------------------------------


def parse_mounts(text):
    """Parse /proc/self/mounts into {mountpoint: [options]}. Last entry wins."""
    mounts = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        mounts[fields[1]] = fields[3].split(",")
    return mounts


def evaluate_tmp_mount(mounts):
    """PASS when /tmp is a separate mount with nodev, nosuid and noexec."""
    options = mounts.get(TMP_PATH)

    if options is None:
        return CheckResult(
            Status.FAIL,
            evidence=TMP_PATH + " is not a separate filesystem (CIS recommends a dedicated mount)",
        )

    missing = []
    for required in TMP_REQUIRED_OPTIONS:
        if required not in options:
            missing.append(required)

    if len(missing) > 0:
        return CheckResult(
            Status.FAIL,
            evidence=TMP_PATH
            + " is mounted without: "
            + ", ".join(missing)
            + " (options: "
            + ",".join(options)
            + ")",
        )
    else:
        return CheckResult(
            Status.PASS, evidence=TMP_PATH + " options: " + ",".join(options)
        )


def check_tmp_mount():
    try:
        with open(MOUNTS_PATH, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except FileNotFoundError:
        return CheckResult(Status.SKIPPED, reason=MOUNTS_PATH + " not found")
    except OSError as error:
        return CheckResult(
            Status.ERROR, reason="cannot read " + MOUNTS_PATH + ": " + str(error)
        )

    return evaluate_tmp_mount(parse_mounts(text))


# The engine discovers checks through this list. ---------------------------

CHECKS = [
    Check(
        id="FS-001",
        title="Critical account files have correct ownership and permissions",
        category=Category.FILESYSTEM,
        severity=Severity.HIGH,
        run=check_critical_file_permissions,
        reference="CIS Linux benchmark, system file permissions (passwd, shadow, sudoers)",
        requires_root=False,
        remediation=(
            "Run 'chown root:root' and 'chmod 644 /etc/passwd', "
            "'chmod 640 /etc/shadow' (group shadow where the distribution uses it) "
            "and 'chmod 440 /etc/sudoers'."
        ),
    ),
    Check(
        id="FS-002",
        title="No world-writable files or unprotected directories in system paths",
        category=Category.FILESYSTEM,
        severity=Severity.HIGH,
        run=check_world_writable,
        reference="CIS Linux benchmark, world-writable files and directories",
        requires_root=True,
        remediation=(
            "Review each item, then remove the write permission for others "
            "with 'chmod o-w <path>' (or add the sticky bit to a shared directory)."
        ),
    ),
    Check(
        id="FS-003",
        title="No unexpected setuid/setgid files",
        category=Category.FILESYSTEM,
        severity=Severity.MEDIUM,
        run=check_setid,
        reference="CIS Linux benchmark, SUID and SGID executables",
        requires_root=True,
        remediation=(
            "Verify each file (which package owns it, whether it is needed). "
            "If it is not needed, remove the bit with 'chmod u-s,g-s <path>' "
            "or uninstall the package."
        ),
    ),
    Check(
        id="FS-004",
        title="Sticky bit is set on world-writable temp directories",
        category=Category.FILESYSTEM,
        severity=Severity.HIGH,
        run=check_sticky_dirs,
        reference="CIS Linux benchmark, sticky bit on world-writable directories",
        requires_root=False,
        remediation="Run 'chmod +t /tmp' (and '/var/tmp') to set the sticky bit.",
    ),
    Check(
        id="FS-005",
        title="/tmp is a separate mount with nodev, nosuid and noexec",
        category=Category.FILESYSTEM,
        severity=Severity.LOW,
        run=check_tmp_mount,
        reference="CIS Linux benchmark, /tmp partition and mount options",
        requires_root=False,
        remediation=(
            "Mount /tmp as its own filesystem (for example tmpfs) with "
            "'nodev,nosuid,noexec' in /etc/fstab or a systemd tmp.mount unit. "
            "Test first: noexec can break some installers."
        ),
    ),
]
