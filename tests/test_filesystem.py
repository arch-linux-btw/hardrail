import os

import pytest

from hardrail.checks import filesystem
from hardrail.checks.filesystem import (
    CHECKS,
    FileState,
    evaluate_file_permissions,
    evaluate_setid,
    evaluate_sticky_dirs,
    evaluate_tmp_mount,
    evaluate_world_writable,
    find_unexpected_setid,
    find_world_writable,
    parse_mounts,
    permission_problem,
    sticky_problem,
)
from hardrail.models import Category, Status

skip_on_windows = pytest.mark.skipif(
    os.name == "nt", reason="needs POSIX permissions and symlinks"
)


def fake_reader(table):
    def fake_read(path):
        if path not in table:
            raise FileNotFoundError(path)
        entry = table[path]
        if isinstance(entry, Exception):
            raise entry
        return entry

    return fake_read


# FS-001 ------------------------------------------------------------------


def test_permission_problem_none_when_ok():
    assert permission_problem(0o100644, 0, 0, 0o644, [0]) == []


def test_permission_problem_stricter_mode_is_ok():
    assert permission_problem(0o100600, 0, 0, 0o644, [0]) == []


def test_permission_problem_extra_bits_flagged():
    problems = permission_problem(0o100666, 0, 0, 0o644, [0])
    assert len(problems) == 1
    assert "mode" in problems[0]


def test_permission_problem_wrong_owner():
    problems = permission_problem(0o100644, 1000, 0, 0o644, [0])
    assert len(problems) == 1
    assert "owner" in problems[0]


def test_permission_problem_group_not_allowed():
    problems = permission_problem(0o100640, 0, 5, 0o640, [0])
    assert len(problems) == 1
    assert "group" in problems[0]


def test_permission_problem_group_allowed_when_listed():
    assert permission_problem(0o100640, 0, 42, 0o640, [0, 42]) == []


def test_permission_problem_setuid_bit_flagged():
    problems = permission_problem(0o104644, 0, 0, 0o644, [0])
    assert len(problems) == 1
    assert "mode" in problems[0]


def test_evaluate_permissions_pass():
    states = [FileState("/etc/passwd", 0o100644, 0, 0, 0o644, [0])]
    result = evaluate_file_permissions(states)
    assert result.status == Status.PASS


def test_evaluate_permissions_fail_lists_offender():
    states = [
        FileState("/etc/passwd", 0o100644, 0, 0, 0o644, [0]),
        FileState("/etc/shadow", 0o100644, 0, 0, 0o640, [0]),
    ]
    result = evaluate_file_permissions(states)
    assert result.status == Status.FAIL
    assert "/etc/shadow" in result.evidence
    assert "/etc/passwd:" not in result.evidence


def test_evaluate_permissions_none_found_is_skipped():
    result = evaluate_file_permissions([])
    assert result.status == Status.SKIPPED


def test_check_permissions_with_fake_files(monkeypatch):
    table = {
        "/etc/passwd": (0o100644, 0, 0),
        "/etc/shadow": (0o100640, 0, 42),
        "/etc/sudoers": (0o100440, 0, 0),
    }
    monkeypatch.setattr(filesystem, "read_file_info", fake_reader(table))
    monkeypatch.setattr(filesystem, "lookup_gid", lambda name: 42)
    result = filesystem.check_critical_file_permissions()
    assert result.status == Status.PASS


def test_check_permissions_ignores_missing_files(monkeypatch):
    table = {
        "/etc/passwd": (0o100644, 0, 0),
        "/etc/shadow": (0o100600, 0, 0),
    }
    monkeypatch.setattr(filesystem, "read_file_info", fake_reader(table))
    monkeypatch.setattr(filesystem, "lookup_gid", lambda name: None)
    result = filesystem.check_critical_file_permissions()
    assert result.status == Status.PASS


def test_check_permissions_error_when_unreadable(monkeypatch):
    table = {"/etc/passwd": PermissionError("denied")}
    monkeypatch.setattr(filesystem, "read_file_info", fake_reader(table))
    result = filesystem.check_critical_file_permissions()
    assert result.status == Status.ERROR


# FS-002 ------------------------------------------------------------------


def test_find_world_writable_flags_files_and_unprotected_dirs():
    entries = [
        ("/a/f", 0o100666),
        ("/a/d", 0o040777),
        ("/a/ok", 0o100644),
        ("/a/tmp", 0o041777),
    ]
    findings = find_world_writable(entries)
    assert findings == ["/a/d (directory without sticky bit)", "/a/f (file)"]


def test_find_world_writable_clean():
    entries = [("/a/f", 0o100644), ("/a/d", 0o040755)]
    assert find_world_writable(entries) == []


def test_evaluate_world_writable_pass():
    result = evaluate_world_writable([], 0)
    assert result.status == Status.PASS


def test_evaluate_world_writable_truncates_long_lists():
    findings = []
    for number in range(15):
        findings.append("/x/f" + str(number) + " (file)")
    result = evaluate_world_writable(findings, 0)
    assert result.status == Status.FAIL
    assert "15 world-writable" in result.evidence
    assert "and 5 more" in result.evidence


def test_evaluate_world_writable_mentions_unreadable():
    result = evaluate_world_writable([], 3)
    assert result.status == Status.PASS
    assert "could not be read" in result.evidence


# FS-003 ------------------------------------------------------------------


def test_find_unexpected_setid_ignores_expected_names():
    entries = [("/usr/bin/sudo", 0o104755), ("/usr/bin/passwd", 0o104755)]
    assert find_unexpected_setid(entries, filesystem.EXPECTED_SETID) == []


def test_find_unexpected_setid_flags_unknown_files():
    entries = [("/home/alice/rootshell", 0o104755)]
    findings = find_unexpected_setid(entries, filesystem.EXPECTED_SETID)
    assert findings == ["/home/alice/rootshell (setuid)"]


def test_find_unexpected_setid_reports_setgid():
    entries = [("/usr/bin/weird", 0o102755)]
    findings = find_unexpected_setid(entries, filesystem.EXPECTED_SETID)
    assert findings == ["/usr/bin/weird (setgid)"]


def test_find_unexpected_setid_ignores_directories_and_plain_files():
    entries = [("/usr/share", 0o042775), ("/usr/bin/tool", 0o100755)]
    assert find_unexpected_setid(entries, filesystem.EXPECTED_SETID) == []


def test_evaluate_setid_pass():
    result = evaluate_setid([], 0)
    assert result.status == Status.PASS


def test_evaluate_setid_fail():
    result = evaluate_setid(["/home/alice/rootshell (setuid)"], 0)
    assert result.status == Status.FAIL
    assert "rootshell" in result.evidence

def test_find_unexpected_setid_accepts_sudo_ws():
    entries = [("/usr/bin/sudo.ws", 0o104755)]
    assert find_unexpected_setid(entries, filesystem.EXPECTED_SETID) == []


def test_find_unexpected_setid_still_flags_ntfs_3g():
    entries = [("/usr/bin/ntfs-3g", 0o104755)]
    findings = find_unexpected_setid(entries, filesystem.EXPECTED_SETID)
    assert findings == ["/usr/bin/ntfs-3g (setuid)"]


# FS-004 ------------------------------------------------------------------


def test_sticky_problem_none_with_sticky():
    assert sticky_problem("/tmp", 0o041777) is None


def test_sticky_problem_flags_missing_sticky():
    problem = sticky_problem("/tmp", 0o040777)
    assert problem is not None
    assert "sticky" in problem


def test_sticky_not_needed_when_not_world_writable():
    assert sticky_problem("/tmp", 0o040755) is None


def test_evaluate_sticky_pass():
    result = evaluate_sticky_dirs([("/tmp", 0o041777), ("/var/tmp", 0o041777)])
    assert result.status == Status.PASS


def test_evaluate_sticky_fail():
    result = evaluate_sticky_dirs([("/tmp", 0o041777), ("/var/tmp", 0o040777)])
    assert result.status == Status.FAIL
    assert "/var/tmp" in result.evidence


def test_evaluate_sticky_none_is_skipped():
    result = evaluate_sticky_dirs([])
    assert result.status == Status.SKIPPED


# FS-005 ------------------------------------------------------------------


def test_parse_mounts_reads_options():
    text = (
        "tmpfs /tmp tmpfs rw,nosuid,nodev,size=1G 0 0\n"
        "/dev/sda1 / ext4 rw,relatime 0 0\n"
        "bad\n"
    )
    mounts = parse_mounts(text)
    assert mounts["/tmp"] == ["rw", "nosuid", "nodev", "size=1G"]
    assert "/" in mounts
    assert len(mounts) == 2


def test_tmp_not_separate_fails():
    result = evaluate_tmp_mount({"/": ["rw"]})
    assert result.status == Status.FAIL
    assert "separate" in result.evidence


def test_tmp_missing_options_fails():
    result = evaluate_tmp_mount({"/tmp": ["rw", "nosuid", "nodev"]})
    assert result.status == Status.FAIL
    assert "noexec" in result.evidence


def test_tmp_all_options_pass():
    result = evaluate_tmp_mount({"/tmp": ["rw", "nosuid", "nodev", "noexec"]})
    assert result.status == Status.PASS


def test_check_tmp_mount_reads_file(monkeypatch, tmp_path):
    mounts = tmp_path / "mounts"
    mounts.write_text("tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n")
    monkeypatch.setattr(filesystem, "MOUNTS_PATH", str(mounts))
    result = filesystem.check_tmp_mount()
    assert result.status == Status.FAIL
    assert "noexec" in result.evidence


def test_check_tmp_mount_skipped_without_mounts_file(monkeypatch, tmp_path):
    monkeypatch.setattr(filesystem, "MOUNTS_PATH", str(tmp_path / "missing"))
    result = filesystem.check_tmp_mount()
    assert result.status == Status.SKIPPED


# Scanning real directories -------------------------------------------------


def test_iter_entries_lists_files_and_directories(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "file.txt").write_text("x")
    unreadable = []
    entries = list(filesystem.iter_entries([str(tmp_path)], unreadable))
    paths = []
    for path, mode in entries:
        paths.append(path)
    assert str(tmp_path / "sub") in paths
    assert str(tmp_path / "sub" / "file.txt") in paths
    assert unreadable == []


@skip_on_windows
def test_iter_entries_skips_symlinks(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "inside.txt").write_text("x")
    link = tmp_path / "link"
    os.symlink(str(target), str(link))

    unreadable = []
    entries = list(filesystem.iter_entries([str(tmp_path)], unreadable))
    paths = []
    for path, mode in entries:
        paths.append(path)

    assert str(link) not in paths
    assert str(link / "inside.txt") not in paths
    assert paths.count(str(target / "inside.txt")) == 1


def test_iter_entries_ignores_missing_roots(tmp_path):
    unreadable = []
    entries = list(filesystem.iter_entries([str(tmp_path / "missing")], unreadable))
    assert entries == []


@skip_on_windows
def test_world_writable_end_to_end(monkeypatch, tmp_path):
    bad = tmp_path / "bad.conf"
    bad.write_text("x")
    os.chmod(str(bad), 0o666)
    good = tmp_path / "good.conf"
    good.write_text("x")
    os.chmod(str(good), 0o644)

    monkeypatch.setattr(filesystem, "WORLD_WRITABLE_ROOTS", [str(tmp_path)])
    result = filesystem.check_world_writable()
    assert result.status == Status.FAIL
    assert "bad.conf" in result.evidence
    assert "good.conf" not in result.evidence


def test_world_writable_check_skipped_when_roots_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(
        filesystem, "WORLD_WRITABLE_ROOTS", [str(tmp_path / "missing")]
    )
    result = filesystem.check_world_writable()
    assert result.status == Status.SKIPPED


# Registry ----------------------------------------------------------------


def test_registered_checks():
    ids = []
    for check in CHECKS:
        ids.append(check.id)
    assert ids == ["FS-001", "FS-002", "FS-003", "FS-004", "FS-005"]
    for check in CHECKS:
        assert check.category == Category.FILESYSTEM
        assert check.remediation != ""


def test_requires_root_flags():
    needs_root = {}
    for check in CHECKS:
        needs_root[check.id] = check.requires_root
    assert needs_root == {
        "FS-001": False,
        "FS-002": True,
        "FS-003": True,
        "FS-004": False,
        "FS-005": False,
    }
    