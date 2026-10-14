import os

from hardrail.checks import identity
from hardrail.checks.identity import (
    CHECKS,
    PasswdEntry,
    ShadowEntry,
    evaluate_empty_passwords,
    evaluate_password_max_days,
    evaluate_sudoers,
    evaluate_system_shells,
    evaluate_uid_zero,
    find_nopasswd_rules,
    logical_lines,
    parse_login_defs,
    parse_passwd,
    parse_shadow,
    read_sudoers_files,
)
from hardrail.models import Category, Status

PASSWD_SAMPLE = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# a comment

broken line
alice:x:1000:1000:Alice:/home/alice:/bin/bash
"""

SHADOW_SAMPLE = """root:$6$abc$hashvalue:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
locked:!:19000:0:99999:7:::
alice:$y$j9T$secret:19000:0:99999:7:::
"""

EMPTY_SHADOW = """guest::19000:0:99999:7:::
root:$6$topsecret$hash:19000:0:99999:7:::
"""


# Parsing -----------------------------------------------------------------


def test_parse_passwd_reads_valid_lines():
    entries = parse_passwd(PASSWD_SAMPLE)
    assert [entry.name for entry in entries] == ["root", "daemon", "alice"]
    assert entries[0].uid == 0
    assert entries[1].shell == "/usr/sbin/nologin"


def test_parse_passwd_keeps_empty_shell():
    entries = parse_passwd("svc:x:500:500::/var/svc:\n")
    assert entries[0].name == "svc"
    assert entries[0].shell == ""


def test_parse_shadow_reads_names_and_password_fields():
    entries = parse_shadow(SHADOW_SAMPLE)
    assert [entry.name for entry in entries] == ["root", "daemon", "locked", "alice"]
    assert entries[0].password.startswith("$6$")
    assert entries[1].password == "*"


# USR-001 -----------------------------------------------------------------


def test_uid_zero_only_root_passes():
    result = evaluate_uid_zero(parse_passwd(PASSWD_SAMPLE))
    assert result.status == Status.PASS


def test_uid_zero_extra_account_fails():
    entries = [PasswdEntry("root", 0, "/bin/bash"), PasswdEntry("toor", 0, "/bin/sh")]
    result = evaluate_uid_zero(entries)
    assert result.status == Status.FAIL
    assert "toor" in result.evidence


def test_uid_zero_no_entries_is_error():
    result = evaluate_uid_zero([])
    assert result.status == Status.ERROR


# USR-002 -----------------------------------------------------------------


def test_empty_passwords_none_passes():
    result = evaluate_empty_passwords(parse_shadow(SHADOW_SAMPLE))
    assert result.status == Status.PASS


def test_empty_passwords_found_fails():
    result = evaluate_empty_passwords(parse_shadow(EMPTY_SHADOW))
    assert result.status == Status.FAIL
    assert "guest" in result.evidence


def test_empty_passwords_evidence_never_contains_hash():
    result = evaluate_empty_passwords(parse_shadow(EMPTY_SHADOW))
    assert "topsecret" not in result.evidence
    assert "$6$" not in result.evidence


def test_empty_passwords_no_entries_is_error():
    result = evaluate_empty_passwords([])
    assert result.status == Status.ERROR


# USR-003 -----------------------------------------------------------------


def test_logical_lines_joins_continuations():
    lines = logical_lines("alice ALL=(ALL) \\\n NOPASSWD: ALL\nbob ALL=(ALL) ALL\n")
    assert len(lines) == 2
    assert "NOPASSWD" in lines[0]


def test_find_nopasswd_detects_rule():
    rules = find_nopasswd_rules("%sudo ALL=(ALL) NOPASSWD: ALL\n")
    assert len(rules) == 1
    assert "%sudo" in rules[0]


def test_find_nopasswd_detects_rule_split_over_two_lines():
    rules = find_nopasswd_rules("alice ALL=(ALL) \\\n NOPASSWD: ALL\n")
    assert len(rules) == 1


def test_find_nopasswd_ignores_comments():
    text = "# alice ALL=(ALL) NOPASSWD: ALL\nalice ALL=(ALL) ALL\n"
    assert find_nopasswd_rules(text) == []


def test_sudoers_without_nopasswd_passes():
    files = [("/etc/sudoers", "root ALL=(ALL) ALL\n")]
    result = evaluate_sudoers(files)
    assert result.status == Status.PASS


def test_sudoers_with_nopasswd_fails():
    files = [
        ("/etc/sudoers", "root ALL=(ALL) ALL\n"),
        ("/etc/sudoers.d/90-cloud", "ubuntu ALL=(ALL) NOPASSWD:ALL\n"),
    ]
    result = evaluate_sudoers(files)
    assert result.status == Status.FAIL
    assert "/etc/sudoers.d/90-cloud" in result.evidence
    assert "NOPASSWD" in result.evidence


def test_read_sudoers_files_skips_ignored_names(monkeypatch, tmp_path):
    main = tmp_path / "sudoers"
    main.write_text("root ALL=(ALL) ALL\n")
    directory = tmp_path / "sudoers.d"
    directory.mkdir()
    (directory / "10-admins").write_text("%sudo ALL=(ALL) ALL\n")
    (directory / "notes.txt").write_text("ignored because of the dot\n")
    (directory / "old~").write_text("ignored because of the tilde\n")
    (directory / "subdir").mkdir()

    monkeypatch.setattr(identity, "SUDOERS_PATH", str(main))
    monkeypatch.setattr(identity, "SUDOERS_DIR", str(directory))

    files = read_sudoers_files()
    names = [os.path.basename(path) for path, text in files]
    assert names == ["sudoers", "10-admins"]


def test_sudoers_check_skipped_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(identity, "SUDOERS_PATH", str(tmp_path / "missing"))
    result = identity.check_sudo_nopasswd()
    assert result.status == Status.SKIPPED


# USR-005 -----------------------------------------------------------------


def test_parse_login_defs_ignores_comments_and_last_wins():
    text = "PASS_MAX_DAYS 99999\n# PASS_MAX_DAYS 10\nPASS_MAX_DAYS   90\n"
    defs = parse_login_defs(text)
    assert defs["PASS_MAX_DAYS"] == "90"


def test_max_days_90_passes():
    result = evaluate_password_max_days({"PASS_MAX_DAYS": "90"})
    assert result.status == Status.PASS


def test_max_days_365_passes():
    result = evaluate_password_max_days({"PASS_MAX_DAYS": "365"})
    assert result.status == Status.PASS


def test_max_days_366_fails():
    result = evaluate_password_max_days({"PASS_MAX_DAYS": "366"})
    assert result.status == Status.FAIL


def test_max_days_default_value_fails():
    result = evaluate_password_max_days({"PASS_MAX_DAYS": "99999"})
    assert result.status == Status.FAIL


def test_max_days_missing_fails():
    result = evaluate_password_max_days({})
    assert result.status == Status.FAIL
    assert "not set" in result.evidence


def test_max_days_not_a_number_is_error():
    result = evaluate_password_max_days({"PASS_MAX_DAYS": "abc"})
    assert result.status == Status.ERROR


def test_max_days_zero_fails():
    result = evaluate_password_max_days({"PASS_MAX_DAYS": "0"})
    assert result.status == Status.FAIL


def test_max_days_negative_fails():
    result = evaluate_password_max_days({"PASS_MAX_DAYS": "-1"})
    assert result.status == Status.FAIL


# USR-006 -----------------------------------------------------------------


def test_system_shells_flags_login_shells():
    entries = [
        PasswdEntry("root", 0, "/bin/bash"),
        PasswdEntry("daemon", 1, "/usr/sbin/nologin"),
        PasswdEntry("postgres", 999, "/bin/bash"),
        PasswdEntry("sync", 4, "/bin/sync"),
        PasswdEntry("alice", 1000, "/bin/bash"),
        PasswdEntry("svc", 500, ""),
    ]
    result = evaluate_system_shells(entries)
    assert result.status == Status.FAIL
    assert "postgres (/bin/bash)" in result.evidence
    assert "svc" in result.evidence
    assert "root" not in result.evidence
    assert "alice" not in result.evidence
    assert "daemon" not in result.evidence
    assert "sync" not in result.evidence


def test_system_shells_all_nologin_passes():
    entries = [
        PasswdEntry("root", 0, "/bin/bash"),
        PasswdEntry("daemon", 1, "/usr/sbin/nologin"),
        PasswdEntry("bin", 2, "/bin/false"),
    ]
    result = evaluate_system_shells(entries)
    assert result.status == Status.PASS


# Wrappers reading real files -----------------------------------------------


def test_uid_zero_check_reads_passwd_file(monkeypatch, tmp_path):
    passwd = tmp_path / "passwd"
    passwd.write_text(PASSWD_SAMPLE)
    monkeypatch.setattr(identity, "PASSWD_PATH", str(passwd))
    assert identity.check_uid_zero().status == Status.PASS


def test_uid_zero_check_skipped_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(identity, "PASSWD_PATH", str(tmp_path / "missing"))
    assert identity.check_uid_zero().status == Status.SKIPPED


def test_empty_passwords_check_reads_shadow_file(monkeypatch, tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text(EMPTY_SHADOW)
    monkeypatch.setattr(identity, "SHADOW_PATH", str(shadow))
    result = identity.check_empty_passwords()
    assert result.status == Status.FAIL
    assert "guest" in result.evidence


# Registry ----------------------------------------------------------------


def test_registered_checks():
    ids = [check.id for check in CHECKS]
    assert ids == ["USR-001", "USR-002", "USR-003", "USR-005", "USR-006"]
    for check in CHECKS:
        assert check.category == Category.IDENTITY
        assert check.remediation != ""


def test_requires_root_flags():
    needs_root = {}
    for check in CHECKS:
        needs_root[check.id] = check.requires_root
    assert needs_root == {
        "USR-001": False,
        "USR-002": True,
        "USR-003": True,
        "USR-005": False,
        "USR-006": False,
    }
    