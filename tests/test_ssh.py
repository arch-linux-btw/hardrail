import subprocess

from hardrail.checks import ssh
from hardrail.checks.ssh import (
    CHECKS,
    evaluate_config_permissions,
    evaluate_empty_passwords,
    evaluate_max_auth_tries,
    evaluate_password_auth,
    evaluate_root_login,
    evaluate_x11_forwarding,
    parse_sshd_output,
)
from hardrail.models import Category, Status

SAMPLE_OUTPUT = """port 22
permitrootlogin no
passwordauthentication yes
permitemptypasswords no
maxauthtries 6
x11forwarding no
"""


def use_fake_sshd(monkeypatch, output):
    monkeypatch.setattr(ssh, "find_sshd", lambda: "/usr/sbin/sshd")
    monkeypatch.setattr(ssh, "read_sshd_config", lambda path: output)


# Parsing -----------------------------------------------------------------


def test_parse_sshd_output():
    config = parse_sshd_output(SAMPLE_OUTPUT)
    assert config["permitrootlogin"] == "no"
    assert config["port"] == "22"


# SSH-001 -----------------------------------------------------------------


def test_root_login_no_passes():
    result = evaluate_root_login({"permitrootlogin": "no"})
    assert result.status == Status.PASS


def test_root_login_yes_fails():
    result = evaluate_root_login({"permitrootlogin": "yes"})
    assert result.status == Status.FAIL
    assert "yes" in result.evidence


def test_root_login_prohibit_password_fails():
    result = evaluate_root_login({"permitrootlogin": "prohibit-password"})
    assert result.status == Status.FAIL


def test_root_login_missing_is_error():
    result = evaluate_root_login({})
    assert result.status == Status.ERROR


# SSH-002 -----------------------------------------------------------------


def test_password_auth_no_passes():
    result = evaluate_password_auth({"passwordauthentication": "no"})
    assert result.status == Status.PASS


def test_password_auth_yes_fails():
    result = evaluate_password_auth({"passwordauthentication": "yes"})
    assert result.status == Status.FAIL


# SSH-003 -----------------------------------------------------------------


def test_empty_passwords_no_passes():
    result = evaluate_empty_passwords({"permitemptypasswords": "no"})
    assert result.status == Status.PASS


def test_empty_passwords_yes_fails():
    result = evaluate_empty_passwords({"permitemptypasswords": "yes"})
    assert result.status == Status.FAIL


# SSH-004 -----------------------------------------------------------------


def test_permissions_600_root_passes():
    result = evaluate_config_permissions(0o100600, 0, 0)
    assert result.status == Status.PASS


def test_permissions_400_root_passes():
    result = evaluate_config_permissions(0o100400, 0, 0)
    assert result.status == Status.PASS


def test_permissions_644_fails():
    result = evaluate_config_permissions(0o100644, 0, 0)
    assert result.status == Status.FAIL
    assert "644" in result.evidence


def test_permissions_640_fails():
    result = evaluate_config_permissions(0o100640, 0, 0)
    assert result.status == Status.FAIL


def test_permissions_wrong_owner_fails():
    result = evaluate_config_permissions(0o100600, 1000, 1000)
    assert result.status == Status.FAIL
    assert "owner" in result.evidence


def test_permissions_check_skipped_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(ssh, "SSHD_CONFIG_PATH", str(tmp_path / "missing_config"))
    result = ssh.check_config_permissions()
    assert result.status == Status.SKIPPED


# SSH-005 -----------------------------------------------------------------


def test_max_auth_tries_at_limit_passes():
    result = evaluate_max_auth_tries({"maxauthtries": "4"})
    assert result.status == Status.PASS


def test_max_auth_tries_above_limit_fails():
    result = evaluate_max_auth_tries({"maxauthtries": "6"})
    assert result.status == Status.FAIL


def test_max_auth_tries_not_a_number_is_error():
    result = evaluate_max_auth_tries({"maxauthtries": "abc"})
    assert result.status == Status.ERROR


def test_max_auth_tries_missing_is_error():
    result = evaluate_max_auth_tries({})
    assert result.status == Status.ERROR


# SSH-006 -----------------------------------------------------------------


def test_x11_forwarding_no_passes():
    result = evaluate_x11_forwarding({"x11forwarding": "no"})
    assert result.status == Status.PASS


def test_x11_forwarding_yes_fails():
    result = evaluate_x11_forwarding({"x11forwarding": "yes"})
    assert result.status == Status.FAIL


# Shared sshd handling ------------------------------------------------------


def test_check_skipped_when_sshd_missing(monkeypatch):
    monkeypatch.setattr(ssh, "find_sshd", lambda: None)
    result = ssh.check_root_login()
    assert result.status == Status.SKIPPED


def test_check_error_when_sshd_times_out(monkeypatch):
    def raise_timeout(path):
        raise subprocess.TimeoutExpired(cmd="sshd", timeout=10)

    monkeypatch.setattr(ssh, "find_sshd", lambda: "/usr/sbin/sshd")
    monkeypatch.setattr(ssh, "read_sshd_config", raise_timeout)
    result = ssh.check_root_login()
    assert result.status == Status.ERROR


def test_check_error_when_sshd_fails(monkeypatch):
    def raise_sshd_error(path):
        raise ssh.SshdError("no hostkeys available")

    monkeypatch.setattr(ssh, "find_sshd", lambda: "/usr/sbin/sshd")
    monkeypatch.setattr(ssh, "read_sshd_config", raise_sshd_error)
    result = ssh.check_root_login()
    assert result.status == Status.ERROR
    assert "no hostkeys available" in result.reason


def test_full_flow_with_fake_sshd_output(monkeypatch):
    use_fake_sshd(monkeypatch, SAMPLE_OUTPUT)
    assert ssh.check_root_login().status == Status.PASS
    assert ssh.check_password_auth().status == Status.FAIL
    assert ssh.check_max_auth_tries().status == Status.FAIL


# Registry ----------------------------------------------------------------


def test_registered_checks():
    ids = [check.id for check in CHECKS]
    assert ids == [
        "SSH-001",
        "SSH-002",
        "SSH-003",
        "SSH-004",
        "SSH-005",
        "SSH-006",
    ]
    for check in CHECKS:
        assert check.category == Category.SSH
        assert check.remediation != ""
        