from hardrail.checks.ssh import evaluate_root_login, parse_sshd_output
from hardrail.models import Status

SAMPLE_OUTPUT = """port 22
permitrootlogin no
passwordauthentication yes
x11forwarding no
"""


def test_parse_sshd_output():
    config = parse_sshd_output(SAMPLE_OUTPUT)
    assert config["permitrootlogin"] == "no"
    assert config["port"] == "22"


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
    