import subprocess

from hardrail.checks import packages
from hardrail.checks.packages import (
    CHECKS,
    evaluate_auto_updates,
    evaluate_insecure_packages,
    evaluate_security_updates,
    parse_apt_upgrades,
    parse_installed_packages,
    parse_unattended_setting,
    read_apt_conf_text,
)
from hardrail.models import Category, Status

APT_SAMPLE = """Reading package lists...
NOTE: This is only a simulation!
Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst vim [2:8.2-1] (2:8.2-2 Ubuntu:22.04/jammy-updates [amd64])
Conf openssl (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
"""

DPKG_SAMPLE = "bash ii \ntelnetd ii \nold-tool rc \nghost un \n"


def fake_tools_present(monkeypatch):
    monkeypatch.setattr(packages.shutil, "which", lambda name: "/usr/bin/" + name)


def fake_tools_missing(monkeypatch):
    monkeypatch.setattr(packages.shutil, "which", lambda name: None)


# PKG-001 -----------------------------------------------------------------


def test_parse_apt_upgrades_reads_inst_lines_only():
    upgrades = parse_apt_upgrades(APT_SAMPLE)
    assert upgrades == [("openssl", True), ("vim", False)]


def test_security_updates_none_passes():
    result = evaluate_security_updates([("vim", False)])
    assert result.status == Status.PASS


def test_security_updates_found_fails():
    result = evaluate_security_updates([("openssl", True), ("vim", False)])
    assert result.status == Status.FAIL
    assert "openssl" in result.evidence
    assert "vim" not in result.evidence


def test_security_updates_empty_output_passes():
    result = evaluate_security_updates(parse_apt_upgrades(""))
    assert result.status == Status.PASS


def test_security_updates_truncates_long_lists():
    upgrades = []
    for number in range(15):
        upgrades.append(("pkg" + str(number), True))
    result = evaluate_security_updates(upgrades)
    assert result.status == Status.FAIL
    assert "15 security update(s)" in result.evidence
    assert "and 5 more" in result.evidence


def test_security_check_skipped_without_apt(monkeypatch):
    fake_tools_missing(monkeypatch)
    result = packages.check_security_updates()
    assert result.status == Status.SKIPPED
    assert "Debian/Ubuntu" in result.reason


def test_security_check_error_when_command_fails(monkeypatch):
    def fail(args):
        raise packages.CommandError("could not get lock")

    fake_tools_present(monkeypatch)
    monkeypatch.setattr(packages, "run_command", fail)
    result = packages.check_security_updates()
    assert result.status == Status.ERROR
    assert "could not get lock" in result.reason


def test_security_check_error_on_timeout(monkeypatch):
    def timeout(args):
        raise subprocess.TimeoutExpired(cmd="apt-get", timeout=60)

    fake_tools_present(monkeypatch)
    monkeypatch.setattr(packages, "run_command", timeout)
    result = packages.check_security_updates()
    assert result.status == Status.ERROR


def test_security_check_full_flow(monkeypatch):
    fake_tools_present(monkeypatch)
    monkeypatch.setattr(packages, "run_command", lambda args: APT_SAMPLE)
    result = packages.check_security_updates()
    assert result.status == Status.FAIL
    assert "openssl" in result.evidence


# PKG-002 -----------------------------------------------------------------


def test_parse_installed_packages_keeps_only_installed():
    installed = parse_installed_packages(DPKG_SAMPLE)
    assert installed == {"bash", "telnetd"}


def test_parse_installed_packages_ignores_malformed_lines():
    installed = parse_installed_packages("justoneword\n\nbash ii \n")
    assert installed == {"bash"}


def test_insecure_packages_none_passes():
    result = evaluate_insecure_packages({"bash", "openssh-server"})
    assert result.status == Status.PASS


def test_insecure_packages_found_fails():
    result = evaluate_insecure_packages({"bash", "telnetd", "xinetd"})
    assert result.status == Status.FAIL
    assert "telnetd" in result.evidence
    assert "xinetd" in result.evidence
    assert "bash" not in result.evidence


def test_insecure_package_list_contains_telnetd():
    assert "telnetd" in packages.INSECURE_PACKAGES


def test_insecure_check_skipped_without_dpkg(monkeypatch):
    fake_tools_missing(monkeypatch)
    result = packages.check_insecure_packages()
    assert result.status == Status.SKIPPED


def test_insecure_check_full_flow(monkeypatch):
    fake_tools_present(monkeypatch)
    monkeypatch.setattr(packages, "run_command", lambda args: DPKG_SAMPLE)
    result = packages.check_insecure_packages()
    assert result.status == Status.FAIL
    assert "telnetd" in result.evidence


# PKG-003 -----------------------------------------------------------------


def test_parse_unattended_setting_ignores_comments():
    text = '// APT::Periodic::Unattended-Upgrade "0";\nAPT::Periodic::Unattended-Upgrade "1";\n'
    assert parse_unattended_setting(text) == "1"


def test_parse_unattended_setting_missing_is_none():
    assert parse_unattended_setting('APT::Periodic::Update-Package-Lists "1";\n') is None


def test_parse_unattended_setting_last_wins():
    text = 'APT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Unattended-Upgrade "0";\n'
    assert parse_unattended_setting(text) == "0"


def test_auto_updates_package_missing_fails():
    result = evaluate_auto_updates({"bash"}, "1")
    assert result.status == Status.FAIL
    assert "not installed" in result.evidence


def test_auto_updates_setting_missing_fails():
    result = evaluate_auto_updates({"unattended-upgrades"}, None)
    assert result.status == Status.FAIL
    assert "not set" in result.evidence


def test_auto_updates_enabled_passes():
    result = evaluate_auto_updates({"unattended-upgrades"}, "1")
    assert result.status == Status.PASS


def test_auto_updates_disabled_fails():
    result = evaluate_auto_updates({"unattended-upgrades"}, "0")
    assert result.status == Status.FAIL


def test_auto_updates_unexpected_value_is_error():
    result = evaluate_auto_updates({"unattended-upgrades"}, "abc")
    assert result.status == Status.ERROR


def test_read_apt_conf_text_reads_files_in_order(monkeypatch, tmp_path):
    (tmp_path / "20auto").write_text('APT::Periodic::Unattended-Upgrade "1";\n')
    (tmp_path / "10first").write_text("// first file\n")
    (tmp_path / "subdir").mkdir()
    monkeypatch.setattr(packages, "APT_CONF_DIR", str(tmp_path))
    text = read_apt_conf_text()
    assert text.index("first file") < text.index("Unattended-Upgrade")


def test_auto_updates_check_skipped_without_dpkg(monkeypatch):
    fake_tools_missing(monkeypatch)
    result = packages.check_auto_updates()
    assert result.status == Status.SKIPPED


def test_auto_updates_check_full_flow(monkeypatch, tmp_path):
    (tmp_path / "20auto-upgrades").write_text('APT::Periodic::Unattended-Upgrade "1";\n')
    fake_tools_present(monkeypatch)
    monkeypatch.setattr(packages, "APT_CONF_DIR", str(tmp_path))
    monkeypatch.setattr(packages, "run_command", lambda args: "unattended-upgrades ii \n")
    result = packages.check_auto_updates()
    assert result.status == Status.PASS


# Registry ----------------------------------------------------------------


def test_registered_checks():
    ids = []
    for check in CHECKS:
        ids.append(check.id)
    assert ids == ["PKG-001", "PKG-002", "PKG-003"]
    for check in CHECKS:
        assert check.category == Category.PACKAGES
        assert check.remediation != ""


def test_requires_root_flags():
    for check in CHECKS:
        assert check.requires_root is False
        