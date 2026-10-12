from hardrail import cli
from hardrail.engine import Outcome
from hardrail.models import Category, Check, CheckResult, Severity, Status


def make_outcome(status):
    check = Check(
        id="T-001",
        title="Test check",
        category=Category.SSH,
        severity=Severity.LOW,
        run=lambda: CheckResult(status),
    )
    return Outcome(check=check, result=CheckResult(status, reason="x"))


def patch_engine(monkeypatch, outcomes):
    def fake_run_checks(checks=None, running_as_root=None):
        return outcomes

    monkeypatch.setattr(cli, "run_checks", fake_run_checks)
    monkeypatch.setattr(cli, "is_root", lambda: True)


def test_scan_exit_zero_when_all_pass(monkeypatch):
    patch_engine(monkeypatch, [make_outcome(Status.PASS)])
    assert cli.main(["scan", "--no-color"]) == 0


def test_scan_exit_one_when_fail(monkeypatch):
    patch_engine(monkeypatch, [make_outcome(Status.FAIL)])
    assert cli.main(["scan", "--no-color"]) == 1


def test_scan_exit_one_when_error(monkeypatch):
    patch_engine(monkeypatch, [make_outcome(Status.ERROR)])
    assert cli.main(["scan", "--no-color"]) == 1


def test_scan_prints_report(monkeypatch, capsys):
    patch_engine(monkeypatch, [make_outcome(Status.PASS)])
    cli.main(["scan", "--no-color"])
    captured = capsys.readouterr()
    assert "Summary:" in captured.out
    assert "T-001" in captured.out


def test_no_command_returns_two(capsys):
    assert cli.main([]) == 2
    