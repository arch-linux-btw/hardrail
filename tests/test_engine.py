from hardrail.engine import discover_checks, run_check, run_checks
from hardrail.models import Category, Check, CheckResult, Severity, Status


def make_check(run, check_id="TEST-001", requires_root=False):
    return Check(
        id=check_id,
        title="Test check",
        category=Category.SSH,
        severity=Severity.LOW,
        run=run,
        requires_root=requires_root,
    )


def passing():
    return CheckResult(Status.PASS, evidence="all good")


def crashing():
    raise RuntimeError("boom")


def invalid():
    return "not a CheckResult"


def test_root_check_is_skipped_when_not_root():
    check = make_check(passing, requires_root=True)
    result = run_check(check, running_as_root=False)
    assert result.status == Status.SKIPPED
    assert "root" in result.reason


def test_root_check_runs_when_root():
    check = make_check(passing, requires_root=True)
    result = run_check(check, running_as_root=True)
    assert result.status == Status.PASS


def test_non_root_check_runs_without_root():
    check = make_check(passing)
    result = run_check(check, running_as_root=False)
    assert result.status == Status.PASS


def test_crashing_check_becomes_error():
    check = make_check(crashing)
    result = run_check(check, running_as_root=True)
    assert result.status == Status.ERROR
    assert "boom" in result.reason


def test_invalid_result_becomes_error():
    check = make_check(invalid)
    result = run_check(check, running_as_root=True)
    assert result.status == Status.ERROR


def test_run_checks_returns_one_outcome_per_check():
    checks = [
        make_check(passing, check_id="TEST-001"),
        make_check(passing, check_id="TEST-002", requires_root=True),
    ]
    outcomes = run_checks(checks, running_as_root=False)
    assert [o.check.id for o in outcomes] == ["TEST-001", "TEST-002"]
    assert [o.result.status for o in outcomes] == [Status.PASS, Status.SKIPPED]


def test_discover_finds_ssh_check():
    ids = [check.id for check in discover_checks()]
    assert "SSH-001" in ids