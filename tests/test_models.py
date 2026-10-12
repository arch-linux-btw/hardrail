from hardrail.models import Category, Check, CheckResult, Severity, Status


def test_severity_weights_increase():
    assert Severity.LOW.weight < Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight < Severity.HIGH.weight
    assert Severity.HIGH.weight < Severity.CRITICAL.weight


def test_result_defaults():
    result = CheckResult(status=Status.PASS)
    assert result.evidence == ""
    assert result.reason == ""


def test_check_can_be_run():
    def fake_check():
        return CheckResult(status=Status.FAIL, evidence="PermitRootLogin yes")

    check = Check(
        id="TEST-001",
        title="Example check",
        category=Category.SSH,
        severity=Severity.HIGH,
        run=fake_check,
    )

    result = check.run()

    assert result.status == Status.FAIL
    assert check.requires_root is False
    