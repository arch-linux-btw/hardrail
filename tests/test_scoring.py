from hardrail.engine import Outcome
from hardrail.models import Category, Check, CheckResult, Severity, Status
from hardrail.scoring import calculate_score


def make_outcome(check_id, status, severity=Severity.HIGH):
    check = Check(
        id=check_id,
        title="Title of " + check_id,
        category=Category.SSH,
        severity=severity,
        run=lambda: CheckResult(status),
    )
    return Outcome(check=check, result=CheckResult(status))


def test_all_pass_gives_100():
    outcomes = [
        make_outcome("T-001", Status.PASS),
        make_outcome("T-002", Status.PASS, Severity.LOW),
    ]
    score = calculate_score(outcomes)
    assert score.value == 100.0
    assert score.complete
    assert score.impacts == []


def test_weights_decide_the_score():
    outcomes = [
        make_outcome("T-001", Status.PASS, Severity.LOW),
        make_outcome("T-002", Status.FAIL, Severity.CRITICAL),
    ]
    score = calculate_score(outcomes)
    # passed weight 1, failed weight 10 -> 1 / 11 = 9.1%
    assert score.value == 9.1
    assert score.impacts[0].check_id == "T-002"
    assert score.impacts[0].points_lost == 90.9


def test_skipped_is_excluded_but_lowers_coverage():
    outcomes = [
        make_outcome("T-001", Status.PASS, Severity.MEDIUM),
        make_outcome("T-002", Status.SKIPPED, Severity.HIGH),
    ]
    score = calculate_score(outcomes)
    assert score.value == 100.0
    assert score.total_weight == 8
    assert score.coverage == 37.5
    assert not score.complete


def test_error_is_excluded_and_never_counts_as_pass():
    outcomes = [
        make_outcome("T-001", Status.FAIL, Severity.MEDIUM),
        make_outcome("T-002", Status.ERROR, Severity.HIGH),
    ]
    score = calculate_score(outcomes)
    assert score.value == 0.0
    assert not score.complete


def test_nothing_evaluated_gives_none():
    outcomes = [make_outcome("T-001", Status.SKIPPED)]
    score = calculate_score(outcomes)
    assert score.value is None


def test_empty_list():
    score = calculate_score([])
    assert score.value is None
    assert score.total_weight == 0
    assert score.coverage == 0.0


def test_impacts_are_sorted_by_weight_then_id():
    outcomes = [
        make_outcome("T-001", Status.FAIL, Severity.LOW),
        make_outcome("T-003", Status.FAIL, Severity.HIGH),
        make_outcome("T-002", Status.FAIL, Severity.HIGH),
    ]
    score = calculate_score(outcomes)
    assert [impact.check_id for impact in score.impacts] == ["T-002", "T-003", "T-001"]
    