from hardrail.engine import Outcome
from hardrail.models import Category, Check, CheckResult, Severity, Status
from hardrail.report import format_report


def make_outcome(check_id, status, requires_root=False, evidence="", reason=""):
    check = Check(
        id=check_id,
        title="Title of " + check_id,
        category=Category.SSH,
        severity=Severity.HIGH,
        run=lambda: CheckResult(status),
        requires_root=requires_root,
        remediation="Fix for " + check_id,
    )
    result = CheckResult(status, evidence=evidence, reason=reason)
    return Outcome(check=check, result=result)


def sample_outcomes():
    return [
        make_outcome("T-001", Status.PASS),
        make_outcome("T-002", Status.FAIL, evidence="permitrootlogin = yes"),
        make_outcome(
            "T-003",
            Status.SKIPPED,
            requires_root=True,
            reason="requires root privileges",
        ),
    ]


def test_report_lists_every_check():
    text = format_report(sample_outcomes(), False, "0.1.0")
    assert "T-001" in text
    assert "T-002" in text
    assert "T-003" in text


def test_fail_shows_evidence_and_remediation():
    text = format_report(sample_outcomes(), False, "0.1.0")
    assert "permitrootlogin = yes" in text
    assert "Fix for T-002" in text


def test_skipped_shows_reason():
    text = format_report(sample_outcomes(), False, "0.1.0")
    assert "requires root privileges" in text


def test_summary_counts():
    text = format_report(sample_outcomes(), False, "0.1.0")
    assert "Summary: PASS 1 | FAIL 1 | SKIPPED 1 | ERROR 0" in text


def test_root_note_when_not_root():
    text = format_report(sample_outcomes(), False, "0.1.0")
    assert "Re-run with sudo" in text


def test_no_root_note_when_root():
    text = format_report(sample_outcomes(), True, "0.1.0")
    assert "Re-run with sudo" not in text


def test_no_color_has_no_escape_codes():
    text = format_report(sample_outcomes(), False, "0.1.0", use_color=False)
    assert "\033" not in text


def test_color_adds_escape_codes():
    text = format_report(sample_outcomes(), False, "0.1.0", use_color=True)
    assert "\033" in text


def test_empty_report():
    text = format_report([], True, "0.1.0")
    assert "No checks found." in text
    