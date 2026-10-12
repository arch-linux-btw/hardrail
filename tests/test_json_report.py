import json

from hardrail.engine import Outcome
from hardrail.models import Category, Check, CheckResult, Severity, Status
from hardrail.report import build_json_data, format_json, format_report


def make_outcome(check_id, status, evidence="", reason=""):
    check = Check(
        id=check_id,
        title="Title of " + check_id,
        category=Category.SSH,
        severity=Severity.HIGH,
        run=lambda: CheckResult(status),
        reference="CIS test reference",
        requires_root=True,
        remediation="Fix for " + check_id,
    )
    result = CheckResult(status, evidence=evidence, reason=reason)
    return Outcome(check=check, result=result)


def sample_outcomes():
    return [
        make_outcome("T-001", Status.PASS, evidence="value = no"),
        make_outcome("T-002", Status.FAIL, evidence="value = yes"),
        make_outcome("T-003", Status.SKIPPED, reason="requires root privileges"),
    ]


def test_json_is_valid_and_has_main_sections():
    text = format_json(sample_outcomes(), True, "0.1.0")
    data = json.loads(text)
    assert data["tool"] == "hardrail"
    assert data["version"] == "0.1.0"
    assert data["running_as_root"] is True
    assert len(data["checks"]) == 3


def test_json_keeps_evidence_for_pass_too():
    data = build_json_data(sample_outcomes(), True, "0.1.0")
    first = data["checks"][0]
    assert first["status"] == "pass"
    assert first["evidence"] == "value = no"


def test_json_summary_and_score():
    data = build_json_data(sample_outcomes(), True, "0.1.0")
    assert data["summary"] == {"pass": 1, "fail": 1, "skipped": 1, "error": 0}
    assert data["score"]["value"] == 50.0
    assert data["score"]["complete"] is False
    assert data["score"]["impacts"][0]["id"] == "T-002"


def test_json_uses_given_timestamp():
    data = build_json_data(
        sample_outcomes(), True, "0.1.0", generated_at="2026-10-12T10:00:00+00:00"
    )
    assert data["generated_at"] == "2026-10-12T10:00:00+00:00"


def test_text_report_shows_score_and_points_lost():
    text = format_report(sample_outcomes(), True, "0.1.0")
    assert "Score: 50.0/100" in text
    assert "The score is partial" in text
    assert "Points lost:" in text
    