"""Reports: turn engine outcomes into text or JSON.

This module only formats. It knows nothing about how checks are run.
"""

import json
from datetime import datetime, timezone

from hardrail.models import Status
from hardrail.scoring import calculate_score

RESET = "\033[0m"

COLORS = {
    "bold": "\033[1m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "magenta": "\033[35m",
}

STATUS_COLORS = {
    Status.PASS: "green",
    Status.FAIL: "red",
    Status.SKIPPED: "yellow",
    Status.ERROR: "magenta",
}


def colorize(text, color, use_color):
    """Wrap text in ANSI color codes, or return it unchanged."""
    if use_color:
        return COLORS[color] + text + RESET
    else:
        return text


def count_statuses(outcomes):
    """Return how many outcomes there are for each Status."""
    counts = {}
    for status in Status:
        counts[status] = 0
    for outcome in outcomes:
        counts[outcome.result.status] += 1
    return counts


def format_outcome(outcome, use_color):
    """Format one check as a header line plus indented details."""
    check = outcome.check
    result = outcome.result

    # Pad first, color after: escape codes would break the alignment.
    status_text = result.status.name.ljust(7)
    status_text = colorize(status_text, STATUS_COLORS[result.status], use_color)

    header = (
        status_text
        + "  "
        + check.id.ljust(9)
        + check.severity.value.ljust(10)
        + check.title
    )
    lines = [header]

    if result.status == Status.FAIL:
        if result.evidence != "":
            lines.append("    evidence: " + result.evidence)
        if check.remediation != "":
            lines.append("    fix:      " + check.remediation)
    elif result.status == Status.SKIPPED or result.status == Status.ERROR:
        if result.reason != "":
            lines.append("    reason:   " + result.reason)

    return lines


def format_score_lines(score):
    """Format the score section: the number, its coverage and what lowered it."""
    lines = []

    if score.value is None:
        lines.append("Score: n/a (no check could be evaluated)")
        return lines

    lines.append(
        "Score: "
        + str(score.value)
        + "/100 (evaluated "
        + str(score.evaluated_checks)
        + " of "
        + str(score.total_checks)
        + " checks, coverage "
        + str(round(score.coverage, 1))
        + "%)"
    )

    if not score.complete:
        lines.append(
            "The score is partial: SKIPPED and ERROR checks are not counted."
        )

    if len(score.impacts) > 0:
        lines.append("Points lost:")
        for impact in score.impacts:
            lines.append(
                "  "
                + impact.check_id.ljust(9)
                + impact.severity.value.ljust(10)
                + "-"
                + str(impact.points_lost).ljust(7)
                + impact.title
            )

    return lines


def format_report(outcomes, running_as_root, version, use_color=False):
    """Build the full terminal report as a single string."""
    lines = []
    lines.append(
        colorize("hardrail " + version + " - risk assessment", "bold", use_color)
    )
    if running_as_root:
        lines.append("Running as root: yes")
    else:
        lines.append("Running as root: no (checks that need root are skipped)")
    lines.append("")

    if len(outcomes) == 0:
        lines.append("No checks found.")
        return "\n".join(lines)

    for outcome in outcomes:
        lines.extend(format_outcome(outcome, use_color))

    counts = count_statuses(outcomes)
    lines.append("")
    lines.append(
        "Summary: PASS "
        + str(counts[Status.PASS])
        + " | FAIL "
        + str(counts[Status.FAIL])
        + " | SKIPPED "
        + str(counts[Status.SKIPPED])
        + " | ERROR "
        + str(counts[Status.ERROR])
    )
    lines.extend(format_score_lines(calculate_score(outcomes)))

    skipped_for_root = 0
    for outcome in outcomes:
        if outcome.result.status == Status.SKIPPED:
            if outcome.check.requires_root and not running_as_root:
                skipped_for_root += 1
    if skipped_for_root > 0:
        lines.append(
            str(skipped_for_root)
            + " check(s) skipped because they need root. "
            + "Re-run with sudo for a complete assessment."
        )

    return "\n".join(lines)


def build_json_data(outcomes, running_as_root, version, generated_at=None):
    """Build the report as plain Python data (dicts and lists)."""
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    score = calculate_score(outcomes)
    counts = count_statuses(outcomes)

    impacts = []
    for impact in score.impacts:
        impacts.append(
            {
                "id": impact.check_id,
                "title": impact.title,
                "severity": impact.severity.value,
                "weight": impact.weight,
                "points_lost": impact.points_lost,
            }
        )

    checks = []
    for outcome in outcomes:
        checks.append(
            {
                "id": outcome.check.id,
                "title": outcome.check.title,
                "category": outcome.check.category.value,
                "severity": outcome.check.severity.value,
                "reference": outcome.check.reference,
                "requires_root": outcome.check.requires_root,
                "status": outcome.result.status.value,
                "evidence": outcome.result.evidence,
                "reason": outcome.result.reason,
                "remediation": outcome.check.remediation,
            }
        )

    return {
        "tool": "hardrail",
        "version": version,
        "generated_at": generated_at,
        "running_as_root": running_as_root,
        "summary": {
            "pass": counts[Status.PASS],
            "fail": counts[Status.FAIL],
            "skipped": counts[Status.SKIPPED],
            "error": counts[Status.ERROR],
        },
        "score": {
            "value": score.value,
            "passed_weight": score.passed_weight,
            "failed_weight": score.failed_weight,
            "evaluated_weight": score.evaluated_weight,
            "total_weight": score.total_weight,
            "coverage": round(score.coverage, 1),
            "evaluated_checks": score.evaluated_checks,
            "total_checks": score.total_checks,
            "complete": score.complete,
            "impacts": impacts,
        },
        "checks": checks,
    }


def format_json(outcomes, running_as_root, version, generated_at=None):
    """Build the report as a JSON string."""
    data = build_json_data(outcomes, running_as_root, version, generated_at)
    return json.dumps(data, indent=2, ensure_ascii=False)
