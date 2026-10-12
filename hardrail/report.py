"""Terminal report: turns engine outcomes into readable text.

This module only formats. It knows nothing about how checks are run.
"""

from hardrail.models import Status

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
