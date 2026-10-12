"""Scoring: turns check outcomes into an explainable risk score.

The score is the percentage of passed weight over the weight of the
evaluated checks (PASS or FAIL). SKIPPED and ERROR checks are left out of
the calculation, but they lower the coverage so the score is never
presented as more complete than it is.
"""

from dataclasses import dataclass, field

from hardrail.models import Severity, Status


@dataclass
class Impact:
    """How many points a single failed check took away from the score."""

    check_id: str
    title: str
    severity: Severity
    weight: int
    points_lost: float


@dataclass
class Score:
    value: float | None  # None when no check could be evaluated
    passed_weight: int
    failed_weight: int
    total_weight: int  # weight of every check, evaluated or not
    evaluated_checks: int
    total_checks: int
    impacts: list = field(default_factory=list)

    @property
    def evaluated_weight(self):
        return self.passed_weight + self.failed_weight

    @property
    def coverage(self):
        """Percentage of the total weight that was actually evaluated."""
        if self.total_weight == 0:
            return 0.0
        else:
            return self.evaluated_weight / self.total_weight * 100

    @property
    def complete(self):
        """True when every check was evaluated (no SKIPPED, no ERROR)."""
        return self.evaluated_checks == self.total_checks


def calculate_score(outcomes):
    """Compute the Score for a list of engine Outcomes."""
    passed_weight = 0
    failed_weight = 0
    total_weight = 0
    evaluated_checks = 0
    failed = []

    for outcome in outcomes:
        weight = outcome.check.severity.weight
        total_weight += weight
        status = outcome.result.status

        if status == Status.PASS:
            passed_weight += weight
            evaluated_checks += 1
        elif status == Status.FAIL:
            failed_weight += weight
            evaluated_checks += 1
            failed.append(outcome)

    evaluated_weight = passed_weight + failed_weight

    if evaluated_weight == 0:
        value = None
    else:
        value = round(passed_weight / evaluated_weight * 100, 1)

    impacts = []
    for outcome in failed:
        weight = outcome.check.severity.weight
        impacts.append(
            Impact(
                check_id=outcome.check.id,
                title=outcome.check.title,
                severity=outcome.check.severity,
                weight=weight,
                points_lost=round(weight / evaluated_weight * 100, 1),
            )
        )
    # Biggest impact first, then by id so the order is stable.
    impacts.sort(key=lambda impact: (-impact.weight, impact.check_id))

    return Score(
        value=value,
        passed_weight=passed_weight,
        failed_weight=failed_weight,
        total_weight=total_weight,
        evaluated_checks=evaluated_checks,
        total_checks=len(outcomes),
        impacts=impacts,
    )
