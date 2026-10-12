"""Core data types shared by every other module of hardrail."""

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class Severity(Enum):
    """How serious a failed check is. Drives the weight in the score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        # Placeholder weights: to be tuned when we build the scoring.
        if self is Severity.LOW:
            return 1
        elif self is Severity.MEDIUM:
            return 3
        elif self is Severity.HIGH:
            return 5
        else:
            return 10


class Status(Enum):
    """Outcome of a single check."""

    PASS = "pass"
    FAIL = "fail"
    SKIPPED = "skipped"
    ERROR = "error"


class Category(Enum):
    """Area of the system a check belongs to."""

    IDENTITY = "identity"
    FILESYSTEM = "filesystem"
    PACKAGES = "packages"
    SSH = "ssh"


@dataclass
class CheckResult:
    """What a check returns: a status plus the proof behind it."""

    status: Status
    evidence: str = ""
    reason: str = ""  # used for SKIPPED and ERROR: why it did not run


@dataclass
class Check:
    """Definition of a single check. Running it must never modify the system."""

    id: str
    title: str
    category: Category
    severity: Severity
    run: Callable[[], CheckResult]
    reference: str = ""
    requires_root: bool = False
    remediation: str = ""
    