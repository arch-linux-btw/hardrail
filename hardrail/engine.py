"""Engine: discovers checks, runs them safely and collects the outcomes."""

import importlib
import os
import pkgutil
from dataclasses import dataclass

import hardrail.checks
from hardrail.models import Check, CheckResult, Status


@dataclass
class Outcome:
    """A check together with the result it produced."""

    check: Check
    result: CheckResult


def is_root():
    """True when running with root privileges (always False where unsupported)."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    else:
        return False


def discover_checks():
    """Collect the CHECKS list of every module inside hardrail/checks/.

    Adding a check means adding it to one file: no central list to update.
    """
    found = []
    seen_ids = set()

    for module_info in pkgutil.iter_modules(hardrail.checks.__path__):
        module = importlib.import_module("hardrail.checks." + module_info.name)
        module_checks = getattr(module, "CHECKS", [])

        for check in module_checks:
            if check.id in seen_ids:
                raise ValueError("duplicate check id: " + check.id)
            seen_ids.add(check.id)
            found.append(check)

    found.sort(key=lambda check: check.id)
    return found


def run_check(check, running_as_root):
    """Run one check and always return a CheckResult, never raise.

    - needs root but we are not root -> SKIPPED
    - the check crashes              -> ERROR (never a false PASS)
    - the check returns garbage      -> ERROR
    """
    if check.requires_root and not running_as_root:
        return CheckResult(Status.SKIPPED, reason="requires root privileges")

    try:
        result = check.run()
    except Exception as error:
        return CheckResult(
            Status.ERROR,
            reason="check crashed: " + type(error).__name__ + ": " + str(error),
        )

    if not isinstance(result, CheckResult):
        return CheckResult(Status.ERROR, reason="check returned an invalid result")

    return result


def run_checks(checks=None, running_as_root=None):
    """Run the given checks (all discovered ones by default) and return Outcomes."""
    if checks is None:
        checks = discover_checks()
    if running_as_root is None:
        running_as_root = is_root()

    outcomes = []
    for check in checks:
        result = run_check(check, running_as_root)
        outcomes.append(Outcome(check=check, result=result))
    return outcomes
