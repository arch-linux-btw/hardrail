"""Command line interface. Parses arguments and calls the engine."""

import argparse
import os
import sys

from hardrail import __version__
from hardrail.engine import is_root, run_checks
from hardrail.models import Status
from hardrail.report import format_report


def build_parser():
    parser = argparse.ArgumentParser(
        prog="hardrail",
        description="Local Linux server risk assessment tool (read-only).",
    )
    parser.add_argument(
        "--version", action="version", version="hardrail " + __version__
    )

    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="run all checks and print a report")
    scan.add_argument(
        "--no-color", action="store_true", help="disable colored output"
    )

    return parser


def should_use_color(no_color_flag):
    """Color only on a real terminal, and never if the user opted out."""
    if no_color_flag:
        return False
    if "NO_COLOR" in os.environ:
        return False
    return sys.stdout.isatty()


def cmd_scan(args):
    running_as_root = is_root()
    outcomes = run_checks(running_as_root=running_as_root)

    report = format_report(
        outcomes,
        running_as_root=running_as_root,
        version=__version__,
        use_color=should_use_color(args.no_color),
    )
    print(report)

    # Exit code: 0 = nothing wrong found, 1 = at least one FAIL or ERROR.
    exit_code = 0
    for outcome in outcomes:
        if outcome.result.status == Status.FAIL:
            exit_code = 1
        elif outcome.result.status == Status.ERROR:
            exit_code = 1
    return exit_code


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return cmd_scan(args)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())
    