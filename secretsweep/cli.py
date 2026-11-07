"""CLI.

    secret-sweep .                    scan working tree + history
    secret-sweep . --history-only
    secret-sweep . --fail-on high      CI gate
    secret-sweep . --baseline .secret-baseline
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .entropy import redact
from .git import GitError, dedupe, is_repo, scan_history, scan_working_tree
from .patterns import Finding

EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_ERROR = 2

CONFIDENCE_ORDER = {"high": 0, "medium": 1}


def _load_baseline(path: Optional[str]) -> set:
    """A baseline of accepted findings, so a team can adopt the tool on a repo
    that already has secrets without fixing everything first."""
    if not path:
        return set()
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"warning: cannot read baseline {path}: {exc}", file=sys.stderr)
        return set()

    keys = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            keys.add(line)
    return keys


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    baseline = _load_baseline(args.baseline)

    findings: List[Finding] = []
    try:
        if not args.history_only:
            findings.extend(scan_working_tree(root))
        if not args.no_history:
            if is_repo(root):
                history = scan_history(root, max_commits=args.max_commits)
                findings.extend(history.findings)
                if not args.quiet:
                    print(
                        f"scanned {history.commits_scanned} commits "
                        f"({history.files_scanned} file changes)",
                        file=sys.stderr,
                    )
            elif not args.history_only:
                print("not a git repository; skipped history scan", file=sys.stderr)
    except GitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = dedupe(findings)

    # Apply confidence and baseline filters.
    findings = [
        f
        for f in findings
        if CONFIDENCE_ORDER[f.confidence] <= CONFIDENCE_ORDER[args.min_confidence]
        and f.key not in baseline
    ]

    if args.json:
        print(
            json.dumps(
                {
                    "findings": [
                        {
                            "detector": f.detector,
                            "confidence": f.confidence,
                            "path": f.path,
                            "line": f.line_number,
                            "commit": f.commit,
                            "author": f.author if args.show_author else None,
                            "redacted": redact(f.value),
                            "key": f.key,
                        }
                        for f in findings
                    ],
                    "count": len(findings),
                    "high": sum(1 for f in findings if f.confidence == "high"),
                },
                indent=2,
            )
        )
    elif not findings:
        print("no secrets found")
    else:
        for finding in findings:
            location = f"{finding.path}:{finding.line_number}" if finding.line_number else finding.path
            origin = f"  in commit {finding.commit}" if finding.commit else ""
            print(f"[{finding.confidence:^6}] {finding.detector:<22} {location}")
            print(f"         {redact(finding.value)}{origin}")
        high = sum(1 for f in findings if f.confidence == "high")
        print()
        print(f"{len(findings)} finding(s), {high} high confidence")
        print("values are truncated on purpose: a scanner that prints the secret")
        print("has made a second copy of the problem")

    if args.write_baseline:
        Path(args.write_baseline).write_text(
            "# secret-sweep baseline — reviewed and accepted\n"
            + "\n".join(sorted(f.key for f in findings))
            + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote baseline: {args.write_baseline}", file=sys.stderr)
        # Adopting the tool on a repo with existing secrets is the whole point
        # of this flag: the user just reviewed the findings and accepted them.
        # Exiting non-zero here would abort the documented `set -e` adoption
        # flow at the exact moment it succeeded.
        return EXIT_CLEAN

    threshold = CONFIDENCE_ORDER[args.fail_on]
    if any(CONFIDENCE_ORDER[f.confidence] <= threshold for f in findings):
        return EXIT_FOUND
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-sweep",
        description="Find credentials in a repo — including its history.",
    )
    parser.add_argument("--version", action="version", version=__version__)

    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--history-only", action="store_true")
    parser.add_argument("--no-history", action="store_true")
    parser.add_argument("--max-commits", type=int, default=5000)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--show-author", action="store_true")
    parser.add_argument(
        "--min-confidence", choices=["high", "medium"], default="medium"
    )
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium"],
        default="high",
        help="exit 1 at this confidence or above",
    )
    parser.add_argument("--baseline", help="file of accepted finding keys")
    parser.add_argument("--write-baseline", help="write current findings as a baseline")
    parser.set_defaults(func=cmd_scan)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
