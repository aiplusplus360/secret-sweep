"""Scanning a git repository, including the parts you already deleted.

A secret removed in a later commit is still in the history and still leaked.
This is the whole reason the tool exists: `git log -p` is where the credentials
actually live, and `git rm` does not touch it.

History is walked with `git log -p` and only `+` lines are scanned, so a secret
is reported once — at the commit that introduced it — instead of once per
subsequent commit that happens to contain it.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .patterns import Finding, detect_in_text

_COMMIT = re.compile(r"^commit ([0-9a-f]{40})")
_AUTHOR = re.compile(r"^Author:\s*(.*)$")
_DATE = re.compile(r"^Date:\s*(.*)$")
_DIFF = re.compile(r"^diff --git a/(.*?) b/(.*)$")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

# Generated or vendored files produce enormous, credential-free noise.
_SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".whl", ".so", ".dll", ".exe", ".woff", ".woff2", ".ttf", ".eot",
    ".min.js", ".min.css", ".map", ".lock",
    # Compiled Python embeds the full text of its source, so scanning a .pyc
    # re-reports every fixture in the test suite.
    ".pyc", ".pyo", ".class", ".jar", ".o", ".a", ".pyd",
)
_SKIP_NAMES = {"package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock"}
# Version control and tool caches are never the source of truth.
_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".eggs",
}


class GitError(RuntimeError):
    """The git command failed — not a repository, or git is missing."""


def _run(args: List[str], cwd: Path) -> str:
    """Run a git subcommand. `args` excludes the leading `git`."""
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc

    if completed.returncode != 0:
        raise GitError(completed.stderr.strip() or f"git {' '.join(args)} failed")
    return completed.stdout


def is_repo(path: Path) -> bool:
    try:
        _run(["rev-parse", "--git-dir"], path)
        return True
    except GitError:
        return False


def _skippable(path: str) -> bool:
    lowered = path.lower()
    if any(lowered.endswith(suffix) for suffix in _SKIP_SUFFIXES):
        return True
    if Path(lowered).name in _SKIP_NAMES:
        return True
    parts = lowered.replace("\\", "/").split("/")
    return any(part in _SKIP_DIRS for part in parts)


def scan_working_tree(root: Path, max_bytes: int = 1_000_000) -> List[Finding]:
    """Scan files currently on disk."""
    findings: List[Finding] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if _skippable(relative):
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(detect_in_text(text, path=relative))
    return findings


@dataclass
class HistoryScan:
    findings: List[Finding] = field(default_factory=list)
    commits_scanned: int = 0
    files_scanned: int = 0


def scan_history(root: Path, max_commits: int = 5000) -> HistoryScan:
    """Walk every commit's diff and scan the added lines.

    Added lines only: a secret is reported where it was introduced, which is
    the commit that has to be rewritten if it is ever rotated properly.
    """
    result = HistoryScan()

    # `--all` covers every branch and tag, because a secret on an unmerged
    # branch is still pushed to the remote.
    output = _run(
        ["log", "--all", "--no-color", "-p", "--unified=0", "--format=%H%n%an%n%ad"],
        root,
    )

    commit = author = date = ""
    path = ""
    line_number = 0

    for line in output.splitlines():
        if _COMMIT.match(line):
            continue

        commit_match = re.match(r"^([0-9a-f]{40})$", line)
        if commit_match:
            commit = commit_match.group(1)
            result.commits_scanned += 1
            if result.commits_scanned > max_commits:
                break
            continue

        author_match = _AUTHOR.match(line)
        if author_match:
            author = author_match.group(1)
            continue

        date_match = _DATE.match(line)
        if date_match:
            date = date_match.group(1)
            continue

        diff_match = _DIFF.match(line)
        if diff_match:
            path = diff_match.group(2)
            result.files_scanned += 1
            line_number = 0
            continue

        hunk_match = _HUNK.match(line)
        if hunk_match:
            line_number = int(hunk_match.group(1))
            continue

        if not line.startswith("+") or line.startswith("+++"):
            continue
        if _skippable(path):
            continue

        for finding in detect_in_text(line, path=path, start_line=line_number - 1):
            finding.commit = commit[:12]
            finding.author = author
            finding.date = date
            result.findings.append(finding)
        line_number += 1

    return result


def dedupe(findings: Iterable[Finding]) -> List[Finding]:
    """Keep one finding per (detector, path, value).

    The same credential committed twenty times is one problem, and a report
    that lists it twenty times is one nobody reads to the end.
    """
    seen: Dict[Tuple[str, str, str], Finding] = {}
    for finding in findings:
        key = (finding.detector, finding.path, finding.value)
        if key not in seen:
            seen[key] = finding
        elif not seen[key].commit and finding.commit:
            # Prefer the record that names a commit.
            seen[key] = finding
    return sorted(
        seen.values(),
        key=lambda f: (f.confidence != "high", f.path, f.line_number),
    )
