"""Find credentials in a repository and its history."""

__version__ = "0.1.0"

from .entropy import redact, shannon_entropy
from .git import GitError, dedupe, is_repo, scan_history, scan_working_tree
from .patterns import Finding, detect_in_text, scan_line

__all__ = [
    "Finding",
    "GitError",
    "dedupe",
    "detect_in_text",
    "is_repo",
    "redact",
    "scan_history",
    "scan_line",
    "scan_working_tree",
    "shannon_entropy",
]
