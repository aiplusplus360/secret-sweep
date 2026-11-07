"""Detectors.

Two kinds, and the split matters:

  **structural**  a credential with a known prefix or format — `AKIA…`, `ghp_…`,
                  `-----BEGIN … PRIVATE KEY-----`. High confidence, low noise.

  **contextual**  a high-entropy value in an assignment position —
                  `password = "…"`. Higher recall, higher noise.

A report that mixes them without labelling them gets ignored within a week.
Each finding carries its `confidence` so a team can gate on high only.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import List, Optional

from .entropy import is_placeholder, looks_random

HIGH = "high"
MEDIUM = "medium"


@dataclass
class Detector:
    name: str
    pattern: "re.Pattern[str]"
    confidence: str = HIGH
    # Capturing group holding the secret; 0 means the whole match.
    group: int = 0


@dataclass
class Finding:
    detector: str
    confidence: str
    value: str
    line: str
    path: str = ""
    line_number: int = 0
    commit: str = ""
    author: str = ""
    date: str = ""

    @property
    def key(self) -> str:
        """Identity for baseline matching: detector + path + fingerprint.

        The fingerprint is a truncated SHA-256 of the matched value, never the
        value itself. A baseline file gets committed, so it must be safe to
        share: embedding even a few raw characters would leak part of every
        credential a team has already decided to accept.

        Hashing the whole value (not the neighbouring line numbers) keeps the
        key stable when unrelated edits shift lines around.
        """
        digest = hashlib.sha256(self.value.encode("utf-8")).hexdigest()[:12]
        return f"{self.detector}|{self.path}|{digest}"


# --- structural detectors ---------------------------------------------------

DETECTORS: List[Detector] = [
    Detector("aws-access-key-id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    Detector(
        "aws-secret-access-key",
        re.compile(r"(?i)aws[_\- ]?(?:secret[_\- ]?)?access[_\- ]?key\w*\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    ),
    Detector("github-pat", re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,})")),
    Detector("github-token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})")),
    Detector("gitlab-pat", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})")),
    Detector("slack-token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9\-]{10,})")),
    Detector("stripe-live", re.compile(r"\b(sk_live_[A-Za-z0-9]{20,})")),
    Detector("stripe-test", re.compile(r"\b(sk_test_[A-Za-z0-9]{20,})"), MEDIUM),
    Detector("openai-key", re.compile(r"\b(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})")),
    Detector(
        "private-key-block",
        re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)"),
    ),
    Detector(
        "jwt",
        re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"),
        MEDIUM,
    ),
    Detector(
        "google-api-key",
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})"),
    ),
    Detector(
        "connection-string",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:([^\s@/]{6,})@"
        ),
        HIGH,
        group=1,
    ),
    Detector(
        "basic-auth-url",
        re.compile(r"\bhttps?://[^\s:@/]+:([^\s@/]{8,})@[^\s/]+"),
        MEDIUM,
        group=1,
    ),
]

# --- contextual detectors ---------------------------------------------------

# Assignment to a secret-ish name. The value is then checked for entropy, so
# `password = "changeme"` and `password = "correct-horse"` are both rejected.
_CONTEXT = re.compile(
    r"""(?ix)
    \b(pass(?:word|wd|phrase)?|secret|token|api[_\-]?key|apikey|auth[_\-]?key|
       private[_\-]?key|access[_\-]?key|client[_\-]?secret|credential|passwd)
    \b\s*[:=]\s*
    ['"]([^'"\s]{8,})['"]
    """
)

# `export FOO=bar` and `FOO=bar` in a shell or .env file.
_ENV_ASSIGN = re.compile(
    r"""(?ix)^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)
    \s*=\s*['"]?([^\s'"]{8,})['"]?"""
)


def scan_line(line: str) -> List[Finding]:
    """Detect credentials in a single line."""
    findings: List[Finding] = []
    seen_values: set = set()

    for detector in DETECTORS:
        for match in detector.pattern.finditer(line):
            value = match.group(detector.group)
            if not value or value in seen_values:
                continue
            if is_placeholder(value):
                continue
            seen_values.add(value)
            findings.append(
                Finding(
                    detector=detector.name,
                    confidence=detector.confidence,
                    value=value,
                    line=line.strip()[:300],
                )
            )

    for pattern, label in ((_CONTEXT, "secret-assignment"), (_ENV_ASSIGN, "env-assignment")):
        for match in pattern.finditer(line):
            value = match.group(2)
            if value in seen_values or is_placeholder(value):
                continue
            if not looks_random(value):
                # Context alone is not enough; the value must also look like a
                # credential or the report fills with `password = "admin"`.
                continue
            seen_values.add(value)
            findings.append(
                Finding(
                    detector=label,
                    confidence=MEDIUM,
                    value=value,
                    line=line.strip()[:300],
                )
            )

    return findings


def detect_in_text(text: str, path: str = "", start_line: int = 0) -> List[Finding]:
    findings: List[Finding] = []
    for offset, line in enumerate(text.splitlines(), start=1):
        for finding in scan_line(line):
            finding.path = path
            finding.line_number = start_line + offset
            findings.append(finding)
    return findings
