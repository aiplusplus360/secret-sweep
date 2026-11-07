"""Tests for detection, entropy, redaction, and history scanning.

The tests that matter most here are the *negative* ones. A secret scanner that
cries wolf gets switched off within a week, and then it protects nothing — so
placeholder rejection and false-positive control are first-class behaviour, not
polish.

**Why the fixtures are assembled instead of written out.** A committed file
containing a string that is indistinguishable from a live credential is
indistinguishable from a credential leak: GitHub push protection blocks it, and
it is right to. Building the strings from fragments at runtime keeps the tests
readable while leaving this source file inert to any scanner pointed at it.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

from secretsweep.entropy import is_placeholder, looks_random, redact, shannon_entropy
from secretsweep.git import dedupe, scan_history, scan_working_tree
from secretsweep.patterns import Finding, detect_in_text, scan_line


def _fixture(*parts):
    """Assemble a credential-shaped string at runtime. See module docstring."""
    return "".join(parts)


AWS_KEY = _fixture("AKIA", "4RTZ7KLM2NOPQ3RS")
AWS_KEY_OTHER = _fixture("AKIA", "7YHN5WQZL9XCV2BM")
AWS_EXAMPLE = _fixture("AKIA", "IOSFODNN7EXAMPLE")
STRIPE_KEY = _fixture("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dcSECRET")
GITHUB_PAT = _fixture("github", "_pat_", "11CTZEWAA0eO1m9X3KbvBS_abcdefghij")
DB_PASSWORD = _fixture("hunter2", "hunter2")
DB_URL = _fixture("postgres://admin:", DB_PASSWORD, "@db.internal:5432/app")
PRIVATE_KEY_HEADER = _fixture("-----BEGIN ", "RSA PRIVATE KEY-----")
ENTROPY_VALUE = "k3J9xQ2mP7vL4nR8zW"


def detectors_in(line):
    return {finding.detector for finding in scan_line(line)}


class TestEntropy(unittest.TestCase):
    def test_uniform_string_is_zero(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_random_is_higher_than_english(self):
        self.assertGreater(
            shannon_entropy("k3J9xQ2mP7vL4nR8"),
            shannon_entropy("passwordpassword"),
        )

    def test_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_looks_random_requires_mixed_classes(self):
        self.assertTrue(looks_random("k3J9xQ2mP7vL4nR8"))
        self.assertFalse(looks_random("abcdefghijklmnop"))     # no digits
        self.assertFalse(looks_random("123456789012345678"))   # no letters
        self.assertFalse(looks_random("short1"))               # too short

    def test_low_entropy_rejected(self):
        self.assertFalse(looks_random("aaaaaaaaaaaa1"))


class TestPlaceholders(unittest.TestCase):
    def test_env_var_forms(self):
        for value in ("${TOKEN}", "<YOUR_TOKEN>", "%API_KEY%", "{{ secret }}"):
            self.assertTrue(is_placeholder(value), value)

    def test_obvious_placeholders(self):
        for value in ("changeme", "your_token", "xxxxxxxx", "TODO", "null"):
            self.assertTrue(is_placeholder(value), value)

    def test_repeated_character(self):
        self.assertTrue(is_placeholder("aaaaaaaaaaaa"))

    def test_real_credential_is_not_a_placeholder(self):
        self.assertFalse(is_placeholder(AWS_KEY))

    def test_known_safe_values(self):
        self.assertTrue(is_placeholder(AWS_EXAMPLE))


class TestRedact(unittest.TestCase):
    def test_keeps_prefix_only(self):
        redacted = redact(AWS_KEY)
        self.assertTrue(redacted.startswith("AKIA"))
        self.assertIn("chars", redacted)

    def test_never_contains_full_value(self):
        self.assertNotIn(STRIPE_KEY, redact(STRIPE_KEY))

    def test_short_value_fully_masked(self):
        self.assertEqual(redact("abc"), "***")


class TestStructuralDetection(unittest.TestCase):
    def test_aws_key(self):
        self.assertIn(
            "aws-access-key-id",
            detectors_in(f"key = {AWS_KEY}"),
        )

    def test_github_pat(self):
        self.assertIn("github-pat", detectors_in(f"token: {GITHUB_PAT}"))

    def test_github_classic_token(self):
        self.assertIn(
            "github-token",
            detectors_in(f"ghp_{'a' * 36}"),
        )

    def test_private_key_block(self):
        self.assertIn("private-key-block", detectors_in(PRIVATE_KEY_HEADER))

    def test_slack_token(self):
        self.assertIn("slack-token", detectors_in("xoxb-" + "1234567890-abcdefghij"))

    def test_connection_string_password(self):
        findings = scan_line(f"DATABASE_URL={DB_URL}")
        self.assertTrue(any(f.detector == "connection-string" for f in findings))
        self.assertEqual(
            [f.value for f in findings if f.detector == "connection-string"][0],
            DB_PASSWORD,
        )

    def test_stripe_live(self):
        self.assertIn("stripe-live", detectors_in(STRIPE_KEY))

    def test_high_confidence_marking(self):
        findings = scan_line(AWS_KEY)
        self.assertEqual(findings[0].confidence, "high")


class TestFalsePositives(unittest.TestCase):
    """The tests that keep the tool switched on."""

    def test_placeholder_aws_example_not_flagged(self):
        self.assertEqual(detectors_in(f"key = {AWS_EXAMPLE}"), set())

    def test_password_word_alone_not_flagged(self):
        self.assertEqual(detectors_in('password = "changeme"'), set())

    def test_env_var_reference_not_flagged(self):
        self.assertEqual(detectors_in('password = "${DB_PASSWORD}"'), set())

    def test_ordinary_prose_not_flagged(self):
        self.assertEqual(
            detectors_in("The quick brown fox jumps over the lazy dog"), set()
        )

    def test_url_without_credentials_not_flagged(self):
        self.assertEqual(
            detectors_in("https://api.example.com/v1/users?id=12345"), set()
        )

    def test_short_value_not_flagged_by_context(self):
        # A short, low-entropy value in an assignment is not a credential.
        self.assertEqual(detectors_in('token = "abc"'), set())

    def test_low_entropy_password_not_flagged(self):
        self.assertEqual(detectors_in('password = "passwordpassword"'), set())

    def test_git_sha_not_flagged(self):
        self.assertEqual(
            detectors_in("commit 23bb055a1b2c3d4e5f60718293a4b5c6d7e8f901"), set()
        )


class TestContextualDetection(unittest.TestCase):
    def test_high_entropy_assignment_flagged(self):
        findings = scan_line(f'api_key = "{ENTROPY_VALUE}"')
        self.assertTrue(any(f.detector == "secret-assignment" for f in findings))
        self.assertEqual(
            [f.confidence for f in findings if f.detector == "secret-assignment"][0],
            "medium",
        )

    def test_env_file_assignment(self):
        findings = scan_line(f"SERVICE_API_TOKEN={ENTROPY_VALUE}")
        self.assertTrue(any(f.detector == "env-assignment" for f in findings))

    def test_non_secret_name_not_flagged(self):
        # High entropy, but the variable is not a secret.
        self.assertEqual(detectors_in(f'build_hash = "{ENTROPY_VALUE}"'), set())


class TestLineNumbers(unittest.TestCase):
    def test_detects_at_correct_line(self):
        text = f"line one\nline two\nkey = {AWS_KEY}\nline four"
        findings = detect_in_text(text, path="config.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "config.py")
        self.assertEqual(findings[0].line_number, 3)

    def test_start_line_offset(self):
        findings = detect_in_text(f"key = {AWS_KEY}", path="x", start_line=99)
        self.assertEqual(findings[0].line_number, 100)


class TestDedupe(unittest.TestCase):
    def test_same_secret_reported_once(self):
        findings = [
            Finding("aws-access-key-id", "high", AWS_KEY, "", path="a.py"),
            Finding("aws-access-key-id", "high", AWS_KEY, "", path="a.py"),
        ]
        self.assertEqual(len(dedupe(findings)), 1)

    def test_prefers_record_with_commit(self):
        findings = [
            Finding("aws-access-key-id", "high", AWS_KEY, "", path="a.py"),
            Finding("aws-access-key-id", "high", AWS_KEY, "",
                    path="a.py", commit="abc123"),
        ]
        result = dedupe(findings)
        self.assertEqual(result[0].commit, "abc123")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
    )


class TestWorkingTree(unittest.TestCase):
    def test_finds_secret_in_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.py").write_text(
                f'AWS_KEY = "{AWS_KEY}"\n', encoding="utf-8"
            )
            findings = scan_working_tree(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].path, "config.py")

    def test_skips_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "image.png").write_bytes(AWS_KEY.encode())
            self.assertEqual(scan_working_tree(root), [])

    def test_skips_bytecode_cache(self):
        # Compiled Python embeds its source text, so scanning it re-reports
        # every fixture in this very file.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "__pycache__"
            cache.mkdir()
            (cache / "mod.cpython-311.pyc").write_bytes(AWS_KEY.encode())
            self.assertEqual(scan_working_tree(root), [])

    def test_skips_editable_install_metadata(self):
        # `pip install -e .` writes *.egg-info/PKG-INFO, a copy of the README.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            info = root / "my_pkg.egg-info"
            info.mkdir()
            (info / "PKG-INFO").write_text(f'key = "{AWS_KEY}"\n', encoding="utf-8")
            self.assertEqual(scan_working_tree(root), [])

    def test_clean_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "readme.md").write_text("# hello\n", encoding="utf-8")
            self.assertEqual(scan_working_tree(root), [])


class TestHistory(unittest.TestCase):
    """The reason this tool exists: deleted secrets are still in the history."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "t@example.com")
        _git(self.repo, "config", "user.name", "T")

    def tearDown(self):
        self._tmp.cleanup()

    def test_finds_secret_in_history_after_deletion(self):
        path = self.repo / "config.py"
        path.write_text(f'KEY = "{AWS_KEY}"\n', encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-q", "-m", "add key")

        path.write_text("KEY = 'removed'\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-q", "-m", "remove key")

        # Working tree is clean...
        self.assertEqual(scan_working_tree(self.repo), [])
        # ...but the history is not.
        result = scan_history(self.repo)
        self.assertTrue(
            any(f.detector == "aws-access-key-id" for f in result.findings)
        )
        self.assertTrue(all(f.commit for f in result.findings))

    def test_clean_history(self):
        (self.repo / "a.py").write_text("x = 1\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-q", "-m", "clean")
        result = scan_history(self.repo)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.commits_scanned, 1)

    def test_secret_reported_once_not_per_commit(self):
        path = self.repo / "c.py"
        path.write_text(f'K = "{AWS_KEY}"\n', encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-q", "-m", "one")
        for index in range(3):
            path.write_text(
                f'K = "{AWS_KEY}"\nother = {index}\n', encoding="utf-8"
            )
            _git(self.repo, "add", ".")
            _git(self.repo, "commit", "-q", "-m", f"edit {index}")

        # Only added lines are scanned, so the unchanged key line is not
        # re-reported on every commit that merely touches the file.
        result = scan_history(self.repo)
        matches = [f for f in result.findings if f.detector == "aws-access-key-id"]
        self.assertEqual(len(dedupe(matches)), 1)


class TestBaselineKeys(unittest.TestCase):
    """The baseline file gets committed, so its keys must be safe to share."""

    def test_key_never_contains_secret_material(self):
        finding = scan_line(f'K = "{AWS_KEY}"')[0]
        self.assertNotIn("AKIA", finding.key)
        self.assertNotIn("4RTZ", finding.key)

    def test_same_secret_same_key_across_line_moves(self):
        first = scan_line(f'K = "{AWS_KEY}"')[0]
        second = Finding(
            detector=first.detector,
            confidence=first.confidence,
            value=first.value,
            line=first.line,
            path=first.path,
            line_number=99,
        )
        self.assertEqual(first.key, second.key)

    def test_different_secrets_in_same_file_have_different_keys(self):
        a = scan_line(f'A = "{AWS_KEY}"')[0]
        b = scan_line(f'B = "{AWS_KEY_OTHER}"')[0]
        self.assertNotEqual(a.key, b.key)

    def test_different_files_have_different_keys(self):
        a = scan_line(f'K = "{AWS_KEY}"')[0]
        b = Finding(
            detector=a.detector,
            confidence=a.confidence,
            value=a.value,
            line=a.line,
            path="other.py",
        )
        self.assertNotEqual(a.key, b.key)


class TestCli(unittest.TestCase):
    """The adoption flow has to survive `set -e` in a shell script."""

    def test_write_baseline_succeeds_even_when_secrets_exist(self):
        from secretsweep.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.py").write_text(f'K = "{AWS_KEY}"\n', encoding="utf-8")
            baseline = root / "baseline.txt"
            code = main([str(root), "--no-history", "--write-baseline", str(baseline)])
            self.assertEqual(code, 0)
            self.assertTrue(baseline.exists())

    def test_gate_fails_on_new_secret_and_passes_with_baseline(self):
        from secretsweep.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.py").write_text(f'K = "{AWS_KEY}"\n', encoding="utf-8")
            baseline = root / "baseline.txt"
            main([str(root), "--no-history", "--write-baseline", str(baseline)])
            self.assertEqual(
                main([str(root), "--no-history", "--baseline", str(baseline)]), 0
            )
            # A second, different secret is not covered by the baseline.
            (root / "other.py").write_text(
                f'K = "{AWS_KEY_OTHER}"\n', encoding="utf-8"
            )
            self.assertEqual(
                main([str(root), "--no-history", "--baseline", str(baseline)]), 1
            )


if __name__ == "__main__":
    unittest.main()
