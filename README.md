# secret-sweep

**Find credentials in a repository — including the ones someone already deleted. `git rm` does not remove a secret from history, and history is what got pushed.**

[![CI](https://github.com/aiplusplus360/secret-sweep/actions/workflows/ci.yml/badge.svg)](https://github.com/aiplusplus360/secret-sweep/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pyproject.toml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```console
$ secret-sweep . --no-history
no secrets found

$ secret-sweep .
[ high ] aws-access-key-id      config.py:1
         AKIA…RS (20 chars)  in commit 694d9e0b93f2
[ high ] connection-string      db.py:1
         hunt…r2 (14 chars)  in commit 694d9e0b93f2

2 finding(s), 2 high confidence
values are truncated on purpose: a scanner that prints the secret
has made a second copy of the problem
```

The working tree is clean. The credentials are still in the repository.

---

## Why this exists

Almost every secret-scanning setup checks the files on disk. That is the one place a leaked secret is *not* a problem any more — because the obvious fix, deleting the line, doesn't remove it from the commits that already contain it.

The realistic sequence:

1. Someone hardcodes a key.
2. It gets committed and pushed.
3. A reviewer catches it and it's removed in the next commit.
4. Everyone considers it handled.
5. The key is still in the history, still on the remote, and still valid.

Step 4 is the failure. This tool exists to make step 4 visible.

## Install

No dependencies. Requires `git` on `PATH`.

```bash
pip install git+https://github.com/aiplusplus360/secret-sweep
```

## Usage

```bash
secret-sweep .                          # working tree + full history
secret-sweep . --history-only           # just the commits
secret-sweep . --no-history             # just the files
secret-sweep . --fail-on high           # CI gate
secret-sweep . --json
```

### Adopting it on a repo that already has secrets

Fixing everything before you can turn the tool on is how it never gets turned on.

```bash
secret-sweep . --write-baseline .secret-baseline
git add .secret-baseline
```

Then scan with `--baseline .secret-baseline` and gate on new findings only.
`--write-baseline` exits 0 on success even when it found secrets — you reviewed
them and accepted them, so the documented adoption script survives `set -e`.

Baseline keys are `detector | path | fingerprint`, where the fingerprint is a
truncated SHA-256 of the matched value. The file is committed, so it is
deliberately safe to share: it never contains any part of a credential, and the
key survives unrelated edits that shift line numbers. This repository dogfoods
the feature — its own test fixtures live in [`.secret-baseline`](.secret-baseline).

### Exit codes

| Code | Meaning |
|---|---|
| `0` | nothing at or above `--fail-on` |
| `1` | findings at or above `--fail-on` |
| `2` | git error |

## What it detects

**Structural** — high confidence, low noise:

| Detector | Format |
|---|---|
| `aws-access-key-id` | `AKIA…` |
| `aws-secret-access-key` | `aws_secret_access_key = …` |
| `github-pat` / `github-token` | `github_pat_…`, `ghp_…` |
| `gitlab-pat` | `glpat-…` |
| `slack-token` | `xoxb-…` |
| `stripe-live` / `stripe-test` | `sk_live_…` |
| `openai-key` | `sk-…T3BlbkFJ…` |
| `private-key-block` | `-----BEGIN … PRIVATE KEY-----` |
| `jwt` | three base64url segments |
| `google-api-key` | `AIza…` |
| `connection-string` | `postgres://user:password@…` |
| `basic-auth-url` | `https://user:password@…` |

**Contextual** — medium confidence, needs entropy to fire:

`password = "k3J9xQ2mP7vL4nR8zW"` and `SERVICE_API_TOKEN=…` are flagged only when the value also looks random.

## False positives are the real design problem

A scanner that cries wolf gets muted in a week, and then it protects nothing. So this one is deliberately conservative, and every rejection below is a test:

| Input | Result |
|---|---|
| `AKIAIOSFODNN7EXAMPLE` | **not** flagged — AWS's documented example key |
| `password = "changeme"` | **not** flagged — placeholder |
| `password = "${DB_PASSWORD}"` | **not** flagged — env reference |
| `token = "abc"` | **not** flagged — too short |
| `password = "passwordpassword"` | **not** flagged — low entropy |
| `build_hash = "k3J9xQ2mP7vL4nR8zW"` | **not** flagged — name isn't secret-ish |
| `commit 23bb055a1b2c…` | **not** flagged — a git SHA |
| `https://api.example.com/v1/users?id=1` | **not** flagged — no credentials |

Entropy alone is a bad detector: `k3J9xQ2mP7vL4nR8zW` and `com.example.springboot.autoconfigure` score similarly, and only one is a secret. **Where** a value sits is what makes entropy useful — the same string in a Gradle package name is not a finding.

## Design notes

**Added lines only.** Scanning every line of every diff reports one credential once per commit that contains it. Scanning `+` lines reports it at the commit that introduced it — which is the commit that matters if the key is ever properly rotated.

**Findings are deduplicated by `(detector, path, value)`.** The same key committed twenty times is one problem, and a report that lists it twenty times is one nobody finishes reading.

**Values are redacted, always.** A scanner that logs full credentials has created a second copy of the problem it was written to find. Output shows `AKIA…RS (20 chars)` — enough to identify which key it is, not enough to use it.

**`--all` covers every branch and tag.** A secret on an unmerged branch has still been pushed to the remote.

**Binaries and lockfiles are skipped.** They produce enormous, credential-free noise, and a slow scan is an unused scan.

**An early version forgot to prepend `git` to subprocess args**, so `subprocess` tried to execute a program named `log`. The resulting `FileNotFoundError` was reported as "git is not installed", which sent the debugging in exactly the wrong direction. The error message is now accurate about what it actually runs.

**This finds secrets; it does not rotate them.** A finding means: revoke the credential, then rewrite history if the repo is shared. Removing the line is not remediation, and treating it as such is the mistake this tool is named after.

## Development

```bash
python -m unittest discover -s tests -v   # 42 tests
```

The history tests build a real repository, commit a credential, delete it, commit again, and assert that the working tree is clean while the history is not — which is the entire premise, verified rather than asserted.

## License

[MIT](LICENSE)
