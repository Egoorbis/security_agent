"""Main entry point for the Compliance Check Agent.

Usage
-----
Run standalone (prints report to stdout)::

    python -m agent.main --base-sha <sha> --head-sha <sha> [--repo-path .]

Run inside GitHub Actions (posts PR comment automatically)::

    python -m agent.main --base-sha $BASE_SHA --head-sha $HEAD_SHA

Environment variables
---------------------
GITHUB_TOKEN          GitHub token with pull-requests:write permission.
GITHUB_REPOSITORY     owner/repo string (set automatically by GitHub Actions).
PR_NUMBER             Pull request number.
COMPLIANCE_RULES_DIR  Optional path to a directory containing custom YAML rules.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

from .parsers.terraform import parse_terraform_files
from .policy_engine import Finding, PolicyEngine
from .pr_reporter import PRReporter, build_report

logger = logging.getLogger(__name__)

_DEFAULT_RULES_DIR = Path(__file__).parent.parent / "rules"


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


# ---------------------------------------------------------------------------
# Changed-file detection
# ---------------------------------------------------------------------------

_IAC_EXTENSIONS = {".tf"}
_IAC_FILENAMES: set[str] = set()  # reserved for future ARM/Bicep support


def get_changed_files(base_sha: str, head_sha: str, repo_path: Path) -> list[Path]:
    """Return IaC files changed between *base_sha* and *head_sha*."""
    try:
        result = subprocess.run(  # noqa: S603
            ["git", "diff", "--name-only", base_sha, head_sha],
            capture_output=True,
            text=True,
            check=True,
            cwd=repo_path,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("git diff failed: %s", exc.stderr)
        return []

    changed: list[Path] = []
    for line in result.stdout.splitlines():
        path = repo_path / line.strip()
        if path.suffix in _IAC_EXTENSIONS or path.name in _IAC_FILENAMES:
            changed.append(path)
    logger.info("Found %d changed IaC file(s)", len(changed))
    return changed


# ---------------------------------------------------------------------------
# Compliance agent
# ---------------------------------------------------------------------------


class ComplianceAgent:
    """Orchestrates parsing, policy evaluation, and reporting."""

    def __init__(self, rules_dir: Path = _DEFAULT_RULES_DIR) -> None:
        rule_files = sorted(rules_dir.glob("*.yaml"))
        if not rule_files:
            raise FileNotFoundError(f"No rule YAML files found in {rules_dir}")
        self._engine = PolicyEngine.from_yaml_files(*rule_files)
        logger.info(
            "Loaded %d policy rules from %d file(s)",
            len(self._engine.rules),
            len(rule_files),
        )

    def run(
        self,
        changed_files: list[Path],
        pr_title: str = "",
    ) -> tuple[list[Finding], str]:
        """Parse *changed_files*, evaluate policies, and return (findings, report)."""
        if not changed_files:
            logger.info("No IaC files changed – nothing to check.")
            findings: list[Finding] = []
        else:
            resources = parse_terraform_files(changed_files)
            logger.info("Parsed %d resource(s) from changed files", len(resources))
            findings = self._engine.evaluate(resources)
            logger.info("Found %d compliance violation(s)", len(findings))

        report = build_report(
            findings,
            changed_files=[str(f) for f in changed_files],
            pr_title=pr_title,
        )
        return findings, report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compliance Check Agent – evaluates IaC changes against Azure/Wiz policies."
    )
    parser.add_argument(
        "--base-sha",
        required=True,
        help="Base commit SHA (e.g. the PR base branch tip).",
    )
    parser.add_argument(
        "--head-sha",
        required=True,
        help="Head commit SHA (e.g. the PR head).",
    )
    parser.add_argument(
        "--repo-path",
        default=".",
        help="Path to the repository root (default: current directory).",
    )
    parser.add_argument(
        "--rules-dir",
        default=None,
        help="Path to directory containing policy YAML files.",
    )
    parser.add_argument(
        "--post-comment",
        action="store_true",
        default=False,
        help="Post the report as a GitHub PR comment (requires GITHUB_TOKEN etc.).",
    )
    parser.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low", ""],
        default="",
        help="Exit with non-zero status if any finding meets or exceeds this severity.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging verbosity (default: INFO).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    configure_logging(args.log_level)

    rules_dir = Path(args.rules_dir) if args.rules_dir else _DEFAULT_RULES_DIR
    try:
        agent = ComplianceAgent(rules_dir=rules_dir)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1

    repo_path = Path(args.repo_path).resolve()
    changed_files = get_changed_files(args.base_sha, args.head_sha, repo_path)
    pr_title = os.environ.get("PR_TITLE", "")

    findings, report = agent.run(changed_files, pr_title=pr_title)

    print(report)

    if args.post_comment:
        try:
            reporter = PRReporter.from_env()
            reporter.post_comment(report)
        except OSError as exc:
            logger.error("Could not post PR comment: %s", exc)
            return 1

    # Optional exit-code enforcement
    if args.fail_on_severity:
        from .policy_engine import Severity

        threshold = Severity(args.fail_on_severity)
        if any(f.severity >= threshold for f in findings):
            logger.error(
                "Failing build: %d finding(s) at or above '%s' severity.",
                sum(1 for f in findings if f.severity >= threshold),
                args.fail_on_severity,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
